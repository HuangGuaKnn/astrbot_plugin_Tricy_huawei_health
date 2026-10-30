# -*- coding: utf-8 -*-
"""离线验证时区、连接池和请求预算；不访问华为服务。"""

import datetime
import os
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
sys.dont_write_bytecode = True

import boot

boot.install_paths(os.environ.get("HW_AUDIT_PLUGIN_DIR") or str(boot.PLUGIN_DIR))
import hw_client


class TestConfiguredTimezone(unittest.TestCase):
    def test_parse_offsets_and_reject_invalid_values(self):
        for value in ("+0800", "+08:00"):
            self.assertEqual(hw_client.parse_timezone(value).utcoffset(None),
                             datetime.timedelta(hours=8))
        self.assertEqual(hw_client.parse_timezone("-03:30").utcoffset(None),
                         -datetime.timedelta(hours=3, minutes=30))
        self.assertEqual(hw_client.parse_timezone("UTC"), datetime.timezone.utc)
        for value in ("+0860", "+2400", "wrong", "0800"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                hw_client.parse_timezone(value)

    def test_calendar_uses_configured_day_across_utc_midnight(self):
        real_datetime = datetime.datetime
        instant = real_datetime(2026, 10, 29, 16, 30, tzinfo=datetime.timezone.utc)

        class FrozenDateTime(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return instant.astimezone(tz or datetime.timezone.utc)

        with patch.object(hw_client.datetime, "datetime", FrozenDateTime):
            self.assertEqual(hw_client._day_window(1, "+0800"),
                             ("20261030", "20261030"))
            self.assertEqual(hw_client._day_window(2, "-0300"),
                             ("20261028", "20261029"))
            with hw_client.HuaweiHealthClient("test", timezone="+08:00") as client:
                bodies = []
                client._post = lambda _path, body: bodies.append(body) or {}
                for method in (client.resting_heart_rate, client.hrv_stats,
                               client.stress_stats, client.body_weight):
                    method(1)
                for body in bodies:
                    req = body["reqs"][0]
                    self.assertEqual(str(req["startDay"]), "20261030")
                    self.assertEqual(str(req["endDay"]), "20261030")
                    self.assertEqual(req["timeZone"], "+0800")


class _FakeClient:
    def __init__(self, token, **kwargs):
        self.token = token
        self.deadline = kwargs.get("deadline")
        self.close_count = 0

    def close(self):
        self.close_count += 1


class TestClientPool(unittest.TestCase):
    def setUp(self):
        self.factory = patch.object(hw_client, "HuaweiHealthClient", _FakeClient)
        self.factory.start()
        self.addCleanup(self.factory.stop)

    def test_reuses_connection_and_evicts_on_account_change(self):
        pool = hw_client.ClientPool(max_size=1)
        self.addCleanup(pool.close)
        first = pool.run("account-a", lambda client: client)
        self.assertIs(pool.run("account-a", lambda client: client), first)
        second = pool.run("account-b", lambda client: client)
        self.assertIsNot(second, first)
        self.assertEqual(first.close_count, 1)
        self.assertEqual(second.token, "account-b")

    def test_same_session_is_never_used_by_two_workers(self):
        pool = hw_client.ClientPool(max_size=2)
        self.addCleanup(pool.close)
        lock = threading.Lock()
        active = set()
        seen = set()

        def producer(client):
            with lock:
                self.assertNotIn(id(client), active)
                active.add(id(client))
                seen.add(id(client))
            time.sleep(0.01)
            with lock:
                active.remove(id(client))
            return client.token

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(pool.run, "account", producer) for _ in range(8)]
            self.assertEqual([future.result(5) for future in futures], ["account"] * 8)
        self.assertLessEqual(len(seen), 2)

    def test_invalidation_closes_busy_client_only_after_release(self):
        pool = hw_client.ClientPool(max_size=1)
        self.addCleanup(pool.close)
        started, release = threading.Event(), threading.Event()
        borrowed = []

        def producer(client):
            borrowed.append(client)
            started.set()
            if not release.wait(5):
                raise AssertionError("test producer was not released")

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(pool.run, "account", producer)
            try:
                self.assertTrue(started.wait(5))
                pool.invalidate()
                self.assertEqual(borrowed[0].close_count, 0)
            finally:
                release.set()
            future.result(5)
        self.assertEqual(borrowed[0].close_count, 1)
        self.assertIsNot(pool.run("account", lambda client: client), borrowed[0])

    def test_exception_releases_slot_and_close_rejects_new_work(self):
        pool = hw_client.ClientPool(max_size=1)
        borrowed = []

        def fail(client):
            borrowed.append(client)
            raise ValueError("failed producer")

        with self.assertRaises(ValueError):
            pool.run("account", fail)
        self.assertIs(pool.run("account", lambda client: client), borrowed[0])
        pool.close()
        pool.close()
        self.assertEqual(borrowed[0].close_count, 1)
        with self.assertRaises(hw_client.HuaweiHealthError):
            pool.run("account", lambda client: client)

    def test_queue_wait_respects_deadline(self):
        pool = hw_client.ClientPool(max_size=1)
        self.addCleanup(pool.close)
        started, release = threading.Event(), threading.Event()

        def producer(_client):
            started.set()
            if not release.wait(5):
                raise AssertionError("test producer was not released")

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(pool.run, "account", producer)
            try:
                self.assertTrue(started.wait(5))
                with self.assertRaises(hw_client.RequestDeadlineExceeded):
                    pool.run("account", lambda client: client,
                             deadline=time.monotonic() + 0.02)
            finally:
                release.set()
            future.result(5)


class TestRequestBudget(unittest.TestCase):
    def setUp(self):
        self.client = hw_client.HuaweiHealthClient("test")
        self.addCleanup(self.client.close)
        self.client.session.close()
        self.client.session = Mock()
        self.clock = [100.0]
        clock_patch = patch.object(hw_client.time, "monotonic", side_effect=lambda: self.clock[0])
        clock_patch.start()
        self.addCleanup(clock_patch.stop)
        throttle_patch = patch.object(hw_client, "_throttle_request")
        throttle_patch.start()
        self.addCleanup(throttle_patch.stop)

    def response(self, status=200, headers=None):
        response = Mock(status_code=status, headers=headers or {}, text="error")
        response.json.return_value = {"healthRecords": []}
        return response

    def test_expired_deadline_does_not_send_request(self):
        self.client.deadline = 99
        with self.assertRaises(hw_client.RequestDeadlineExceeded):
            self.client.sleep_records(1)
        self.client.session.get.assert_not_called()

    def test_insufficient_retry_budget_does_not_sleep_or_resend(self):
        self.client.deadline = 100.25
        self.client.session.get.return_value = self.response(429, {"Retry-After": "10"})
        with patch.object(hw_client.time, "sleep") as sleep:
            with self.assertRaises(hw_client.RequestDeadlineExceeded):
                self.client.sleep_records(1)
        self.client.session.get.assert_called_once()
        sleep.assert_not_called()

    def test_network_failure_cannot_start_retry_outside_budget(self):
        self.client.deadline = 100.25
        self.client.session.get.side_effect = hw_client.requests.ConnectionError("offline")
        with self.assertRaises(hw_client.RequestDeadlineExceeded):
            self.client.sleep_records(1)
        self.client.session.get.assert_called_once()

    def test_socket_timeout_is_limited_and_late_success_rejected(self):
        self.client.deadline = 101

        def send(*_args, **kwargs):
            self.assertEqual(kwargs["timeout"].total, 1)
            self.assertLessEqual(kwargs["timeout"].connect_timeout, 1)
            self.clock[0] = 102
            return self.response()

        self.client.session.get.side_effect = send
        with self.assertRaises(hw_client.RequestDeadlineExceeded):
            self.client.sleep_records(1)

    def test_401_is_returned_without_retry(self):
        self.client.deadline = 110
        self.client.session.get.return_value = self.response(401)
        with self.assertRaises(hw_client.AuthExpired):
            self.client.sleep_records(1)
        self.client.session.get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
