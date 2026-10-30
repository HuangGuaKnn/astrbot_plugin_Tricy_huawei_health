# -*- coding: utf-8 -*-
"""账号切换、共享缓存和工具预算的离线回归。所有磁盘数据均由 boot 隔离。"""

import asyncio
import datetime
import os
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
sys.dont_write_bytecode = True

import boot

main_mod = boot.load_main(plugin_dir=os.environ.get("HW_AUDIT_PLUGIN_DIR") or str(boot.PLUGIN_DIR))


class TestStateRevision(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.plugin = boot.make_plugin(boot.load_main())

    async def asyncTearDown(self):
        await self.plugin.terminate()

    async def test_account_change_separates_inflight_and_rejects_old_result(self):
        p = self.plugin
        started, release = threading.Event(), threading.Event()
        account = ["old-account"]
        calls = []

        async def client(**_kwargs):
            return SimpleNamespace(token=account[0])

        def producer(c):
            calls.append(c.token)
            if c.token == "old-account":
                started.set()
                if not release.wait(5):
                    raise AssertionError("old producer not released")
            return {"account": c.token}

        p._client = client
        old = asyncio.create_task(p._cached("hr:7", producer))
        try:
            self.assertTrue(await asyncio.to_thread(started.wait, 3))
            await p._invalidate_auth_cache()
            account[0] = "new-account"
            new = await asyncio.wait_for(p._cached("hr:7", producer), 2)
            self.assertEqual(new, {"account": "new-account"})
            self.assertFalse(old.done(), "new account should finish independently of old request")
        finally:
            release.set()
        with self.assertRaises(main_mod.StateChanged):
            await old
        self.assertEqual(calls, ["old-account", "new-account"])
        self.assertEqual(p.store.get("hr:7"), {"account": "new-account"})

    async def test_web_login_start_atomically_blocks_old_cookie_authentication(self):
        """Starting the browser must not leave a query window after invalidation."""
        p = self.plugin
        import hw_webapi
        api = hw_webapi.HuaweiHealthWebApi(p)
        entered, release = threading.Event(), threading.Event()
        auth = SimpleNamespace(fetch_token=Mock(return_value="old-account"),
                               token_expire_at=time.time() + 600)
        session = SimpleNamespace(is_running=lambda: True,
                                  snapshot=lambda: {"state": "NEED_CRED"},
                                  cancel=Mock(), join=Mock())

        def delayed_start(*_args, **_kwargs):
            entered.set()
            if not release.wait(5):
                raise AssertionError("browser start not released")
            p.login_manager._session = session
            return session.snapshot()

        with patch.object(main_mod.HuaweiHealthPlugin, "auth", new_callable=PropertyMock,
                          return_value=auth), \
                patch.object(p.login_manager, "start", side_effect=delayed_start), \
                patch.object(p.login_manager, "status", return_value={}), \
                patch.object(hw_webapi, "request", SimpleNamespace(
                    json=AsyncMock(return_value={"mode": "manual"}))):
            opening = asyncio.create_task(api.login_start())
            query = None
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 3))
                query = asyncio.create_task(p._cached("hr:7", lambda c: c.token))
                # Allow normal event-loop/worker scheduling while browser startup is paused.
                await asyncio.wait({query}, timeout=0.1)
                auth.fetch_token.assert_not_called()
            finally:
                release.set()
                await opening
            with self.assertRaises((main_mod.StateChanged, main_mod.LoginNeedsHuman)):
                await query
        self.assertIsNone(p.store.get("token"))
        self.assertIsNone(p.store.get("hr:7"))

    async def test_changed_config_import_invalidates_token_and_health_cache(self):
        p = self.plugin
        p.config["cookie_CASTGC"] = "synthetic-config-value"
        p.store.set("token", {"token": "old-account", "expire_at": time.time() + 600})
        p.store.set("hr:7", {"account": "old-account"}, ttl=600)
        auth = Mock()
        auth.import_cookie_sources.return_value = 8
        import hw_webapi
        with patch.object(main_mod.HuaweiHealthPlugin, "auth", new_callable=PropertyMock,
                          return_value=auth), \
                patch.object(main_mod, "harden_dir_permissions", return_value=None), \
                patch.object(hw_webapi.HuaweiHealthWebApi, "register"):
            await p.initialize()
        self.assertIsNone(p.store.get("token"))
        self.assertIsNone(p.store.get("hr:7"))
        self.assertFalse(p._state_error)
        self.assertEqual(auth.import_cookie_sources.call_args.args[2], True)

    async def test_unchanged_config_preserves_valid_session_and_cache(self):
        p = self.plugin
        token = {"token": "current", "expire_at": time.time() + 600}
        p.store.set("token", token)
        p.store.set("hr:7", {"value": 60}, ttl=600)
        auth = Mock()
        auth.import_cookie_sources.return_value = 0
        with patch.object(main_mod.HuaweiHealthPlugin, "auth", new_callable=PropertyMock,
                          return_value=auth):
            self.assertEqual(p._import_config_cookies("", {}), 0)
        self.assertEqual(p.store.get("token"), token)
        self.assertEqual(p.store.get("hr:7"), {"value": 60})

    async def test_disabling_cache_bypasses_preexisting_value_and_explicit_ttl(self):
        p = self.plugin
        p.store.set("perf", {"stale": True}, ttl=600)
        p.config["data_ttl"] = 0
        p._client = AsyncMock(return_value=SimpleNamespace(token="test"))
        produced = []

        def producer(_client):
            produced.append(len(produced) + 1)
            return {"fresh": produced[-1]}

        self.assertEqual(await p._cached("perf", producer, ttl=3600), {"fresh": 1})
        self.assertEqual(await p._cached("perf", producer, ttl=3600), {"fresh": 2})
        self.assertEqual(p.store.get("perf"), {"stale": True}, "disabled cache must not write")

    async def test_overview_and_heart_tool_share_raw_cache(self):
        p = self.plugin
        hr = {"overall": {"restBpm": {"avg": 60}}, "daily": []}
        hrv = {"overall": {"avgHrv": {"count": 7}}, "daily": []}
        fake = SimpleNamespace(
            token="test", resting_heart_rate=Mock(return_value=hr),
            hrv_stats=Mock(return_value=hrv), sleep_records=Mock(return_value=[]),
            stress_stats=Mock(return_value={}), body_weight=Mock(return_value={}),
            heart_rate_zones=Mock(return_value={}), athletic_performance=Mock(return_value={}),
            personal_bests=Mock(return_value={}), activities=Mock(return_value=[]))
        p._client = AsyncMock(return_value=fake)
        overview = await p._overview_items()
        self.assertTrue(next(item for item in overview if item["key"] == "heart")["ok"])
        text = await p.health_heart(boot.allowed_event(), days=7)
        self.assertIn("60", text)
        fake.resting_heart_rate.assert_called_once_with(7)
        fake.hrv_stats.assert_called_once_with(7)
        self.assertEqual(p.store.get(p._query_key("hr:7")), hr)

    async def test_shared_total_deadline_keeps_successful_sections(self):
        p = self.plugin
        deadlines = []

        async def query(key, producer, ttl=None, deadline=None):
            deadlines.append(deadline)
            if key == "quick":
                return "available"
            await asyncio.sleep(5)
            return "too late"

        p._query = query
        specs = [(key, key, lambda _c: None, str, None)
                 for key in ("quick", "slow-1", "slow-2", "queued")]
        started = time.monotonic()
        items = await p._run_items(specs, timeout=0.05)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1)
        self.assertEqual(len(set(deadlines)), 1, "all sections must use the same absolute deadline")
        self.assertTrue(items[0]["ok"])
        self.assertEqual(items[0]["text"], "available")
        self.assertTrue(all(not item["ok"] for item in items[1:]))

    async def test_composite_rejects_old_account_even_if_one_section_completed(self):
        p = self.plugin
        got_first = asyncio.Event()
        release = asyncio.Event()

        async def query(key, producer, ttl=None, deadline=None):
            if key == "first":
                got_first.set()
                return "old-account private data"
            await release.wait()
            return "old-account more data"

        p._query = query
        specs = [(key, key, lambda _c: None, str, None) for key in ("first", "second")]
        running = asyncio.create_task(p._run_items(specs, timeout=3))
        await asyncio.wait_for(got_first.wait(), 2)
        await p._invalidate_auth_cache()
        release.set()
        with self.assertRaises(main_mod.StateChanged):
            await running

    async def test_terminate_discards_late_worker_result(self):
        p = self.plugin
        started, release, finished = threading.Event(), threading.Event(), threading.Event()
        p._client = AsyncMock(return_value=SimpleNamespace(token="test"))

        def producer(_client):
            started.set()
            if not release.wait(5):
                raise AssertionError("worker not released")
            finished.set()
            return {"late": True}

        caller = asyncio.create_task(p._cached("late", producer))
        try:
            self.assertTrue(await asyncio.to_thread(started.wait, 3))
            await p.terminate()
            with self.assertRaises((asyncio.CancelledError, main_mod.StateChanged)):
                await caller
        finally:
            release.set()
        self.assertTrue(await asyncio.to_thread(finished.wait, 3))
        await asyncio.sleep(0)
        self.assertIsNone(p.store.get("late"))
        self.assertFalse(p._cache_inflight)

    async def test_cancel_password_waiter_only_cancels_its_captured_session(self):
        p = self.plugin
        polled = threading.Event()
        old = SimpleNamespace(cancel=Mock())
        new = SimpleNamespace(cancel=Mock())
        manager = SimpleNamespace(_session=old, start=Mock(return_value={}),
                                  session_timeout=300, cancel=Mock(),
                                  invalidate=Mock(), stop=Mock())
        manager.current_session = lambda: manager._session

        def status():
            polled.set()
            return {"state": "SUBMITTING"}

        old.snapshot = status
        new.snapshot = lambda: {"state": "SUBMITTING"}
        manager.status = status
        p.login_manager = manager
        waiting = asyncio.create_task(p._password_token())
        self.assertTrue(await asyncio.to_thread(polled.wait, 3))
        manager._session = new
        waiting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiting
        old.cancel.assert_called_once()
        new.cancel.assert_not_called()
        manager.cancel.assert_not_called()

    async def test_human_intervention_keeps_password_session_available(self):
        p = self.plugin
        session = SimpleNamespace(cancel=Mock(), snapshot=lambda: {"state": "NEED_SMS"})
        manager = SimpleNamespace(start=Mock(return_value={}), session_timeout=300,
                                  current_session=lambda: session,
                                  status=lambda: {"state": "NEED_SMS"},
                                  cancel=Mock(), invalidate=Mock(), stop=Mock())
        p.login_manager = manager
        with self.assertRaises(main_mod.LoginNeedsHuman):
            await p._password_token()
        session.cancel.assert_not_called()

    async def test_cancel_while_password_start_is_queued_cancels_late_session(self):
        p = self.plugin
        started, release, cancelled = (threading.Event() for _ in range(3))
        session = SimpleNamespace(cancel=Mock(side_effect=cancelled.set),
                                  snapshot=lambda: {"state": "SUBMITTING"})
        manager = SimpleNamespace(session_timeout=300, current_session=lambda: session,
                                  status=lambda: {"state": "SUBMITTING"},
                                  invalidate=Mock(), stop=Mock())

        def start(*_args, **_kwargs):
            started.set()
            if not release.wait(5):
                raise AssertionError("password start not released")

        manager.start = start
        p.login_manager = manager
        waiting = asyncio.create_task(p._password_token())
        try:
            self.assertTrue(await asyncio.to_thread(started.wait, 3))
            waiting.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiting
        finally:
            release.set()
        self.assertTrue(await asyncio.to_thread(cancelled.wait, 3))
        session.cancel.assert_called_once()

    async def test_cancelling_token_waiter_signals_cookie_auth_worker(self):
        p = self.plugin
        started, release, finished, cancelled = (threading.Event() for _ in range(4))

        def fetch_token():
            started.set()
            if not release.wait(5):
                raise AssertionError("auth worker not released")
            try:
                if cancelled.is_set():
                    raise main_mod.HuaweiAuthError("cancelled")
                return "late-token"
            finally:
                finished.set()

        auth = SimpleNamespace(fetch_token=fetch_token, cancel=Mock(side_effect=cancelled.set),
                               token_expire_at=time.time() + 600)
        with patch.object(main_mod.HuaweiHealthPlugin, "auth", new_callable=PropertyMock,
                          return_value=auth):
            waiting = asyncio.create_task(p._token())
            try:
                self.assertTrue(await asyncio.to_thread(started.wait, 3))
                waiting.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await waiting
                auth.cancel.assert_called_once()
            finally:
                release.set()
            self.assertTrue(await asyncio.to_thread(finished.wait, 3))
        self.assertIsNone(p.store.get("token"))

    async def test_auth_instance_cannot_start_after_account_change_or_termination(self):
        p = self.plugin
        import hw_auth
        old_auth = p.auth
        await p._invalidate_auth_cache()
        # Real auth validation must reject the stale instance before browser discovery.
        with patch.object(hw_auth, "find_browser", side_effect=AssertionError("must not start browser")):
            with self.assertRaises(hw_auth.HuaweiAuthInvalidated):
                old_auth._fetch_token_locked()
            stopped_auth = p.auth
            await p.terminate()
            with self.assertRaises(hw_auth.HuaweiAuthInvalidated):
                stopped_auth._fetch_token_locked()


class TestCompleteFormatting(unittest.TestCase):
    def setUp(self):
        self.plugin = boot.make_plugin(boot.load_main())
        self.addCleanup(self.plugin._client_pool.close)

    def records(self, count=30):
        start = datetime.datetime(2026, 10, 1, 22, tzinfo=datetime.timezone(datetime.timedelta(hours=8)))
        return [{"startTime": int((start + datetime.timedelta(days=i)).timestamp() * 1e9),
                 "endTime": int((start + datetime.timedelta(days=i, hours=8)).timestamp() * 1e9),
                 "value": [{"fieldName": "all_sleep_time", "integerValue": 480}]}
                for i in range(count)]

    def test_sleep_uses_configured_timezone_and_preserves_all_30_records(self):
        records = self.records()
        text = self.plugin._sleep_text(list(reversed(records)), 30, timezone="+0800")
        self.assertEqual(text.count("总睡"), 30)
        self.assertIn("22:00→06:00", text)
        self.assertLess(text.index("10-01"), text.index("10-30"))
        utc = self.plugin._sleep_text(records[:1], 1, timezone="UTC")
        self.assertIn("14:00→22:00", utc)

    def test_summary_limit_is_explicit_and_uses_latest_record(self):
        text = self.plugin._sleep_text(self.records(), 30, timezone="+0800", limit=1)
        self.assertEqual(text.count("总睡"), 1)
        self.assertIn("共 30 条，显示最近 1 条", text)
        self.assertIn("10-30", text)

    def test_heart_daily_output_preserves_90_days(self):
        start = datetime.date(2026, 8, 1)
        daily = [{"day": str(start + datetime.timedelta(days=i)), "restBpm": {"avg": 60}}
                 for i in range(90)]
        text = self.plugin._metric_text({"overall": {}, "daily": daily}, "bpm", 90, "静息心率")
        self.assertEqual(text.count("60 bpm"), 90)


if __name__ == "__main__":
    unittest.main()
