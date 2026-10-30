# -*- coding: utf-8 -*-
"""Authentication changes remain atomic through asynchronous persistence.

Only fake accounts/tokens and boot-isolated files are used. Browser and network
authentication are forbidden so a missing state guard fails the test safely.
"""

import asyncio
import os
import pathlib
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import AsyncMock

TESTS_DIR = pathlib.Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
sys.dont_write_bytecode = True

import boot

boot.install_paths()


class TestAuthTransactions(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="t_auth_transaction_", dir=boot.TMP)
        self.addCleanup(self.temp.cleanup)
        self.main = boot.load_main(data_dir=self.temp.name,
                                   plugin_dir=os.environ.get("HW_AUDIT_PLUGIN_DIR") or str(boot.PLUGIN_DIR))
        self.plugin = boot.make_plugin(self.main)
        self.plugin._fetch_auth = AsyncMock(side_effect=AssertionError("network/browser auth is forbidden"))
        self.tasks = []
        self.releases = []

    async def asyncTearDown(self):
        for event in self.releases:
            event.set()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        if self.tasks:
            await asyncio.wait_for(asyncio.gather(*self.tasks, return_exceptions=True), 5)
        await self.plugin.terminate()

    def task(self, awaitable):
        task = asyncio.create_task(awaitable)
        self.tasks.append(task)
        return task

    def release_event(self, *, thread=False):
        event = threading.Event() if thread else asyncio.Event()
        self.releases.append(event)
        return event

    def seed_old_account(self):
        self.plugin.store.set("token", {
            "token": "synthetic-old-account-token",
            "expire_at": time.time() + 600,
        })
        self.plugin.store.set("sleep:7", {"account": "synthetic-old-account"}, ttl=600)
        return self.plugin._auth_epoch, self.plugin.auth

    def assert_old_state_invalidated(self, old_epoch, old_auth):
        self.assertGreater(self.plugin._auth_epoch, old_epoch)
        self.assertIsNone(self.plugin.store.get("token"))
        self.assertIsNone(self.plugin.store.get("sleep:7"))
        with self.assertRaises(self.main.StateChanged):
            self.plugin._assert_current(old_epoch)
        with self.assertRaises(self.main.HuaweiAuthError):
            old_auth._check_current()

    async def assert_query_blocked(self):
        with self.assertRaises(self.main.StateChanged):
            await asyncio.wait_for(self.plugin._token(), 2)
        self.plugin._fetch_auth.assert_not_awaited()

    async def assert_still_waiting(self, task, entered=None):
        # Give worker/event-loop scheduling a chance to expose a wrongly opened
        # transaction boundary, while keeping the test independent of I/O timing.
        done, _ = await asyncio.wait({task}, timeout=0.05)
        self.assertFalse(done, "the change completed before its predecessor was released")
        if entered is not None:
            self.assertFalse(entered.is_set(), "the next mutator ran before the previous change completed")

    async def test_async_finalizer_blocks_queries_until_success(self):
        p = self.plugin
        old_epoch, old_auth = self.seed_old_account()
        entered, release = asyncio.Event(), self.release_event()
        result = {"saved": "synthetic-new-account"}

        async def finalize(value):
            self.assertIs(value, result)
            entered.set()
            await release.wait()

        change = self.task(p._change_auth_state_async(lambda: result, finalize))
        await asyncio.wait_for(entered.wait(), 2)
        self.assertTrue(p._state_error)
        self.assert_old_state_invalidated(old_epoch, old_auth)
        await self.assert_query_blocked()
        release.set()
        self.assertIs(await asyncio.wait_for(change, 2), result)
        self.assertFalse(p._state_error)
        p._assert_current(p._auth_epoch)

    async def test_another_change_waits_for_async_finalizer(self):
        p = self.plugin
        finalizer_entered, release = asyncio.Event(), self.release_event()
        second_entered = threading.Event()
        order = []

        async def finalize(_value):
            finalizer_entered.set()
            await release.wait()
            order.append("first-finalized")

        def second_mutator():
            order.append("second-mutated")
            second_entered.set()
            return "second-result"

        first = self.task(p._change_auth_state_async(lambda: "first-result", finalize))
        await asyncio.wait_for(finalizer_entered.wait(), 2)
        second = self.task(p._change_auth_state(second_mutator))
        await self.assert_still_waiting(second, second_entered)
        release.set()
        self.assertEqual(await asyncio.wait_for(first, 2), "first-result")
        self.assertEqual(await asyncio.wait_for(second, 2), "second-result")
        self.assertEqual(order, ["first-finalized", "second-mutated"])
        self.assertFalse(p._state_error)

    async def test_finalizer_failure_keeps_queries_blocked_and_old_cache_invalid(self):
        p = self.plugin
        old_epoch, old_auth = self.seed_old_account()

        async def finalize(_value):
            await asyncio.sleep(0)
            raise OSError("synthetic configuration persistence failure")

        with self.assertRaisesRegex(OSError, "synthetic configuration"):
            await p._change_auth_state_async(lambda: "new-credentials-written", finalize)
        self.assertTrue(p._state_error)
        self.assert_old_state_invalidated(old_epoch, old_auth)
        await self.assert_query_blocked()
        # An explicit subsequent change is the recovery boundary.
        await p._change_auth_state()
        self.assertFalse(p._state_error)

    async def test_mutator_failure_never_runs_finalizer_or_reuses_old_cache(self):
        p = self.plugin
        old_epoch, old_auth = self.seed_old_account()
        finalize = AsyncMock()

        def mutator():
            raise OSError("synthetic credentials write failure")

        with self.assertRaisesRegex(OSError, "synthetic credentials"):
            await p._change_auth_state_async(mutator, finalize)
        finalize.assert_not_awaited()
        self.assertTrue(p._state_error)
        self.assert_old_state_invalidated(old_epoch, old_auth)
        await self.assert_query_blocked()

    async def test_cancelled_finalizer_leaves_state_blocked(self):
        p = self.plugin
        old_epoch, old_auth = self.seed_old_account()
        entered, release = asyncio.Event(), self.release_event()

        async def finalize(_value):
            entered.set()
            await release.wait()

        change = self.task(p._change_auth_state_async(lambda: "written", finalize))
        await asyncio.wait_for(entered.wait(), 2)
        change.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await change
        self.assertTrue(p._state_error)
        self.assert_old_state_invalidated(old_epoch, old_auth)
        await self.assert_query_blocked()

    async def test_cancelled_worker_finishes_before_next_change_is_allowed(self):
        p = self.plugin
        old_epoch, old_auth = self.seed_old_account()
        entered, exited, second_entered = threading.Event(), threading.Event(), threading.Event()
        release = self.release_event(thread=True)
        finalize = AsyncMock()
        order = []

        def mutator():
            entered.set()
            if not release.wait(5):
                raise AssertionError("mutator was not released")
            order.append("first-worker-exited")
            exited.set()
            return "written-after-cancellation"

        def second_mutator():
            self.assertTrue(exited.is_set())
            order.append("second-mutator")
            second_entered.set()

        first = self.task(p._change_auth_state_async(mutator, finalize))
        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
        first.cancel()
        second = self.task(p._change_auth_state(second_mutator))
        await self.assert_still_waiting(first)
        await self.assert_still_waiting(second, second_entered)
        self.assertTrue(p._state_error)
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(first, 2)
        finalize.assert_not_awaited()
        await asyncio.wait_for(second, 2)
        self.assertEqual(order, ["first-worker-exited", "second-mutator"])
        self.assert_old_state_invalidated(old_epoch, old_auth)

    async def test_repeated_cancellation_still_waits_for_mutator_exit(self):
        p = self.plugin
        entered, exited = threading.Event(), threading.Event()
        release = self.release_event(thread=True)

        def mutator():
            entered.set()
            if not release.wait(5):
                raise AssertionError("mutator was not released")
            exited.set()

        change = self.task(p._change_auth_state_async(mutator))
        self.assertTrue(await asyncio.to_thread(entered.wait, 2))
        change.cancel()
        await self.assert_still_waiting(change)
        change.cancel()
        await self.assert_still_waiting(change)
        self.assertFalse(exited.is_set())
        self.assertTrue(p._auth_change_lock.locked())
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(change, 2)
        self.assertTrue(exited.is_set())
        self.assertTrue(p._state_error)
        await self.assert_query_blocked()

    async def test_termination_during_finalizer_cannot_reopen_authentication(self):
        p = self.plugin
        old_epoch, old_auth = self.seed_old_account()
        entered, release = asyncio.Event(), self.release_event()

        async def finalize(_value):
            entered.set()
            await release.wait()

        change = self.task(p._change_auth_state_async(lambda: "written", finalize))
        await asyncio.wait_for(entered.wait(), 2)
        await asyncio.wait_for(p.terminate(), 2)
        self.assertTrue(p._closed)
        release.set()
        with self.assertRaises(self.main.StateChanged):
            await asyncio.wait_for(change, 2)
        self.assertTrue(p._state_error)
        self.assert_old_state_invalidated(old_epoch, old_auth)
        await self.assert_query_blocked()
        later = AsyncMock()
        with self.assertRaises(self.main.StateChanged):
            await p._change_auth_state_async(finalize=later)
        later.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
