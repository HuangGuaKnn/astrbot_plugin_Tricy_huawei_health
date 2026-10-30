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
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

TESTS_DIR = pathlib.Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
sys.dont_write_bytecode = True

import boot

boot.install_paths()


class _ObservedLock:
    """在 ``_token`` 的锁上挂一个观察点，让测试能证明第二个请求确实被互相排斥。

    正确实现里第二个 ``_token()`` 会停在这个包装锁的 ``acquire`` 上；把
    ``self._lock`` 换成每次新建 ``asyncio.Lock()`` 的变异则会绕过包装锁，
    另起一次认证。两种情形由不同的 Event 暴露，测试据此决定何时放行。
    """

    def __init__(self, inner, second_entrant):
        self._inner = inner
        self._second_entrant = second_entrant
        self._entrants = 0
        self._guard = threading.Lock()

    async def __aenter__(self):
        with self._guard:
            self._entrants += 1
            if self._entrants >= 2:
                self._second_entrant.set()
        await self._inner.acquire()
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        self._inner.release()
        return False


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

    def patch_auth(self, fake, real_fetch=True):
        """用合成 auth 替换 ``plugin.auth``，并可恢复真实的 fetch 桥。

        ``setUp`` 把 ``_fetch_auth`` 换成了「禁止网络/浏览器」的 tripwire。需要
        模拟「worker 线程里正在跑认证」的用例必须走生产代码的
        ``to_thread(auth.fetch_token)`` 边界，所以这里把真实方法装回去。
        """
        if real_fetch:
            self.plugin._fetch_auth = self.main.HuaweiHealthPlugin._fetch_auth.__get__(
                self.plugin, type(self.plugin))
        patcher = patch.object(self.main.HuaweiHealthPlugin, "auth",
                               new_callable=PropertyMock)
        auth_property = patcher.start()
        auth_property.return_value = fake
        self.addCleanup(patcher.stop)
        return fake

    def synthetic_auth(self, fetch_token):
        """假 auth：只实现 ``_token`` 用到的 fetch/token_expire_at/cancel 接口。"""
        fake = Mock()
        fake.token_expire_at = time.time() + 600
        fake.cancel = Mock()
        fake.fetch_token = Mock(side_effect=fetch_token)
        fake.clear_cookies = Mock()
        return fake

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


    async def test_account_switch_during_token_fetch_rejects_old_token(self):
        """旧账号认证在飞行中时切号，旧 token 绝不能被回写进 store。

        红色意味着两件事之一：``_token`` 的 commit 边界缺少 epoch 校验（旧账号
        token 覆盖了新账号的 store），或切号被旧认证拖死/永久卡死，即审计问题
        「旧结果回写 _token」没有被防住。
        """
        p = self.plugin
        started, release = threading.Event(), self.release_event(thread=True)

        def fetch_token():
            started.set()
            if not release.wait(5):
                raise AssertionError("synthetic token fetch was not released")
            return "old-account-token"

        self.patch_auth(self.synthetic_auth(fetch_token))

        fetching = self.task(p._token())
        self.assertTrue(await asyncio.to_thread(started.wait, 3),
                        "synthetic authentication never reached fetch_token")
        # 旧认证还卡在 worker 里时切号必须能完成，而不是被它拖死。
        await asyncio.wait_for(p._change_auth_state(), 3)
        self.assertFalse(p._state_error)
        release.set()
        with self.assertRaises(self.main.StateChanged):
            await asyncio.wait_for(fetching, 3)
        self.assertIsNone(
            p.store.get("token"),
            "the replaced account's stale token was written into the store")
        # 状态机没有被旧认证卡死：之后一次显式切号仍然成功。
        await asyncio.wait_for(p._change_auth_state(), 2)
        self.assertFalse(p._state_error)

    async def test_concurrent_token_requests_share_one_authentication(self):
        """两个并发 ``_token()`` 只能触发一次 ``auth.fetch_token``。

        红色意味着互斥被破坏：两个请求各起一套浏览器/OAuth 互抢同一个 profile，
        即认证没有做单飞（single-flight）。
        """
        p = self.plugin
        started = threading.Event()
        second_entrant = threading.Event()
        second_fetch = threading.Event()
        release = self.release_event(thread=True)
        calls = []
        calls_lock = threading.Lock()

        def fetch_token():
            with calls_lock:
                calls.append("fetch")
                concurrent = len(calls)
            if concurrent >= 2:
                second_fetch.set()
            started.set()
            if not release.wait(5):
                raise AssertionError("synthetic token fetch was not released")
            return "shared-token"

        self.patch_auth(self.synthetic_auth(fetch_token))
        p._lock = _ObservedLock(p._lock, second_entrant)

        def advanced(timeout):
            # 正确实现：第二个请求停在共享锁上；变异实现：它自己又开了一次认证。
            return second_entrant.wait(timeout) or second_fetch.wait(timeout)

        first = self.task(p._token())
        second = self.task(p._token())
        self.assertTrue(await asyncio.to_thread(started.wait, 3),
                        "synthetic authentication never started")
        self.assertTrue(
            await asyncio.to_thread(advanced, 3),
            "the second _token() neither queued on the shared lock nor re-authenticated")
        release.set()
        results = await asyncio.wait_for(asyncio.gather(first, second), 3)
        self.assertEqual(list(results), ["shared-token", "shared-token"])
        self.assertEqual(
            len(calls), 1,
            "concurrent _token() calls started %d authentications" % len(calls))

    async def test_cookie_clear_failure_keeps_queries_blocked_and_cookie_file(self):
        """``_change_auth_state(clear_cookies=True)`` 清 cookie 失败必须 fail-closed。

        红色意味着异常被吞掉/事务收尾错误：查询被放行、旧 cookie 文件被提前删除，
        或状态错误地恢复，即审计问题「切号事务失败后半完成」没有被防住。
        """
        p = self.plugin
        self.seed_old_account()
        pathlib.Path(p.cookie_file).write_bytes(b"synthetic-old-account-cookie-file")

        fake = self.synthetic_auth(Mock(side_effect=AssertionError(
            "fetch must not run while the change is failing")))
        fake.clear_cookies = Mock(side_effect=OSError("synthetic clear failure"))
        self.patch_auth(fake, real_fetch=False)

        with self.assertRaises(OSError):
            await p._change_auth_state(clear_cookies=True)
        self.assertTrue(
            p._state_error,
            "a failed cookie clear left the authentication state unblocked")
        self.assertTrue(
            os.path.exists(p.cookie_file),
            "the old cookie file was deleted by an incomplete account switch")
        await self.assert_query_blocked()
        # 失败之后必须还能靠一次显式切号恢复。
        await p._change_auth_state()
        self.assertFalse(p._state_error)


if __name__ == "__main__":
    unittest.main()
