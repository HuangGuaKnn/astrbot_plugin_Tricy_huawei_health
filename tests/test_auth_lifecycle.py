"""Offline regressions for cancelled authentication and credential protection.

All browser/CDP calls and cryptographic failure cases use local fakes. No Huawei
requests or real user credentials are needed to exercise these races.
"""

import datetime
import json
import os
import sys
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, patch

import boot

boot.install_paths()
import hw_auth
import hw_login
from hw_credentials import CredentialsError, DPAPIUnavailableError, CredentialsUnavailableError


class LoginLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.plugin = types.SimpleNamespace(
            data_dir=self.temp.name, config={}, store=Mock(),
            _clear_health_cache=Mock(), _state_lock=threading.RLock(),
            _auth_epoch=1, logger=Mock())
        self.manager = hw_login.HuaweiLoginManager(self.plugin)
        self.session = hw_login.HuaweiLoginSession(self.manager)
        self.manager._session = self.session
        self.auth = Mock()
        self.auth._call.return_value = {"result": {"cookies": [
            {"name": "sid", "value": "fake-session", "domain": ".huawei.com"}]}}
        self.auth._js.return_value = 9999999999
        self.auth.save_cookies.return_value = True
        self.session._auth = self.auth

    def test_cancel_during_final_cookie_read_prevents_all_writes(self):
        response = self.auth._call.return_value

        def complete_after_cancel(*args):
            self.session.cancel()
            return response

        self.auth._call.side_effect = complete_after_cancel
        with self.assertRaises(hw_login.LoginFlowError) as raised:
            self.session._finish("fake-token")
        self.assertEqual(raised.exception.code, "cancelled")
        self.assertEqual(self.session.snapshot()["state"], "FAILED")
        self.auth.save_cookies.assert_not_called()
        self.plugin.store.set.assert_not_called()
        self.plugin._clear_health_cache.assert_not_called()

    def test_cancel_during_page_poll_cannot_restore_sms_state(self):
        self.session._set_state("SUBMITTING")

        def page_result(_ws, expression):
            if "sessionStorage" in expression:
                return None
            self.session.cancel()
            return json.dumps({"sms": True})

        self.auth._js.side_effect = page_result
        self.session._wait_for_completion()
        self.assertEqual(self.session.snapshot()["state"], "FAILED")
        self.assertFalse(self.manager.is_busy())

    def test_account_epoch_change_rejects_old_result(self):
        self.plugin._auth_epoch += 1
        with self.assertRaises(hw_login.LoginFlowError) as raised:
            self.session._finish("old-account-token")
        self.assertEqual(raised.exception.code, "cancelled")
        self.auth.save_cookies.assert_not_called()
        self.plugin.store.set.assert_not_called()

    def test_plugin_rejecting_commit_does_not_fall_back_to_local_writes(self):
        self.plugin._commit_login_result = Mock(return_value=False)
        with self.assertRaises(hw_login.LoginFlowError):
            self.session._finish("fake-token")
        self.plugin._commit_login_result.assert_called_once()
        self.auth.save_cookies.assert_not_called()
        self.plugin.store.set.assert_not_called()

    def test_successful_commit_uses_plugin_transaction(self):
        self.plugin._commit_login_result = Mock(return_value=True)
        self.session._finish("fake-token")
        args = self.plugin._commit_login_result.call_args.args
        self.assertIs(args[0], self.session)
        self.assertEqual(args[2], "fake-token")
        self.assertEqual(self.session.snapshot()["state"], "DONE")
        self.auth.save_cookies.assert_not_called()

    def test_invalidate_marks_worker_without_waiting_for_it(self):
        self.session.join = Mock(side_effect=AssertionError("must not join"))
        self.manager.invalidate()
        self.assertTrue(self.session._cancel.is_set())
        self.assertEqual(self.session.snapshot()["state"], "FAILED")
        self.session.join.assert_not_called()

    def test_terminal_state_rejects_late_transition_and_queued_actions(self):
        self.session.cancel()
        self.session._set_state("NEED_SMS")
        self.session._set_state("DONE")
        self.assertEqual(self.session.snapshot()["state"], "FAILED")
        self.assertFalse(self.session._enqueue_action("sms", "123456"))
        self.assertTrue(self.session._actions.empty())

    def test_dead_worker_state_does_not_prevent_starting_a_new_session(self):
        self.session._set_state("NEED_SMS")
        with patch.object(hw_login.HuaweiLoginSession, "start") as start:
            self.manager.start()
        start.assert_called_once()
        self.assertIsNot(self.manager.current_session(), self.session)
        self.assertTrue(self.session._cancel.is_set())

    def test_profiles_are_unique_and_cleanup_cannot_remove_another_session(self):
        other = hw_login.HuaweiLoginSession(self.manager)
        self.assertNotEqual(self.session._profile_dir, other._profile_dir)
        Path(self.session._profile_dir).mkdir()
        Path(other._profile_dir).mkdir()
        self.session._proc = Mock()
        self.auth._stop_process.return_value = True
        self.manager._session = other
        self.session._close_browser()
        self.assertFalse(Path(self.session._profile_dir).exists())
        self.assertTrue(Path(other._profile_dir).exists())

    def test_cleanup_keeps_profile_if_browser_exit_was_not_confirmed(self):
        Path(self.session._profile_dir).mkdir()
        self.session._proc = Mock()
        self.auth._stop_process.return_value = False
        self.session._close_browser()
        self.assertTrue(Path(self.session._profile_dir).exists())

    def test_auto_login_reuses_current_trusted_device_cookies(self):
        self.session.mode = "auto"
        cookies = [{"name": "sid", "value": "current-account"}]
        self.auth.load_cookies.return_value = cookies
        self.session._inject_saved_cookies()
        self.auth._call.assert_called_once_with(
            None, "Network.setCookies", {"cookies": cookies})

    def test_manual_login_starts_without_old_account_cookies(self):
        self.session._inject_saved_cookies()
        self.auth.load_cookies.assert_not_called()
        self.auth._call.assert_not_called()

    def test_old_epoch_cannot_inject_saved_cookies(self):
        self.session.mode = "auto"
        self.plugin._auth_epoch += 1
        with self.assertRaises(hw_login.LoginFlowError):
            self.session._inject_saved_cookies()
        self.auth.load_cookies.assert_not_called()
        self.auth._call.assert_not_called()

    def test_invalidated_failure_cannot_restore_cooldown(self):
        self.manager.record_auto_failure = Mock()
        self.manager.invalidate()
        self.session._record_auto_failure("timeout")
        self.manager.record_auto_failure.assert_not_called()


class CookieAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cookie_file = Path(self.temp.name) / "cookies.json"
        self.auth = hw_auth.HuaweiAuth(str(self.cookie_file),
                                      str(Path(self.temp.name) / "profile"))

    def test_encrypt_failure_preserves_existing_file(self):
        previous = hw_auth.COOKIE_MAGIC + b"previous-protected-data"
        self.cookie_file.write_bytes(previous)
        with patch.object(hw_auth.sys, "platform", "win32"), patch.object(
                hw_auth, "_protect", side_effect=CredentialsError("test failure")):
            with self.assertRaises(hw_auth.HuaweiAuthError):
                self.auth.save_cookies([{"name": "sid", "value": "must-not-be-written"}])
        self.assertEqual(self.cookie_file.read_bytes(), previous)
        self.assertFalse(list(Path(self.temp.name).glob(".hw_cookies.*")))

    def test_windows_unavailable_dpapi_never_uses_plaintext(self):
        with patch.object(hw_auth.sys, "platform", "win32"), patch.object(
                hw_auth, "_protect", side_effect=DPAPIUnavailableError("unavailable")):
            with self.assertRaises(hw_auth.HuaweiAuthError):
                self.auth._serialize_cookies([{"name": "sid", "value": "secret"}])

    def test_non_windows_missing_key_never_uses_plaintext(self):
        with patch.object(hw_auth.sys, "platform", "linux"), patch.object(
                hw_auth, "_aes_operation", side_effect=CredentialsUnavailableError("missing key")):
            with self.assertRaises(hw_auth.HuaweiAuthError):
                self.auth.save_cookies([{"name": "sid", "value": "must-not-be-written"}])
        self.assertFalse(self.cookie_file.exists())

    def test_storage_status_reports_actual_file_without_values(self):
        self.assertEqual(self.auth.cookie_storage_status()["mode"], "absent")
        self.cookie_file.write_text('[{"name":"sid","value":"must-not-return"}]')
        status = self.auth.cookie_storage_status()
        self.assertEqual(status["mode"], "plaintext")
        self.assertFalse(status["encrypted"])
        self.assertNotIn("must-not-return", json.dumps(status))

    def test_stop_process_without_proc_still_sweeps_orphans(self):
        """proc 为 None 时也必须做兜底清扫。

        实测背景（2026-10-30）：Edge 的启动器会先于浏览器主进程退出，
        传进来的 proc 常常已经「结束」，但真正持有 profile 的子进程仍在。
        旧实现在 proc is None 时直接 return True，残留越积越多
        （现场累积到 14 个，把 browser_profile 锁死）。
        """
        calls = []
        with patch.object(type(self.auth), "_cleanup_orphan_browsers",
                          lambda _inst: calls.append(1)):
            self.assertTrue(self.auth._stop_process(None, sweep_profile=True))
        self.assertEqual(len(calls), 1)

    def test_stop_process_without_proc_respects_sweep_flag(self):
        """sweep_profile=False 时不许清扫——否则会误杀新会话刚起的浏览器。"""
        calls = []
        with patch.object(type(self.auth), "_cleanup_orphan_browsers",
                          lambda _inst: calls.append(1)):
            self.assertTrue(self.auth._stop_process(None, sweep_profile=False))
        self.assertEqual(calls, [])

    @staticmethod
    def _fixture_serialization(cookies):
        # Test-only plaintext fixtures avoid depending on the host's DPAPI user.
        return json.dumps(cookies).encode("utf-8")

    def test_replacing_cookie_import_drops_previous_account_auxiliary_cookies(self):
        original = [
            {"name": "CASTGC", "value": "old", "domain": ".id1.cloud.huawei.com"},
            {"name": "sid", "value": "old", "domain": ".id1.cloud.huawei.com"},
            {"name": "__uni__uid", "value": "old-user", "domain": ".huawei.com"},
            {"name": "JSESSIONID", "value": "old-session", "domain": ".huawei.com"},
        ]
        self.cookie_file.write_bytes(self._fixture_serialization(original))
        with patch.object(self.auth, "_serialize_cookies", self._fixture_serialization):
            self.auth.import_cookie_sources(
                fields={"CASTGC": "new-cast", "sid": "new-sid"}, replace_existing=True)
        cookies = self.auth.load_cookies()
        self.assertEqual({c["name"] for c in cookies}, {"CASTGC", "sid"})
        self.assertTrue(all(c["value"].startswith("new-") for c in cookies))

    def test_default_import_still_supports_partial_cookie_updates(self):
        with patch.object(self.auth, "_serialize_cookies", self._fixture_serialization):
            self.auth.import_cookie_sources(fields={"CASTGC": "current", "sid": "old-sid"})
            self.auth.import_cookie_sources(fields={"sid": "new-sid"})
        cookies = self.auth.load_cookies()
        self.assertEqual({c["value"] for c in cookies if c["name"] == "CASTGC"}, {"current"})
        self.assertEqual({c["value"] for c in cookies if c["name"] == "sid"}, {"new-sid"})

    def test_unchanged_replacement_config_preserves_renewed_cookies(self):
        fields = {"CASTGC": "configured-cast", "sid": "configured-sid"}
        with patch.object(self.auth, "_serialize_cookies", self._fixture_serialization):
            self.auth.import_cookie_sources(
                fields=fields, only_if_changed=True, replace_existing=True)
            cookies = self.auth.load_cookies()
            for cookie in cookies:
                cookie["value"] = "renewed-value"
            cookies.append({"name": "JSESSIONID", "value": "renewed-session",
                            "domain": ".huawei.com"})
            self.auth.save_cookies(cookies)
            renewed = self.cookie_file.read_bytes()
            count = self.auth.import_cookie_sources(
                fields=fields, only_if_changed=True, replace_existing=True)
        self.assertEqual(count, 0)
        self.assertEqual(self.cookie_file.read_bytes(), renewed)

    def test_invalid_replacement_does_not_borrow_missing_values_or_touch_old_file(self):
        original = self._fixture_serialization([
            {"name": "CASTGC", "value": "old-cast", "domain": ".huawei.com"},
            {"name": "sid", "value": "old-sid", "domain": ".huawei.com"},
        ])
        for incoming in ([{"name": "sid", "value": "new-sid"}],
                         [{"name": "CASTGC", "value": ""}, {"name": "sid", "value": "new"}]):
            with self.subTest(incoming=incoming):
                self.cookie_file.write_bytes(original)
                with patch.object(self.auth, "save_cookies") as save:
                    with self.assertRaises(hw_auth.HuaweiAuthError):
                        self.auth.import_cookie_sources(json.dumps(incoming), replace_existing=True)
                    save.assert_not_called()
                self.assertEqual(self.cookie_file.read_bytes(), original)

    def test_cancellation_only_invalidates_that_auth_instance(self):
        self.auth.cancel()
        with self.assertRaises(hw_auth.HuaweiAuthInvalidated):
            self.auth._check_current()
        other = hw_auth.HuaweiAuth(str(self.cookie_file), self.auth.profile_dir)
        other._check_current()

    def test_invalidated_auth_does_not_launch_or_clean_up_any_browser(self):
        self.auth._is_current = lambda: False
        with patch.object(self.auth, "_cleanup_orphan_browsers") as cleanup:
            with self.assertRaises(hw_auth.HuaweiAuthInvalidated):
                self.auth._fetch_token_locked()
            cleanup.assert_not_called()

    def test_late_cdp_failure_after_invalidation_cannot_restore_cooldown(self):
        for reason in ("epoch", "cancel"):
            with self.subTest(reason=reason):
                current = [True]
                self.auth._cancel.clear()
                self.auth._is_current = lambda: current[0]
                self.auth._commit_lock = threading.RLock()
                self.cookie_file.write_text(json.dumps([
                    {"name": "sid", "value": "old", "domain": ".huawei.com"}]))

                def late_failure(*args, **kwargs):
                    if reason == "epoch":
                        current[0] = False
                    else:
                        self.auth.cancel()
                    raise hw_auth.HuaweiAuthError("simulated late CDP error")

                with patch.object(hw_auth, "find_browser", return_value="fake-browser"), \
                        patch.object(hw_auth, "read_devtools_port", return_value=12345), \
                        patch.object(hw_auth.subprocess, "Popen"), \
                        patch.object(self.auth, "_cleanup_orphan_browsers"), \
                        patch.object(self.auth, "_wait_cdp"), \
                        patch.object(self.auth, "_attach", return_value=Mock()), \
                        patch.object(self.auth, "_wait_token", side_effect=late_failure), \
                        patch.object(self.auth, "_call", return_value={}), \
                        patch.object(self.auth, "_stop_process"), \
                        patch.object(self.auth, "_mark_failure") as failure:
                    with self.assertRaises(hw_auth.HuaweiAuthInvalidated):
                        self.auth._fetch_token_locked()
                    failure.assert_not_called()

    def test_cookie_change_during_browser_auth_rejects_token_without_cooldown(self):
        for change in ("clear", "replace", "epoch", "cancel"):
            with self.subTest(change=change):
                current = [True]
                self.auth._cancel.clear()
                self.auth._is_current = lambda: current[0]
                self.auth._commit_lock = threading.RLock()
                self.cookie_file.write_text(json.dumps([
                    {"name": "sid", "value": "old", "domain": ".huawei.com"}]))
                previous_bytes = self.cookie_file.read_bytes()
                previous_mtime = self.cookie_file.stat().st_mtime_ns

                def call(_ws, method, *args, **kwargs):
                    if method == "Network.getAllCookies":
                        if change == "clear":
                            self.cookie_file.unlink()
                        elif change == "replace":
                            self.cookie_file.write_text("[]")
                            os.utime(self.cookie_file, ns=(previous_mtime + 1_000_000,
                                                         previous_mtime + 1_000_000))
                        elif change == "epoch":
                            current[0] = False
                        elif change == "cancel":
                            self.auth.cancel()
                        if change in ("epoch", "cancel"):
                            return {"result": {"cookies": [
                                {"name": "new%d" % i, "value": "new", "domain": ".huawei.com"}
                                for i in range(5)]}}
                        # Even too few cookies to persist must not skip validation.
                        return {"result": {"cookies": []}}
                    return {}

                with patch.object(hw_auth, "find_browser", return_value="fake-browser"), \
                        patch.object(hw_auth, "read_devtools_port", return_value=12345), \
                        patch.object(hw_auth.subprocess, "Popen"), \
                        patch.object(self.auth, "_cleanup_orphan_browsers"), \
                        patch.object(self.auth, "_wait_cdp"), \
                        patch.object(self.auth, "_attach", return_value=Mock()), \
                        patch.object(self.auth, "_wait_token", return_value="old-token"), \
                        patch.object(self.auth, "_js", return_value=9999999999), \
                        patch.object(self.auth, "_call", side_effect=call), \
                        patch.object(self.auth, "_stop_process"), \
                        patch.object(self.auth, "save_cookies") as save, \
                        patch.object(self.auth, "_mark_failure") as failure:
                    with self.assertRaises(hw_auth.HuaweiAuthInvalidated):
                        self.auth._fetch_token_locked()
                    failure.assert_not_called()
                    save.assert_not_called()
                if change in ("epoch", "cancel"):
                    self.assertEqual(self.cookie_file.read_bytes(), previous_bytes)


class DailyLimitSyncTests(unittest.TestCase):
    """``daily_limit`` 必须在内存与 ``login_config.json`` 两边一致。

    背景（2026-10-31）：``main.py`` 曾在 ``__init__`` 里直接
    ``manager.daily_limit = x``，只改内存；``login_config.json`` 里的旧值会在
    下次启动被 ``_load_login_config`` 读回来，于是出现「配置页显示 3、磁盘写着
    10」的两边不一致。统一走 ``set_daily_limit`` 才能保证写穿。
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.plugin = types.SimpleNamespace(
            data_dir=self.temp.name, config={},
            logger=Mock(), _state_lock=threading.RLock(), _auth_epoch=1)
        self.manager = hw_login.HuaweiLoginManager(self.plugin)

    def _on_disk(self):
        with open(self.manager.login_config_path, encoding="utf-8") as handle:
            return json.load(handle)["daily_limit"]

    def test_value_change_is_written_through(self):
        self.manager.set_daily_limit(7)
        self.assertEqual(self.manager.daily_limit, 7)
        self.assertEqual(self._on_disk(), 7, "改了内存却没写盘，下次启动会被旧值盖掉")

    def test_unchanged_value_does_not_rewrite_file(self):
        self.manager.set_daily_limit(4)
        before = os.stat(self.manager.login_config_path).st_mtime_ns
        self.manager.set_daily_limit(4)
        after = os.stat(self.manager.login_config_path).st_mtime_ns
        self.assertEqual(before, after, "值没变就不该重写整份配置")

    def test_out_of_range_is_clamped_before_writing(self):
        for raw, expect in ((0, 1), (-5, 1), (99, 10)):
            with self.subTest(raw=raw):
                self.manager.set_daily_limit(raw)
                self.assertEqual(self.manager.daily_limit, expect)
                self.assertEqual(self._on_disk(), expect)

    def test_garbage_value_keeps_current_and_does_not_raise(self):
        self.manager.set_daily_limit(5)
        for bad in ("abc", None, [], {}):
            with self.subTest(bad=bad):
                self.manager.set_daily_limit(bad)
                self.assertEqual(self.manager.daily_limit, 5)

    def test_reload_picks_up_the_written_value(self):
        """写穿之后，新建一个 manager 读同一目录必须拿到新值。"""
        self.manager.set_daily_limit(6)
        plugin2 = types.SimpleNamespace(
            data_dir=self.temp.name, config={},
            logger=Mock(), _state_lock=threading.RLock(), _auth_epoch=1)
        self.assertEqual(hw_login.HuaweiLoginManager(plugin2).daily_limit, 6)


class DailyQuotaWindowTests(unittest.TestCase):
    """额度「今日」必须按当地日历日算，不能是滚动 24 小时。

    背景（2026-10-31 03:50 线上）：主人在凌晨重启 AstrBot，日志弹
    「今日自动登录失败次数已达上限，请稍后再试」。可 ``login_config.json``
    里那三条 ``attempts`` 全是**前一天下午 16:41～16:51** 真机验证留下的失败，
    按日历日算当天一次都没试过。根因是 ``_prune_attempts`` 用了
    ``now - 24 * 60 * 60`` 的滑动窗口：前一天下午的失败会一直占到第二天
    同一时刻，于是凌晨重启必然撞上限、当天整天都拿不到额度。
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.plugin = self._make_plugin({"timezone": "+0800"})
        self.manager = hw_login.HuaweiLoginManager(self.plugin)
        self.manager.daily_limit = 3

    def _make_plugin(self, config):
        return types.SimpleNamespace(
            data_dir=self.temp.name, config=config, logger=Mock(),
            _state_lock=threading.RLock(), _auth_epoch=1)

    def _manager_with_tz(self, value):
        return hw_login.HuaweiLoginManager(self._make_plugin({"timezone": value}))

    def test_yesterday_afternoon_attempts_do_not_block_today(self):
        """线上原样复现：三条昨天 16:41～16:51 的失败，今天必须不占额度。"""
        start = self.manager._day_window()[0]
        base = start - 86400  # 昨天 0 点
        self.manager._attempts = [
            base + 16 * 3600 + 41 * 60 + 23,
            base + 16 * 3600 + 50 * 60 + 51,
            base + 16 * 3600 + 51 * 60 + 51,
        ]
        self.manager._check_auto_gate()  # 不该抛 daily_limit
        self.assertEqual(self.manager._attempts, [], "昨天的失败必须被裁掉")
        self.assertEqual(self.manager.status()["daily_used"], 0)

    def test_today_attempts_still_block(self):
        start = self.manager._day_window()[0]
        if time.time() <= start + 180:
            self.skipTest("跨日 3 分钟内构造不出「今天已发生」的时间戳")
        self.manager._attempts = [start + 60, start + 120, start + 180]
        with self.assertRaises(hw_login.LoginFlowError) as ctx:
            self.manager._check_auto_gate()
        self.assertEqual(ctx.exception.code, "daily_limit")
        self.assertEqual(self.manager.status()["daily_used"], 3)

    def test_one_second_before_midnight_is_expired(self):
        start = self.manager._day_window()[0]
        self.manager._attempts = [start - 1]
        self.manager._prune_attempts()
        self.assertEqual(self.manager._attempts, [])

    def test_day_window_is_local_midnight(self):
        tz = hw_login.parse_timezone("+0800")
        start, end = self.manager._day_window()
        local = datetime.datetime.fromtimestamp(start, tz)
        self.assertEqual((local.hour, local.minute, local.second), (0, 0, 0))
        self.assertEqual(int(end - start), 86400)
        self.assertEqual(datetime.datetime.fromtimestamp(end, tz).hour, 0)

    def test_timezone_config_moves_the_boundary(self):
        """日界跟着配置走：三个时区算出的日界各不相同，且各自在当地都是 0 点。"""
        windows = {}
        for name in ("+0800", "+0000", "-0500"):
            tz = hw_login.parse_timezone(name)
            start, end = self._manager_with_tz(name)._day_window()
            windows[name] = (start, end)
            local = datetime.datetime.fromtimestamp(start, tz)
            self.assertEqual((local.hour, local.minute, local.second, local.microsecond),
                             (0, 0, 0, 0), "%s 的日界必须落在当地 0 点" % name)
            self.assertEqual(int(end - start), 86400, name)
        self.assertEqual(len({round(v[0]) for v in windows.values()}), 3,
                         "时区不同，日界必须不同")
        # 东八区与 UTC 的日界之差只有两种可能：此刻 UTC 已跨日 → 8h，
        # 未跨日（东八区先进入新的一天）→ 16h。
        delta = round(windows["+0800"][0] - windows["+0000"][0])
        self.assertIn(delta, (-8 * 3600, 16 * 3600))

    def test_status_reports_when_quota_resets(self):
        data = self.manager.status()
        start, end = self.manager._day_window()
        self.assertEqual(data["daily_reset_at"], int(end))
        self.assertGreaterEqual(data["daily_reset_in"], 0)
        self.assertLessEqual(data["daily_reset_in"], 86400)
        self.assertEqual(int(end - start), 86400)

    def test_bad_timezone_falls_back_instead_of_raising(self):
        """配置写错不该让插件起不来，退回本机时区即可。"""
        for bad in ("garbage", "", "+99:99", None, 123):
            with self.subTest(value=bad):
                manager = self._manager_with_tz(bad)
                manager._check_auto_gate()  # 不抛
                self.assertEqual(len(manager._day_window()), 2)

    def test_future_timestamps_are_still_dropped(self):
        now = time.time()
        self.manager._attempts = [now + 3600, now - 10]
        self.manager._prune_attempts()
        self.assertEqual(self.manager._attempts, [now - 10])

    def test_loading_prunes_and_writes_back(self):
        """过期条目要在启动时清掉并写回磁盘。

        否则采样脚本（读磁盘）会一直报「额度 3/3」，而运行时其实是 0/3，
        15:00 的巡检就会误报一次。
        """
        start = self.manager._day_window()[0]
        stale = start - 3600  # 昨天 23:00，一定早于今日 0 点
        path = self.manager.login_config_path
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"mode": "password", "daily_limit": 3,
                       "attempts": [stale, stale + 60]}, f)
        manager = hw_login.HuaweiLoginManager(self.plugin)
        self.assertEqual(manager._attempts, [])
        with open(path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["attempts"], [],
                             "启动时裁剪后必须写回，否则磁盘上永远显示额度已满")

    def test_loading_with_illegal_fields_does_not_rewrite(self):
        """配置里有非法字段时不写回，免得把默认值当成用户意图固化掉。"""
        start = self.manager._day_window()[0]
        path = self.manager.login_config_path
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"daily_limit": "abc", "attempts": [start - 60]}, f)
        with open(path, encoding="utf-8") as f:
            before = f.read()
        hw_login.HuaweiLoginManager(self.plugin)
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read(), before)


if __name__ == "__main__":
    unittest.main()
