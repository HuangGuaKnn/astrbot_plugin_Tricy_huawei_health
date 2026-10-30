"""Exercise the real login flow with fake CDP/processes, never a real browser."""

import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
import boot

boot.install_paths()
import hw_login


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def time(self):
        return 2_000_000_000.0 + self.now

    def advance(self, seconds):
        self.now += seconds
        if self.now > 1000:
            raise AssertionError("login polling exceeded its simulated time budget")


class FakeEvent:
    def __init__(self, clock):
        self.clock = clock
        self.flag = False
        self.on_wait = None

    def is_set(self):
        return self.flag

    def set(self):
        self.flag = True

    def clear(self):
        self.flag = False

    def wait(self, timeout=None):
        if self.on_wait:
            self.on_wait()
        if not self.flag:
            self.clock.advance(timeout or 0)
        return self.flag


class FakeCDP:
    def __init__(self):
        self.page_timeout = 2.0
        self.token_expire_at = 0
        self.calls = []
        self.token_reads = 0
        self.login_probes = 0
        self.fill_calls = 0
        self.sms_calls = 0
        self.token = ""
        self.read_token = lambda: self.token
        self.ready = "notfound"
        self.fill = "missing"
        self.page = {}
        self.cookies = [{"name": "sid", "value": "fixture-session", "domain": ".huawei.com"}]
        self.load_cookies = Mock(return_value=self.cookies)
        self.save_cookies = Mock(return_value=True)
        self._cleanup_orphan_browsers = Mock()
        self._stop_process = Mock(return_value=True)
        self.socket = Mock()

    def _attach(self, port):
        return self.socket

    def _call(self, ws, method, params=None, **kwargs):
        self.calls.append((method, params))
        if method == "Network.getAllCookies":
            return {"result": {"cookies": self.cookies}}
        return {}

    def _js(self, ws, script):
        if script == "sessionStorage.getItem('accessToken')":
            self.token_reads += 1
            return self.read_token()
        if script == "sessionStorage.getItem('expireTime')":
            return 2_000_003_000
        if "const user=" in script:
            self.fill_calls += 1
            return self.fill() if callable(self.fill) else self.fill
        if "const code=" in script:
            self.sms_calls += 1
            self.token = "after-sms-token"
            return "submitted"
        if "pwd_error" in script:
            return json.dumps(self.page)
        if "button.login-button" in script:
            self.login_probes += 1
            return self.ready() if callable(self.ready) else self.ready
        raise AssertionError("unexpected CDP script in login flow")


class CookieReadyFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hw-login-ready-")
        self.addCleanup(self.temp.cleanup)
        self.clock = FakeClock()
        self.auth = FakeCDP()
        self.credentials = SimpleNamespace(available=True, load=Mock(return_value={
            "account": "fixture-account", "password": "fixture-password"}))
        self.plugin = SimpleNamespace(
            data_dir=self.temp.name, cookie_file=str(Path(self.temp.name) / "cookies.json"),
            config={"page_timeout": 2, "token_ttl": 3000}, credentials=self.credentials,
            _state_lock=threading.RLock(), _auth_epoch=7, logger=Mock(), store=Mock(),
            _clear_health_cache=Mock(),
        )
        self.manager = SimpleNamespace(
            plugin=self.plugin, auto_trust=False, session_timeout=60,
            allow_visible_fallback=False, record_auto_success=Mock(), record_auto_failure=Mock(),
        )
        self.session = hw_login.HuaweiLoginSession(self.manager, mode="auto")
        self.session._cancel = FakeEvent(self.clock)
        self.session._wake = FakeEvent(self.clock)
        self.session._started_at = self.clock.time()
        self.session._finish = Mock(wraps=self.session._finish)
        self.process = Mock()
        self.process.poll.return_value = None

    @contextlib.contextmanager
    def fake_browser(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(hw_login, "find_browser", return_value="fixture-browser"))
            stack.enter_context(patch.object(hw_login, "HuaweiAuth", return_value=self.auth))
            stack.enter_context(patch.object(hw_login, "clear_devtools_port_file"))
            stack.enter_context(patch.object(hw_login, "read_devtools_port", return_value=9222))
            popen = stack.enter_context(patch.object(hw_login.subprocess, "Popen", return_value=self.process))
            stack.enter_context(patch.object(hw_login.time, "monotonic", side_effect=self.clock.monotonic))
            stack.enter_context(patch.object(hw_login.time, "time", side_effect=self.clock.time))
            # The pre-fix implementation used sleep. Advancing it too makes these
            # regressions fail quickly against old code rather than waiting 45s.
            stack.enter_context(patch.object(hw_login.time, "sleep", side_effect=self.clock.advance))
            try:
                yield popen
            finally:
                self.session._cleanup()

    def run_session(self):
        with self.fake_browser() as popen:
            self.session._run()
            popen.assert_called_once()

    def assert_success(self, token):
        self.assertEqual(self.session.snapshot()["state"], "DONE")
        self.session._finish.assert_called_once_with(token)
        self.auth.save_cookies.assert_called_once()
        self.plugin.store.set.assert_called_once()
        self.assertEqual(self.plugin.store.set.call_args.args[1]["token"], token)
        self.manager.record_auto_failure.assert_not_called()

    def assert_no_commit(self):
        self.session._finish.assert_not_called()
        self.auth.save_cookies.assert_not_called()
        self.plugin.store.set.assert_not_called()
        self.plugin._clear_health_cache.assert_not_called()

    def test_launch_injects_cookie_before_navigation_and_returns_existing_token(self):
        self.auth.token = "existing-cookie-token"
        with self.fake_browser():
            ready = self.session._launch()
        self.assertEqual(ready, {"token": "existing-cookie-token"})
        methods = [method for method, _ in self.auth.calls]
        self.assertLess(methods.index("Network.setCookies"), methods.index("Page.navigate"))
        self.assertEqual(self.auth.login_probes, 0)
        self.assertEqual(self.auth.fill_calls, 0)
        self.credentials.load.assert_not_called()

    def test_run_keeps_token_seen_only_once_during_launch(self):
        self.auth.read_token = lambda: "captured-once-token" if self.auth.token_reads == 1 else ""
        self.run_session()
        self.assert_success("captured-once-token")
        self.assertEqual(self.auth.token_reads, 1, "do not discard a captured token by rereading a new document")
        self.assertEqual(self.auth.login_probes, 0)
        self.credentials.load.assert_not_called()

    def test_token_after_login_click_skips_password_loading(self):
        self.auth.ready = "clicked"
        self.auth.read_token = lambda: "late-before-password" if self.auth.token_reads >= 3 else ""
        self.run_session()
        self.assert_success("late-before-password")
        self.credentials.load.assert_not_called()
        self.assertEqual(self.auth.fill_calls, 0)

    def test_token_arriving_while_waiting_for_password_form_completes(self):
        self.auth.ready = "clicked"
        self.auth.read_token = lambda: "late-while-form-missing" if self.auth.fill_calls else ""
        self.run_session()
        self.assert_success("late-while-form-missing")
        self.assertEqual(self.auth.fill_calls, 1)
        self.assertFalse(self.session._credentials_submitted)
        self.assertLess(self.clock.now, self.auth.page_timeout)

    def test_token_returned_atomically_by_fill_script_is_not_lost(self):
        self.auth.ready = "credentials"
        self.auth.fill = {"token": "token-between-check-and-fill"}
        self.run_session()
        self.assert_success("token-between-check-and-fill")
        self.assertFalse(self.session._credentials_submitted)

    def test_token_returned_atomically_by_login_probe_is_not_lost(self):
        self.auth.ready = {"token": "token-between-check-and-click"}
        self.run_session()
        self.assert_success("token-between-check-and-click")
        self.credentials.load.assert_not_called()
        self.assertEqual(self.auth.fill_calls, 0)

    def test_direct_password_form_does_not_require_training_login_button(self):
        self.auth.ready = "credentials"
        self.auth.fill = "submitted"
        self.auth.read_token = lambda: "password-token" if self.session._credentials_submitted else ""
        self.run_session()
        self.assert_success("password-token")
        self.credentials.load.assert_called_once()
        self.assertEqual(self.auth.fill_calls, 1)
        self.assertTrue(self.session._credentials_submitted)

    def test_no_token_or_login_entry_fails_within_ready_budget(self):
        self.run_session()
        self.assertEqual(self.session.snapshot()["state"], "FAILED")
        self.assertIn("自动登录页未准备好", self.session.snapshot()["message"])
        self.assertGreaterEqual(self.clock.now, self.auth.page_timeout)
        self.assertLessEqual(self.clock.now, self.auth.page_timeout + 0.5)
        self.credentials.load.assert_not_called()
        self.assert_no_commit()

    def test_authenticated_dom_waits_for_late_token_without_reading_password(self):
        self.auth.ready = {"await_token": True}
        # The dashboard is already visible, but authInfo completes after the
        # login-entry budget. Waiting for a nonexistent button would time out.
        self.auth.read_token = lambda: "after-dashboard-token" if self.clock.now >= 3 else ""
        self.run_session()
        self.assert_success("after-dashboard-token")
        self.assertGreaterEqual(self.clock.now, 3)
        self.credentials.load.assert_not_called()
        self.assertEqual(self.auth.fill_calls, 0)

    def test_authenticated_dom_without_token_is_not_success_and_has_deadline(self):
        self.auth.ready = {"await_token": True}
        self.run_session()
        self.assertEqual(self.session.snapshot()["state"], "FAILED")
        self.assertIn("登录等待超时", self.session.snapshot()["message"])
        self.assertGreaterEqual(self.clock.now, hw_login.STATE_DEADLINES["SUBMITTING"])
        self.assertLessEqual(self.clock.now, hw_login.STATE_DEADLINES["SUBMITTING"] + 1)
        self.credentials.load.assert_not_called()
        self.assert_no_commit()

    def test_password_submission_still_reaches_sms_and_finishes_after_code(self):
        self.auth.ready = "credentials"
        self.auth.fill = "submitted"
        self.auth.page = {"sms": True}
        observed = []

        def submit_when_ready():
            if self.session.snapshot()["state"] == "NEED_SMS":
                observed.append("NEED_SMS")
                self.session.submit_sms("123456")

        self.session._wake.on_wait = submit_when_ready
        self.run_session()
        self.assert_success("after-sms-token")
        self.assertEqual(observed, ["NEED_SMS"])
        self.assertEqual(self.auth.sms_calls, 1)
        self.assertTrue(self.session._credentials_submitted)
        self.assertTrue(self.session._sms_action_sent)

    def test_cancel_during_ready_token_read_prevents_finish_and_storage(self):
        def cancelled_read():
            self.session.cancel()
            return "late-cancelled-token"

        self.auth.read_token = cancelled_read
        self.run_session()
        self.assert_no_commit()
        self.manager.record_auto_failure.assert_not_called()

    def test_epoch_change_during_ready_token_read_prevents_finish_and_storage(self):
        def changed_read():
            self.plugin._auth_epoch += 1
            return "late-old-account-token"

        self.auth.read_token = changed_read
        self.run_session()
        self.assert_no_commit()
        self.manager.record_auto_failure.assert_not_called()

    def test_cancel_during_fill_script_token_response_prevents_finish(self):
        self.auth.ready = "credentials"

        def cancelled_fill():
            self.session.cancel()
            return {"token": "cancelled-fill-token"}

        self.auth.fill = cancelled_fill
        self.run_session()
        self.assert_no_commit()

    def test_epoch_change_during_fill_script_token_response_prevents_finish(self):
        self.auth.ready = "credentials"

        def changed_fill():
            self.plugin._auth_epoch += 1
            return {"token": "old-account-fill-token"}

        self.auth.fill = changed_fill
        self.run_session()
        self.assert_no_commit()


@unittest.skipUnless(shutil.which("node"), "Node.js is required for actual page-script checks")
class LoginReadyScriptTests(unittest.TestCase):
    def test_real_scripts_do_not_fill_or_click_after_cookie_authentication(self):
        scripts = {
            "fill": hw_login.HuaweiLoginSession._credential_fill_script("fixture-account", "fixture-password"),
            "ready": hw_login.HuaweiLoginSession._login_click_script(),
        }
        runner = r"""
const vm = require('vm'), assert = require('assert');
const scripts = JSON.parse(process.argv[1]);
function run(script, token) {
  let touched = 0;
  const context = {
    location: {hostname: 'health.huawei.com'},
    sessionStorage: {getItem: key => key === 'accessToken' ? token : null},
    document: {querySelector: () => {touched++; throw Error('authenticated page must not be touched');}},
  };
  vm.createContext(context);
  const result = vm.runInContext(script, context);
  assert.equal(result.token, 'captured-browser-token');
  assert.equal(touched, 0, 'token guard must run before any form lookup/click');
}
for (const script of Object.values(scripts)) run(script, '  captured-browser-token  ');
console.log('login token scripts passed');
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", runner, json.dumps(scripts)],
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("login token scripts passed", result.stdout)

    def test_real_scripts_require_visible_dashboard_menu_and_keep_login_form_working(self):
        scripts = {
            "fill": hw_login.HuaweiLoginSession._credential_fill_script("fixture-account", "fixture-password"),
            "ready": hw_login.HuaweiLoginSession._login_click_script(),
        }
        runner = r"""
const vm = require('vm'), assert = require('assert');
const scripts = JSON.parse(process.argv[1]);
function probe(script, menuVisible, formVisible, hasLogout = true, zeroRect = false) {
  let fills = 0, clicks = 0;
  const rectangle = () => ({width: 20, height: 10});
  class Input {
    get value() {return this._value || '';}
    set value(v) {this._value = v; fills++;}
    getBoundingClientRect() {return rectangle();}
    dispatchEvent() {}
  }
  const user = new Input(), password = new Input();
  const menu = {
    getBoundingClientRect: () => zeroRect ? {width: 0, height: 0} : rectangle(),
    querySelector: selector => hasLogout && selector === 'li.custom-option.text-orange' ? {} : null,
  };
  const button = {getBoundingClientRect: rectangle, className: '', click: () => clicks++};
  const context = {
    location: {hostname: 'health.huawei.com'},
    sessionStorage: {getItem: () => null},
    getComputedStyle: element => ({display: element === menu && !menuVisible ? 'none' : 'block', visibility: 'visible'}),
    Event: class {constructor(type) {this.type = type;}},
    document: {querySelector: selector => {
      if (selector === 'div.custom-select-container') return menu;
      if (selector === 'input.userAccount') return formVisible ? user : null;
      if (selector === 'input.hwid-input-pwd') return formVisible ? password : null;
      if (selector.includes('login-button') || selector.includes('hwid-login-btn')) return button;
      return null;
    }},
  };
  vm.createContext(context);
  return {result: vm.runInContext(script, context), fills, clicks};
}
for (const script of Object.values(scripts)) {
  const found = probe(script, true, true);
  assert.equal(found.result.await_token, true);
  assert.equal(found.result.token, undefined, 'DOM alone is never a successful token');
  assert.equal(found.fills, 0);
  assert.equal(found.clicks, 0);
}
const directForm = probe(scripts.ready, false, true);
assert.equal(directForm.result, 'credentials');
assert.equal(directForm.clicks, 0);
const loginEntry = probe(scripts.ready, false, false);
assert.equal(loginEntry.result, 'clicked');
assert.equal(loginEntry.clicks, 1);
const password = probe(scripts.fill, false, true);
assert.equal(password.result, 'submitted');
assert.equal(password.fills, 2);
assert.equal(password.clicks, 1);
for (const [hasLogout, zeroRect] of [[true, true], [false, false]]) {
  const ready = probe(scripts.ready, true, true, hasLogout, zeroRect);
  assert.equal(ready.result, 'credentials', 'zero-sized/menu-without-logout is not authenticated evidence');
  assert.equal(ready.clicks, 0);
  const fill = probe(scripts.fill, true, true, hasLogout, zeroRect);
  assert.equal(fill.result, 'submitted');
  assert.equal(fill.fills, 2);
  assert.equal(fill.clicks, 1);
  const entry = probe(scripts.ready, true, false, hasLogout, zeroRect);
  assert.equal(entry.result, 'clicked');
  assert.equal(entry.clicks, 1);
}
console.log('login menu scripts passed');
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", runner, json.dumps(scripts)],
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("login menu scripts passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
