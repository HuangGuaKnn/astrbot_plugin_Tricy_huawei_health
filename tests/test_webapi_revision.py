# -*- coding: utf-8 -*-
"""rc.3 WebAPI and browser regressions; no browser, network or real credentials."""

import asyncio
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
sys.dont_write_bytecode = True

import boot

boot.install_paths()
main_mod = boot.load_main()
import hw_auth
import hw_webapi
from astrbot.api.web import request


class FakeCredentials:
    available = True

    def __init__(self):
        self.saved = None
        self.saved_thread = None

    def save(self, account, password):
        self.saved = (account, password)
        self.saved_thread = threading.current_thread()

    def clear(self):
        self.saved = None

    def status(self):
        return {"password_set": bool(self.saved), "state": "ok" if self.saved else "absent",
                "account_masked": "example-account" if self.saved else ""}


class TestWebApiRevision(unittest.TestCase):
    def setUp(self):
        self.plugin = boot.make_plugin(boot.load_main())
        self.real_credentials = self.plugin.credentials
        self.plugin.credentials = FakeCredentials()
        self.api = hw_webapi.HuaweiHealthWebApi(self.plugin)
        self.addCleanup(setattr, request, "body", {})

    def seed_old_account(self):
        self.plugin.store.set("token", {"token": "old-example-token", "expire_at": time.time() + 600})
        self.plugin.store.set("sleep:7", {"account": "old-example"}, ttl=600)
        pathlib.Path(self.plugin.cookie_file).write_text("[]", encoding="utf-8")

    def assert_cache_cleared(self):
        self.assertIsNone(self.plugin.store.get("token"))
        self.assertIsNone(self.plugin.store.get("sleep:7"))

    def test_saving_credentials_invalidates_old_account_and_runs_off_loop(self):
        self.plugin.credentials = self.real_credentials
        original_save = self.real_credentials.save
        save_threads = []

        def record_save(*args, **kwargs):
            save_threads.append(threading.current_thread())
            return original_save(*args, **kwargs)

        self.seed_old_account()
        request.body = {"account": "new-example-account", "password": "example-password"}
        with patch.object(self.real_credentials, "save", side_effect=record_save):
            response = asyncio.run(self.api.credentials_write())
        self.assertEqual(response["status_code"], 200)
        self.assert_cache_cleared()
        self.assertFalse(os.path.exists(self.plugin.cookie_file))
        self.assertEqual(self.plugin.login_manager.login_mode, "password")
        self.assertEqual(len(save_threads), 1)
        self.assertIsNot(save_threads[0], threading.current_thread())

    def test_clearing_credentials_keeps_cookie_but_clears_cache(self):
        self.seed_old_account()
        self.plugin.credentials.save("old-example-account", "example-password")
        self.plugin.login_manager.set_login_mode("password")
        request.body = {"clear": True}
        response = asyncio.run(self.api.credentials_write())
        self.assertEqual(response["status_code"], 200)
        self.assert_cache_cleared()
        self.assertTrue(os.path.exists(self.plugin.cookie_file))
        self.assertIsNone(self.plugin.credentials.saved)
        self.assertEqual(self.plugin.login_manager.login_mode, "cookie")

    def test_webui_same_account_resave_keeps_health_cache_after_restart(self):
        p = self.plugin
        p.credentials = self.real_credentials
        request.body = {"account": "example-account", "password": "initial-example-password"}
        self.assertEqual(asyncio.run(self.api.credentials_write())["status_code"], 200)
        ciphertext = pathlib.Path(p.credentials.path).read_bytes()
        cookies = [
            {"name": "CASTGC", "value": "example-cookie-a", "domain": ".huawei.com", "path": "/CAS"},
            {"name": "sid", "value": "example-cookie-b", "domain": ".huawei.com", "path": "/"},
        ]
        session = SimpleNamespace(
            _auth=p.auth,
            _auth_epoch=p._auth_epoch,
            _lock=threading.RLock(),
            _cancel=threading.Event(),
            _submitted_account="example-account",
        )
        with patch.object(p.login_manager, "current_session", return_value=session):
            self.assertTrue(p._commit_login_result(session, cookies, "example-old-token", time.time() + 120))
        p.store.set("sleep:7", {"minutes": 420}, ttl=120)
        request.body = {"account": "example-account", "password": "changed-example-password"}
        self.assertEqual(asyncio.run(self.api.credentials_write())["status_code"], 200)
        self.assertNotEqual(pathlib.Path(p.credentials.path).read_bytes(), ciphertext)
        self.assertIsNone(p.store.get("token"))
        self.assertFalse(pathlib.Path(p.cookie_file).exists())

        restarted = boot.make_plugin(boot.load_main(data_dir=p.data_dir))

        async def check_cache():
            await p.terminate()
            try:
                await restarted.initialize()
                with patch.object(restarted, "_client", new_callable=AsyncMock) as client:
                    self.assertEqual(await restarted._cached("sleep:7", None), {"minutes": 420})
                    client.assert_not_awaited()
            finally:
                await restarted.terminate()

        asyncio.run(check_cache())

    def test_visible_login_does_not_inherit_injected_cookie_owner(self):
        p = self.plugin
        p.credentials = self.real_credentials
        request.body = {"account": "example-account", "password": "example-password"}
        self.assertEqual(asyncio.run(self.api.credentials_write())["status_code"], 200)
        current_cookies = [
            {"name": "CASTGC", "value": "example-account-a-cookie", "domain": ".huawei.com", "path": "/CAS"},
        ]
        session = SimpleNamespace(
            _auth=p.auth, _auth_epoch=p._auth_epoch,
            _lock=threading.RLock(), _cancel=threading.Event(),
            _submitted_account="example-account", _headless=True,
        )
        with patch.object(p.login_manager, "current_session", return_value=session):
            self.assertTrue(p._commit_login_result(session, current_cookies, "example-token-a", time.time() + 120))
            p.store.set("sleep:7", {"minutes": 420}, ttl=120)
            session._injected_cookie_identity = p._cookie_owner_source(current_cookies)
            session._headless = False
            session._submitted_account = ""
            other_cookies = [dict(current_cookies[0], value="example-account-b-cookie")]
            self.assertTrue(p._commit_login_result(session, other_cookies, "example-token-b", time.time() + 120))
        self.assertEqual(p.store.current_auth_binding()[0], "cookie")
        self.assertIsNone(p.store.get("sleep:7"))

    def test_cookie_clear_removes_file_and_old_account_cache(self):
        self.seed_old_account()
        response = asyncio.run(self.api.clear_cookie())
        self.assertEqual(response["status_code"], 200)
        self.assert_cache_cleared()
        self.assertFalse(os.path.exists(self.plugin.cookie_file))

    def test_cookie_import_invalidates_cache_and_runs_off_loop(self):
        self.seed_old_account()
        threads = []

        def fake_import(auth, text, fields, *, replace_existing=False):
            self.assertTrue(replace_existing, "explicit import must discard the previous account cookies")
            threads.append(threading.current_thread())
            return 7

        request.body = {"json": "[]"}
        with patch.object(hw_auth.HuaweiAuth, "import_cookie_sources", fake_import):
            response = asyncio.run(self.api.import_cookie())
        self.assertEqual(response["status_code"], 200)
        self.assertEqual(response["payload"]["count"], 7)
        self.assert_cache_cleared()
        self.assertIsNot(threads[0], threading.current_thread())

    def test_invalid_cookie_types_do_not_modify_auth_state(self):
        self.plugin._change_auth_state = AsyncMock()
        for body in ({"json": 12}, {"json": True}, {"json": []}, {"json": {}},
                     {"json": None}, {"fields": []}, {"fields": {"sid": 12}}):
            with self.subTest(body=body):
                request.body = body
                response = asyncio.run(self.api.import_cookie())
                self.assertEqual(response["status_code"], 400)
        self.plugin._change_auth_state.assert_not_awaited()

    def test_refresh_does_not_authenticate_when_cache_clear_fails(self):
        self.plugin._token = AsyncMock(return_value="example-token")
        with patch.object(self.plugin.store, "clear_except", side_effect=OSError("database is locked")):
            response = asyncio.run(self.api.refresh())
        self.assertEqual(response["status_code"], 500)
        self.assertEqual(response["payload"]["status"], "error")
        self.plugin._token.assert_not_awaited()

    def test_refresh_authentication_has_a_wait_budget(self):
        self.plugin.QUERY_TIMEOUT = 0.02

        async def slow_token(**kwargs):
            await asyncio.sleep(5)

        self.plugin._token = slow_token
        response = asyncio.run(self.api.refresh())
        self.assertEqual(response["status_code"], 500)

    def test_overview_returns_a_redacted_error_response(self):
        self.plugin._overview_items = AsyncMock(side_effect=RuntimeError("request https://example.com/private failed"))
        response = asyncio.run(self.api.overview())
        self.assertEqual(response["status_code"], 500)
        self.assertNotIn("https://", response["payload"]["message"])

    def test_cookie_protection_is_available_in_both_status_responses(self):
        protection = {"mode": "dpapi", "encrypted": True, "message": "Cookie 已加密"}
        with patch.object(hw_auth.HuaweiAuth, "cookie_storage_status", return_value=protection):
            status = asyncio.run(self.api.get_status())["payload"]["data"]
            credentials = asyncio.run(self.api.credentials_status())["payload"]["data"]
        self.assertEqual(status["cookie"]["storage"], protection)
        self.assertEqual(credentials["cookie_storage"], protection)

    def test_corrupt_switch_marker_keeps_webui_available_with_manual_repair_path(self):
        marker = pathlib.Path(self.plugin.data_dir, "account_switch.pending.json")
        marker.write_text("invalid marker", encoding="utf-8")
        self.plugin._token = AsyncMock(side_effect=AssertionError("browser auth must not run"))
        asyncio.run(self.plugin.initialize())
        self.assertTrue(any(api["route"].endswith("/status") for api in self.plugin.context.web_apis))
        status = asyncio.run(self.api.get_status())
        self.assertEqual(status["status_code"], 200)
        switch = status["payload"]["data"]["account_switch"]
        self.assertEqual(switch, {
            "pending": True,
            "marker_path": str(marker.absolute()),
            "cookie_path": os.path.abspath(self.plugin.cookie_file),
        })
        request.body = {"repair_account_switch": True}
        result = asyncio.run(self.api.refresh())
        self.assertEqual(result["status_code"], 409)
        self.assertTrue(marker.exists())
        self.assertEqual(asyncio.run(self.api.login_start())["status_code"], 409)
        self.plugin._token.assert_not_awaited()

    def test_switch_repair_mode_recovers_without_authentication(self):
        self.plugin._recover_account_transition = AsyncMock()
        self.plugin._token = AsyncMock()
        request.body = {"repair_account_switch": True}
        result = asyncio.run(self.api.refresh())
        self.assertEqual(result["status_code"], 200)
        self.plugin._recover_account_transition.assert_awaited_once()
        self.plugin._token.assert_not_awaited()

    def test_new_manual_login_invalidates_old_cache(self):
        self.seed_old_account()
        request.body = {"mode": "manual"}
        with patch.object(self.plugin.login_manager, "start", return_value=None):
            response = asyncio.run(self.api.login_start())
        self.assertEqual(response["status_code"], 200)
        self.assert_cache_cleared()

    def test_login_start_holds_state_lock_until_session_is_published(self):
        self.seed_old_account()
        request.body = {"mode": "manual"}
        starting, release, read_attempted = threading.Event(), threading.Event(), threading.Event()
        state = {"session": None}
        active = SimpleNamespace(is_running=lambda: True, snapshot=lambda: {"state": "NEED_SMS"})
        original_load = self.plugin._load_token

        def slow_start(*args, **kwargs):
            starting.set()
            if not release.wait(2):
                raise RuntimeError("test login was not released")
            state["session"] = active

        def tracked_load(epoch):
            read_attempted.set()
            return original_load(epoch)

        async def run():
            login = asyncio.create_task(self.api.login_start())
            query = None
            try:
                self.assertTrue(await asyncio.to_thread(starting.wait, 1))
                query = asyncio.create_task(self.plugin._token())
                self.assertTrue(await asyncio.to_thread(read_attempted.wait, 1))
                done, _ = await asyncio.wait({query}, timeout=0.03)
                self.assertFalse(done, "query crossed the state change before the session was published")
                fetch.assert_not_called()
            finally:
                release.set()
                await asyncio.wait_for(login, 2)
                if query is not None:
                    outcome = await asyncio.gather(query, return_exceptions=True)
            self.assertIsInstance(outcome[0], main_mod.LoginNeedsHuman)
            fetch.assert_not_called()

        with patch.object(self.plugin.login_manager, "start", slow_start), \
                patch.object(self.plugin.login_manager, "current_session", lambda: state["session"]), \
                patch.object(self.plugin, "_load_token", tracked_load), \
                patch.object(hw_auth.HuaweiAuth, "fetch_token", return_value="old-example-token") as fetch:
            asyncio.run(run())

    def test_active_login_is_reused_without_cancelling_it(self):
        self.plugin._change_auth_state = AsyncMock()
        active = SimpleNamespace(is_running=lambda: True, snapshot=lambda: {"state": "NEED_SMS"})
        request.body = {"mode": "manual"}
        with patch.object(self.plugin.login_manager, "current_session", return_value=active), \
                patch.object(self.plugin.login_manager, "start", Mock()) as start:
            response = asyncio.run(self.api.login_start())
        self.assertEqual(response["status_code"], 200)
        self.plugin._change_auth_state.assert_not_awaited()
        start.assert_not_called()

    def test_finished_login_thread_does_not_prevent_restarting(self):
        request.body = {"mode": "manual"}
        finished = SimpleNamespace(is_running=lambda: True, snapshot=lambda: {"state": "FAILED"})
        with patch.object(self.plugin.login_manager, "current_session", return_value=finished), \
                patch.object(self.plugin.login_manager, "start", Mock()) as start:
            response = asyncio.run(self.api.login_start())
        self.assertEqual(response["status_code"], 200)
        start.assert_called_once()


@unittest.skipUnless(shutil.which("node"), "Node.js is required for browser JavaScript checks")
class TestBrowserRevision(unittest.TestCase):
    def test_switch_repair_displays_absolute_path_and_uses_local_recovery(self):
        root = pathlib.Path(os.environ.get("HW_AUDIT_PLUGIN_DIR") or boot.PLUGIN_DIR)
        script = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const html = fs.readFileSync(process.argv[1], 'utf8');
const marker = 'C:\\TestData\\account_switch.pending.json';
const oldCookie = 'C:\\TestData\\hw_cookies.json';
const elements = new Proxy({}, {get(o, key) { return o[key] ||= {}; }});
const calls = [];
const context = {
  $: id => elements[id],
  setMsg(node,text) { node.textContent = text; },
  apiPost: async (path, body) => { calls.push([path, body.repair_account_switch]); },
  unwrap: value => value,
  loadStatus: async () => context.renderAccountSwitch({}),
};
vm.createContext(context);
vm.runInContext(html.slice(html.indexOf('function renderAccountSwitch('),
    html.indexOf('function renderStatus(')), context);
vm.runInContext(html.slice(html.indexOf('async function doRepairAccountSwitch('),
    html.indexOf('/* ---------- 账号登录 ---------- */')), context);
(async () => {
  assert.match(html, /检测到未完成的账号切换/);
  assert.match(html, /删除切换标记 <code id="accountSwitchMarker">/);
  context.renderAccountSwitch({pending: true, marker_path: marker, cookie_path: oldCookie});
  assert.equal(elements.accountSwitchRepair.hidden, false);
  assert.equal(elements.accountSwitchMarker.textContent, marker);
  assert.equal(elements.accountSwitchCookie.textContent, oldCookie);
  await context.doRepairAccountSwitch();
  assert.deepEqual(calls, [['refresh', true]]);
  assert.equal(elements.accountSwitchRepair.hidden, true);
  assert.equal(elements.btnRepairAccountSwitch.disabled, false);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
        subprocess.run([shutil.which("node"), "-e", script,
                        str(root / "pages" / "health_console" / "index.html")],
                       check=True, encoding="utf-8", capture_output=True)

    def test_real_javascript_preserves_errors_and_redacts_diagnostics(self):
        root = pathlib.Path(os.environ.get("HW_AUDIT_PLUGIN_DIR") or boot.PLUGIN_DIR)
        script = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const html = fs.readFileSync(process.argv[1], 'utf8');
function extract(start, end) {
  const from = html.indexOf(start), to = html.indexOf(end, from);
  assert(from >= 0 && to > from);
  return html.slice(from, to);
}
const calls = [];
const context = {
  URL, location: {href:'https://example.com/plugins/_t/example-token/?secret=example-query#fragment'},
  TOKEN: 'example-token', mode:'bridge', bridge:{}, inIframe:()=>true,
  bridgeApi:async()=>{throw new Error('original-business-error');},
  directApi:async(...args)=>{calls.push(args); return {ok:true};},
};
vm.createContext(context);
vm.runInContext(extract('async function callApi(', 'const apiGet ='), context);
vm.runInContext(extract('function diagnosticUrl(', '/* AstrBot'), context);
(async()=>{
  for (const method of ['GET','POST']) {
    await assert.rejects(context.callApi('refresh', method, {}), /original-business-error/);
  }
  assert.equal(calls.length, 0, 'bridge failure must not retry through direct transport');
  context.mode = 'unavailable';
  await assert.rejects(context.callApi('status', 'GET'), /桥接未连接/);
  assert.equal(calls.length, 0);
  context.mode = 'direct'; context.inIframe = ()=>false;
  await context.callApi('status', 'GET');
  assert.equal(calls.length, 1);
  const page = context.diagnosticUrl(context.location.href);
  const script = context.diagnosticUrl('https://example.com/bridge.js?secret=example-query');
  const error = context.diagnosticError(new Error('failed example-token https://example.com/?secret=example-query'));
  for (const output of [page, script, error]) {
    assert(!output.includes('example-token'));
    assert(!output.includes('example-query'));
    assert(!output.includes('fragment'));
  }
  console.log('browser regressions passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
"""
        result = subprocess.run([shutil.which("node"), "-e", script,
                                 str(root / "pages" / "health_console" / "index.html")],
                                text=True, encoding="utf-8", capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("browser regressions passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
