"""Real AES integration of the control panel's write-only Cookie settings."""

import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import boot

boot.install_paths()
import hw_credentials
import hw_webapi
from astrbot.api import AstrBotConfig
from astrbot.api.web import request


class DiskConfig(AstrBotConfig):
    def __init__(self, values, path):
        super().__init__(values)
        self.config_path = str(path)
        self._save_revision = 0
        self._save_committed_revision = 0
        self.fail = False
        self.entered = None
        self.release = None
        self.flush()

    def flush(self):
        Path(self.config_path).write_text(json.dumps(dict(self)), encoding="utf-8")

    async def save_config_async(self, replace_config=None, indent=2):
        if self.entered is not None:
            self.entered.set()
            await self.release.wait()
        if self.fail:
            return False
        self.update(replace_config)
        self._save_revision += 1
        self.flush()
        self._save_committed_revision = self._save_revision
        return True


class SecureConfigTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="health-secure-config-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.key = root / "example-master.key"
        self.key.write_bytes(os.urandom(32))
        self.key.chmod(0o600)
        self.env = patch.dict(os.environ, {"HUAWEI_HEALTH_MASTER_KEY_FILE": str(self.key)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.platform = patch.object(sys, "platform", "linux")
        self.platform.start()
        self.addCleanup(self.platform.stop)
        self.main = boot.load_main(data_dir=str(root / "data"))
        self.plugin = boot.make_plugin(self.main)
        self.config = DiskConfig(dict(self.plugin.config), root / "config.json")
        self.plugin.config = self.config
        self.api = hw_webapi.HuaweiHealthWebApi(self.plugin)
        self.values = {"cookie_CASTGC": "example-new-account-ticket",
                       "cookie_sid": "example-new-account-session"}

    async def asyncTearDown(self):
        await self.plugin.terminate()

    async def post(self, values, revision=None):
        request.body = {"values": values,
                        "revision": revision or self.api._config_revision()}
        return await self.api.post_config()

    def saved_cookies(self):
        return {c["name"]: c["value"] for c in self.plugin.auth.load_cookies()}

    def seed_previous(self):
        self.plugin.auth.save_cookies([
            {"name": "CASTGC", "value": "example-previous-ticket", "domain": ".id1.cloud.huawei.com", "path": "/"},
            {"name": "sid", "value": "example-previous-session", "domain": ".id1.cloud.huawei.com", "path": "/"},
            {"name": "JSESSIONID", "value": "example-previous-auxiliary", "domain": ".huawei.com", "path": "/"},
        ])
        self.plugin.store.set("token", {"token": "example-previous-token", "expire_at": 9999999999})
        self.plugin.store.set("health-example", {"private": "previous-account"}, ttl=600)

    async def test_complete_import_encrypts_without_plaintext_config_or_old_auxiliary(self):
        self.seed_previous()
        self.config["cookie_json"] = "example-legacy-config-copy"
        self.config.flush()
        response = await self.post(self.values)
        self.assertEqual(response["status_code"], 200, response)
        raw = Path(self.plugin.cookie_file).read_bytes()
        self.assertTrue(raw.startswith(hw_credentials.AES_MAGIC))
        for value in self.values.values():
            self.assertNotIn(value.encode(), raw)
            self.assertNotIn(value, Path(self.config.config_path).read_text())
            self.assertNotIn(value, json.dumps(response))
        self.assertNotIn("example-legacy-config-copy", Path(self.config.config_path).read_text())
        self.assertTrue(all(self.config[key] == "" for key in hw_webapi.SENSITIVE_KEYS))
        self.assertEqual(self.saved_cookies()["sid"], self.values["cookie_sid"])
        self.assertNotIn("JSESSIONID", self.saved_cookies())
        self.assertIsNone(self.plugin.store.get("token"))
        self.assertIsNone(self.plugin.store.get("health-example"))
        payload = (await self.api.get_config())["payload"]["data"]
        self.assertTrue(payload["meta"]["has_value"]["cookie_sid"])
        self.assertTrue(all(payload["values"][key] == "***" for key in hw_webapi.SENSITIVE_KEYS))

    async def test_partial_import_cannot_borrow_previous_identity(self):
        self.seed_previous()
        before = Path(self.plugin.cookie_file).read_bytes()
        for values in ({"cookie_CASTGC": "example-new-only-ticket"},
                       {"cookie_hwid_cas_sid": "example-new-only-optional"}):
            response = await self.post(values)
            self.assertEqual(response["status_code"], 400, response)
            self.assertEqual(Path(self.plugin.cookie_file).read_bytes(), before)
            self.assertEqual(self.config._save_revision, 0)

    async def test_wrong_key_preserves_cookie_and_does_not_persist_new_secrets(self):
        self.seed_previous()
        before = Path(self.plugin.cookie_file).read_bytes()
        self.key.write_bytes(os.urandom(32))
        response = await self.post(self.values)
        self.assertGreaterEqual(response["status_code"], 400)
        self.assertEqual(Path(self.plugin.cookie_file).read_bytes(), before)
        self.assertEqual(self.config._save_revision, 0)
        self.assertTrue(self.plugin._state_error)
        self.assertIsNone(self.plugin.store.get("token"))
        self.assertIsNone(self.plugin.store.get("health-example"))

    async def test_legacy_matching_fingerprint_is_still_migrated(self):
        fields = {key.removeprefix("cookie_"): value for key, value in self.values.items()}
        self.plugin.auth.import_cookie_sources("", fields, True, replace_existing=True)
        cookies = self.plugin.auth.load_cookies()
        Path(self.plugin.cookie_file).write_text(json.dumps(cookies), encoding="utf-8")
        self.config.update(self.values)
        self.config.flush()
        response = await self.post(self.values)
        self.assertEqual(response["status_code"], 200, response)
        self.assertTrue(Path(self.plugin.cookie_file).read_bytes().startswith(hw_credentials.AES_MAGIC))
        self.assertTrue(all(self.config[key] == "" for key in hw_webapi.SENSITIVE_KEYS))

    async def test_persistence_failure_does_not_reenable_old_account_results(self):
        self.seed_previous()
        self.config.fail = True
        response = await self.post(self.values)
        self.assertEqual(response["status_code"], 500, response)
        self.assertTrue(self.plugin._state_error)
        self.assertEqual(self.saved_cookies()["sid"], self.values["cookie_sid"])
        self.assertIsNone(self.plugin.store.get("token"))
        self.assertIsNone(self.plugin.store.get("health-example"))
        with self.assertRaises(self.main.StateChanged):
            await self.plugin._token()

    async def test_same_revision_requests_cannot_both_change_account(self):
        self.config.entered = asyncio.Event()
        self.config.release = asyncio.Event()
        revision = self.api._config_revision()
        first = asyncio.create_task(self.post(self.values, revision))
        await asyncio.wait_for(self.config.entered.wait(), 3)
        second = asyncio.create_task(self.post({"cookie_CASTGC": "example-later-ticket",
                                               "cookie_sid": "example-later-session"}, revision))
        await asyncio.sleep(0)
        self.config.release.set()
        first_result, second_result = await asyncio.gather(first, second)
        self.assertEqual(first_result["status_code"], 200, first_result)
        self.assertEqual(second_result["status_code"], 409, second_result)
        self.assertEqual(self.saved_cookies()["sid"], self.values["cookie_sid"])

    async def test_unrelated_save_retains_unmigrated_legacy_config(self):
        self.config["cookie_sid"] = "example-legacy-config-session"
        self.config.flush()
        response = await self.post({"page_timeout": 101})
        self.assertEqual(response["status_code"], 200, response)
        self.assertEqual(self.config["cookie_sid"], "example-legacy-config-session")
        self.assertNotIn("example-legacy-config-session", json.dumps(response))

    async def test_config_waiting_behind_account_change_rechecks_revision(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def hold(_result):
            entered.set()
            await release.wait()

        first = asyncio.create_task(self.plugin._change_auth_state_async(finalize=hold))
        await asyncio.wait_for(entered.wait(), 3)
        revision = self.api._config_revision()
        second = asyncio.create_task(self.plugin._change_auth_state(lambda:
            self.plugin.auth.import_cookie_sources("", {
                "CASTGC": "example-dedicated-import-ticket",
                "sid": "example-dedicated-import-session",
            }, replace_existing=True)))
        await asyncio.sleep(0)
        pending = asyncio.create_task(self.post(self.values, revision))
        await asyncio.sleep(0)
        release.set()
        await asyncio.gather(first, second)
        response = await pending
        self.assertEqual(response["status_code"], 409, response)
        self.assertEqual(self.saved_cookies()["sid"], "example-dedicated-import-session")
        self.assertEqual(self.config._save_revision, 0)

    async def test_query_option_change_invalidates_old_results_and_old_revision(self):
        self.seed_previous()
        revision = self.api._config_revision()
        old_epoch = self.plugin._data_epoch
        response = await self.post({"timezone": "+0900"}, revision)
        self.assertEqual(response["status_code"], 200, response)
        self.assertIsNone(self.plugin.store.get("health-example"))
        self.assertGreater(self.plugin._data_epoch, old_epoch)
        stale = await self.post({"page_timeout": 101}, revision)
        self.assertEqual(stale["status_code"], 409, stale)


if __name__ == "__main__":
    unittest.main()
