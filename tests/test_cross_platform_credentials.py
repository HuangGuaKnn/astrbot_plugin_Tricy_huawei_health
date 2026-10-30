"""Credential, Cookie and WebAPI integration using real AES and temporary keys."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import boot

boot.install_paths()
import hw_auth
import hw_credentials
import hw_webapi
from astrbot.api.web import request


class CrossPlatformCredentialsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="health-credentials-example-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "data"
        self.data_dir.mkdir()
        self.key_file = self.root / "example-master.key"
        self.key_file.write_bytes(os.urandom(32))
        self.key_file.chmod(0o600)
        env = {"HUAWEI_HEALTH_MASTER_KEY_FILE": str(self.key_file)}
        self.env = patch.dict(os.environ, env)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.platform = patch.object(sys, "platform", "linux")
        self.platform.start()
        self.addCleanup(self.platform.stop)
        self.store = hw_credentials.HuaweiCredentialsStore(str(self.data_dir))
        self.auth = hw_auth.HuaweiAuth(str(self.data_dir / "cookies.json"),
                                      str(self.data_dir / "profile"))
        self.cookies = [{"name": "sid", "value": "example-private-cookie",
                         "domain": ".huawei.com", "path": "/"}]

    def test_password_round_trip_after_store_recreation(self):
        status = self.store.save("example-account", "example-password")
        raw = Path(self.store.path).read_bytes()
        self.assertTrue(raw.startswith(hw_credentials.AES_MAGIC))
        self.assertNotIn(b"example-password", raw)
        self.assertNotIn(b"example-account", raw)
        restored = hw_credentials.HuaweiCredentialsStore(str(self.data_dir))
        self.assertEqual(restored.load(), {"account": "example-account", "password": "example-password"})
        self.assertEqual(status["state"], "ok")
        self.assertEqual(status["storage"]["method"], "aes-256-gcm")
        self.assertNotIn("example-password", json.dumps(status))
        self.assertNotIn(str(self.key_file), json.dumps(status))

    def test_password_survives_fresh_process_without_in_memory_key(self):
        self.store.save("example-account", "example-password")
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); sys.platform='linux'; "
            "from hw_credentials import HuaweiCredentialsStore; "
            "v=HuaweiCredentialsStore(sys.argv[2]).load(); "
            "assert v == {'account':'example-account','password':'example-password'}"
        )
        result = subprocess.run([sys.executable, "-B", "-c", code,
                                 str(Path(hw_credentials.__file__).parent), str(self.data_dir)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_missing_key_does_not_write_credentials_or_cookies(self):
        self.key_file.unlink()
        self.assertFalse(self.store.available)
        with self.assertRaises(hw_credentials.CredentialsUnavailableError):
            self.store.save("example-account", "example-password")
        with self.assertRaises(hw_auth.HuaweiAuthError):
            self.auth.save_cookies(self.cookies)
        self.assertFalse(Path(self.store.path).exists())
        self.assertFalse(Path(self.auth.cookie_file).exists())

    def test_wrong_key_locks_and_preserves_both_existing_files(self):
        self.store.save("example-account", "example-password")
        self.auth.save_cookies(self.cookies)
        original_password = Path(self.store.path).read_bytes()
        original_cookie = Path(self.auth.cookie_file).read_bytes()
        self.key_file.write_bytes(os.urandom(32))
        with self.assertRaises(hw_credentials.CredentialsLockedError):
            self.store.save("new-example-account", "new-example-password")
        with self.assertRaises(hw_auth.HuaweiAuthError):
            self.auth.save_cookies(self.cookies)
        self.assertEqual(self.store.status()["state"], "locked")
        self.assertEqual(self.auth.cookie_storage_status()["mode"], "locked")
        self.assertEqual(Path(self.store.path).read_bytes(), original_password)
        self.assertEqual(Path(self.auth.cookie_file).read_bytes(), original_cookie)
        self.assertFalse(list(self.data_dir.glob(".*.tmp")))

    def test_legacy_cookie_read_is_side_effect_free_and_resave_migrates(self):
        old = json.dumps(self.cookies).encode("utf-8")
        path = Path(self.auth.cookie_file)
        path.write_bytes(old)
        stamp = path.stat().st_mtime_ns
        restored = self.auth.load_cookies()
        self.assertEqual(path.read_bytes(), old)
        self.assertEqual(path.stat().st_mtime_ns, stamp)
        self.auth.save_cookies(restored)
        encrypted = path.read_bytes()
        self.assertTrue(encrypted.startswith(hw_credentials.AES_MAGIC))
        self.assertNotIn(b"example-private-cookie", encrypted)
        self.assertEqual(self.auth.load_cookies()[0]["value"], "example-private-cookie")

    def test_failed_legacy_cookie_migration_preserves_plaintext_original(self):
        old = json.dumps(self.cookies).encode("utf-8")
        path = Path(self.auth.cookie_file)
        path.write_bytes(old)
        self.key_file.unlink()
        with self.assertRaises(hw_auth.HuaweiAuthError):
            self.auth.save_cookies(self.auth.load_cookies())
        self.assertEqual(path.read_bytes(), old)

    def test_old_dpapi_file_is_never_misread_as_aes_or_plaintext(self):
        original = hw_credentials.MAGIC + b"example-old-dpapi-blob"
        Path(self.store.path).write_bytes(original)
        with self.assertRaises(hw_credentials.DPAPIUnavailableError):
            self.store.load()
        with self.assertRaises(hw_credentials.DPAPIUnavailableError):
            self.store.save("example-new-account", "example-new-password")
        self.assertEqual(Path(self.store.path).read_bytes(), original)
        self.assertEqual(self.store.status()["storage"]["method"], "dpapi")
        self.assertFalse(self.store.status()["storage"]["available"])

    def test_aes_file_reports_its_actual_format_after_moving_to_windows(self):
        self.store.save("example-account", "example-password")
        with patch.object(sys, "platform", "win32"), patch.object(hw_credentials, "_require_dpapi"):
            status = self.store.status()
        self.assertEqual(status["state"], "ok")
        self.assertEqual(status["storage"]["method"], "aes-256-gcm")
        self.assertEqual(status["storage"]["key_source"], "file")

    def test_ciphertexts_cannot_be_swapped_between_cookies_and_passwords(self):
        self.store.save("example-account", "example-password")
        Path(self.auth.cookie_file).write_bytes(Path(self.store.path).read_bytes())
        with self.assertRaises(hw_auth.HuaweiAuthError):
            self.auth.load_cookies()

    def test_webapi_rejects_wrong_key_without_deleting_original_cookie(self):
        # boot.load_main's test sandbox may differ; give this plugin its own key
        # source, and keep all files within this fixture for deterministic cleanup.
        main_mod = boot.load_main(data_dir=str(self.data_dir))
        plugin = boot.make_plugin(main_mod)
        self.addCleanup(lambda: asyncio.run(plugin.terminate()))
        plugin.credentials.save("example-account", "example-password")
        plugin.auth.save_cookies(self.cookies)
        before = Path(plugin.cookie_file).read_bytes()
        self.key_file.write_bytes(os.urandom(32))
        api = hw_webapi.HuaweiHealthWebApi(plugin)
        request.body = {"account": "new-example-account", "password": "new-example-password"}
        response = asyncio.run(api.credentials_write())
        self.assertEqual(response["status_code"], 409)
        self.assertEqual(Path(plugin.cookie_file).read_bytes(), before)
        self.assertNotIn("example-password", json.dumps(response))

    def test_webapi_missing_key_status_is_actionable_without_exposing_key_path(self):
        main_mod = boot.load_main(data_dir=str(self.data_dir))
        plugin = boot.make_plugin(main_mod)
        self.addCleanup(lambda: asyncio.run(plugin.terminate()))
        self.key_file.unlink()
        api = hw_webapi.HuaweiHealthWebApi(plugin)
        data = asyncio.run(api.credentials_status())["payload"]["data"]
        self.assertFalse(data["available"])
        self.assertEqual(data["state"], "absent")
        self.assertTrue(data["storage"]["error"])
        self.assertNotIn(str(self.key_file), json.dumps(data))

    def test_locked_token_does_not_break_status_or_start_new_login(self):
        main_mod = boot.load_main(data_dir=str(self.data_dir))
        plugin = boot.make_plugin(main_mod)
        self.addCleanup(lambda: asyncio.run(plugin.terminate()))
        plugin.store.set("token", {"token": "example-protected-token", "expire_at": 9999999999})
        self.key_file.write_bytes(os.urandom(32))
        api = hw_webapi.HuaweiHealthWebApi(plugin)
        with patch.object(plugin, "_token", side_effect=AssertionError("status must not authenticate")):
            response = asyncio.run(api.get_status())
        self.assertEqual(response["status_code"], 200)
        status = response["payload"]["data"]["token"]
        self.assertEqual(status["state"], "locked")
        self.assertTrue(status["error"])
        self.assertFalse(status["cached"])
        self.assertIn("token", plugin.store.keys())
        self.assertNotIn("example-protected-token", json.dumps(response))
        self.assertNotIn(str(self.key_file), json.dumps(response))


if __name__ == "__main__":
    unittest.main()
