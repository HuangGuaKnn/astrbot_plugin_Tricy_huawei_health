"""Persistent account boundaries verified with synthetic authentication sources."""

import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import AsyncMock, patch

import boot

boot.install_paths()


def cookie_snapshot(value="example-cookie-A"):
    return [
        {"name": "CASTGC", "value": value, "domain": ".id1.cloud.huawei.com", "path": "/CAS"},
        {"name": "sid", "value": "example-sid", "domain": ".id1.cloud.huawei.com", "path": "/"},
    ]


class TestCacheOwnership(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix="t_cache_ownership_", dir=boot.TMP)
        self.addCleanup(fixture.cleanup)
        self.main = boot.load_main(data_dir=fixture.name)
        self.plugins = []

    async def asyncTearDown(self):
        for plugin in self.plugins:
            await plugin.terminate()

    def plugin(self, **config):
        plugin = boot.make_plugin(self.main, **config)
        plugin._fetch_auth = AsyncMock(side_effect=AssertionError("unexpected live auth"))
        self.plugins.append(plugin)
        return plugin

    def seed_cache(self, plugin):
        plugin.store.set("token", {"token": "example-token-A", "expire_at": time.time() + 20})
        plugin.store.set("sleep:7", {"owner": "example-A"}, ttl=300)

    def seed_cookie_owner(self, plugin, cookies):
        plugin.auth.save_cookies(cookies)
        owner = plugin._cookie_owner_source(cookies)
        binding = plugin._cookie_binding(owner)
        plugin.store.bind_auth_cache(binding)
        self.seed_cache(plugin)
        return binding

    async def test_replaced_cookie_rejects_bound_token_and_health_at_restart(self):
        old = self.plugin()
        self.seed_cookie_owner(old, cookie_snapshot())
        stamp = os.stat(old.cookie_file)
        old.auth.save_cookies(cookie_snapshot("example-cookie-B"))
        os.utime(old.cookie_file, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))

        new = self.plugin()
        await new.initialize()
        self.assertIsNone(new.store.get("sleep:7"))
        self.assertIsNone(new.store.get("token"))
        self.assertIsNone(new.store.current_auth_binding())

    async def test_cookie_expiry_order_and_encryption_changes_keep_bound_cache(self):
        old = self.plugin()
        cookies = cookie_snapshot()
        binding = self.seed_cookie_owner(old, cookies)
        before = Path(old.cookie_file).read_bytes()
        renewed = [dict(cookie, expires=time.time() + 60) for cookie in reversed(cookies)]
        old.auth.save_cookies(renewed)
        self.assertNotEqual(before, Path(old.cookie_file).read_bytes())

        new = self.plugin()
        await new.initialize()
        self.assertEqual(new.store.current_auth_binding(), binding)
        self.assertEqual(await new._token(), "example-token-A")
        self.assertEqual(await new._cached("sleep:7", None), {"owner": "example-A"})
        new._fetch_auth.assert_not_awaited()

    async def test_cookie_auth_refresh_keeps_health_after_rotating_cookie_and_token(self):
        old = self.plugin()
        old_cookies = cookie_snapshot()
        self.seed_cookie_owner(old, old_cookies)
        renewed = [dict(cookie, expires=time.time() + 60)
                   for cookie in cookie_snapshot("example-renewed-cookie")]

        async def authenticate(auth):
            auth.save_cookies(renewed)
            auth.authenticated_cookie_digests = (auth.cache_cookie_digest(old_cookies),
                                                 auth.cache_cookie_digest(renewed))
            auth.token_expire_at = time.time() + 120
            return "example-renewed-token"

        old._fetch_auth.side_effect = authenticate
        self.assertEqual(await old._token(force=True), "example-renewed-token")

        new = self.plugin()
        await new.initialize()
        self.assertEqual(await new._token(), "example-renewed-token")
        self.assertEqual(await new._cached("sleep:7", None), {"owner": "example-A"})
        new._fetch_auth.assert_not_awaited()

    async def test_matching_legacy_config_marker_does_not_adopt_unbound_cache(self):
        config = {"cookie_CASTGC": "example-cookie-A", "cookie_sid": "example-sid"}
        original = self.plugin(**config)
        await original.initialize()
        self.assertTrue(original.auth._read_config_marker())
        self.seed_cache(original)

        new = self.plugin(**config)
        await new.initialize()
        self.assertTrue(new.auth.load_cookies())
        self.assertIsNone(new.store.current_auth_binding())
        self.assertIsNone(new.store.get("sleep:7"))
        self.assertIsNone(new.store.get("token"))

    async def test_password_resave_preserves_only_proven_health_at_restart(self):
        old = self.plugin()
        await old._save_account_credentials("example-account-A", "example-old-password")
        before = Path(old.credentials.path).read_bytes()
        self.seed_cache(old)
        epoch, data_epoch = old._auth_epoch, old._data_epoch
        await old._save_account_credentials(" example-account-A ", "example-new-password")
        self.assertNotEqual(Path(old.credentials.path).read_bytes(), before)
        self.assertIsNone(old.store.get("token"))
        self.assertGreater(old._auth_epoch, epoch)
        self.assertGreater(old._data_epoch, data_epoch)

        new = self.plugin()
        await new.initialize()
        self.assertEqual(await new._cached("sleep:7", None), {"owner": "example-A"})
        self.assertFalse(new.account_transition_pending)
        session = SimpleNamespace(_lock=threading.RLock(), _cancel=threading.Event(),
                                  _auth_epoch=new._auth_epoch, _auth=new.auth,
                                  _submitted_account="example-account-A")
        with patch.object(new.login_manager, "current_session", return_value=session):
            self.assertTrue(new._commit_login_result(
                session, cookie_snapshot("example-fresh-cookie"), "example-fresh-token",
                time.time() + 600))
        self.assertEqual(await new._cached("sleep:7", None), {"owner": "example-A"})
        with new.store._conn() as db:
            db.execute("UPDATE kv SET expire_at=1 WHERE k='sleep:7'")
        self.assertIsNone(new.store.get("sleep:7"))
        new.store.set("sleep:7", {"owner": "example-A"}, ttl=300)
        await new._save_account_credentials("example-account-B", "example-other-password")
        self.assertIsNone(new.store.get("sleep:7"))

    async def test_password_resave_never_preserves_cookie_fallback_owner(self):
        old = self.plugin()
        await old._save_account_credentials("example-account-A", "example-old-password")
        fallback = cookie_snapshot("example-cookie-B")
        fallback_binding = self.seed_cookie_owner(old, fallback)
        new = self.plugin()
        await new.initialize()
        self.assertEqual(new.store.current_auth_binding(), fallback_binding)

        await new._save_account_credentials("example-account-A", "example-new-password")
        self.assertIsNone(new.store.get("sleep:7"))
        self.assertIsNone(new.store.get("token"))

    async def test_same_password_account_never_adopts_health_after_live_cookie_swap(self):
        old = self.plugin()
        await old._save_account_credentials("example-account-A", "example-old-password")
        old.auth.save_cookies(cookie_snapshot())
        previous = old.store.current_auth_binding()
        cookie = old._cookie_owner_source(cookie_snapshot())
        old.store.bind_auth_cache(("password", previous[1], cookie, None))
        self.seed_cache(old)
        old.auth.save_cookies(cookie_snapshot("example-other-cookie"))

        await old._save_account_credentials("example-account-A", "example-new-password")
        self.assertIsNone(old.store.get("sleep:7"))

    async def test_uncommitted_marker_aborts_without_removing_old_cookie(self):
        old = self.plugin()
        self.seed_cookie_owner(old, cookie_snapshot())
        cookie = Path(old.cookie_file).read_bytes()
        old._write_account_transition(uuid.uuid4().hex, None, None)

        new = self.plugin()
        await new.initialize()
        self.assertFalse(new.account_transition_pending)
        self.assertFalse(Path(new.account_transition_path).exists())
        self.assertEqual(Path(new.cookie_file).read_bytes(), cookie)
        self.assertEqual(await new._cached("sleep:7", None), {"owner": "example-A"})

    async def test_committed_switch_restarts_blocked_until_cleanup_succeeds(self):
        config = {"cookie_CASTGC": "example-cookie-A", "cookie_sid": "example-sid"}
        old = self.plugin(**config)
        self.seed_cookie_owner(old, cookie_snapshot())
        fail_clear = OSError("synthetic sharing violation")
        with patch.object(self.main.HuaweiAuth, "clear_cookies", side_effect=fail_clear):
            with self.assertRaises(OSError):
                await old._save_account_credentials("example-account-B", "example-password")
            self.assertTrue(Path(old.account_transition_path).is_file())
            self.assertTrue(old.account_transition_pending)
            new = self.plugin(**config)
            await new.initialize()
            self.assertTrue(new.account_transition_pending)
            with self.assertRaises(self.main.StateChanged):
                await new._token()
            with self.assertRaises(self.main.StateChanged):
                await new._change_auth_state()
            self.assertTrue(Path(new.cookie_file).is_file())

        self.assertTrue(await new._recover_account_transition())
        self.assertFalse(await new._recover_account_transition())
        self.assertFalse(Path(new.account_transition_path).exists())
        self.assertFalse(Path(new.cookie_file).exists())
        self.assertIsNone(new.store.get("token"))
        self.assertIsNone(new.store.get("sleep:7"))
        final = self.plugin(**config)
        await final.initialize()
        self.assertFalse(Path(final.cookie_file).exists())
        self.assertEqual(final.login_manager.login_mode, "password")

    async def test_cookie_auth_commit_rejects_changed_source_even_with_equal_mtime(self):
        plugin = self.plugin()
        cookies = cookie_snapshot()
        self.seed_cookie_owner(plugin, cookies)
        digest = plugin.auth.cache_cookie_digest(cookies)
        stamp = os.stat(plugin.cookie_file)
        plugin.auth.save_cookies(cookie_snapshot("example-cookie-B"))
        os.utime(plugin.cookie_file, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))

        with self.assertRaises(self.main.StateChanged):
            plugin._bind_cookie_authentication(digest, digest)
        self.assertIsNone(plugin.store.get("token"))
        self.assertIsNone(plugin.store.get("sleep:7"))

    async def test_malformed_marker_stays_pending_without_removing_cookie(self):
        plugin = self.plugin()
        self.seed_cookie_owner(plugin, cookie_snapshot())
        Path(plugin.account_transition_path).write_text("{bad", encoding="utf-8")

        await plugin.initialize()
        self.assertTrue(plugin.account_transition_pending)
        with self.assertRaises(self.main.StateChanged):
            await plugin._recover_account_transition()
        self.assertTrue(Path(plugin.account_transition_path).is_file())
        self.assertTrue(Path(plugin.cookie_file).is_file())
