# -*- coding: utf-8 -*-
"""Persistent token protection, using synthetic tokens and throw-away keys."""

import base64
import json
import os
import pathlib
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

TESTS_DIR = pathlib.Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
sys.dont_write_bytecode = True

import boot

boot.install_paths()
import hw_credentials
import hw_store


class TestTokenStorage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="health-token-storage-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.db = self.data / "health.db"
        self.key = self.root / "master.key"
        self.key.write_bytes(os.urandom(32))
        self.key.chmod(0o600)
        self.env = patch.dict(os.environ, {
            "HUAWEI_HEALTH_MASTER_KEY_FILE": str(self.key),
            "CREDENTIALS_DIRECTORY": "",
            "HUAWEI_HEALTH_KEYCHAIN": "",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        # Exercise the AES deployment path even on the Windows development
        # machine. POSIX permission behavior has platform-specific core tests.
        self.platform = patch.object(hw_credentials.sys, "platform", "linux")
        self.platform.start()
        self.addCleanup(self.platform.stop)
        self.store = hw_store.HealthStore(str(self.db))
        self.token = {"token": "synthetic-private-token-for-storage-tests", "expire_at": 4102444800}

    def raw_value(self):
        with closing(sqlite3.connect(self.db)) as connection:
            row = connection.execute("SELECT v FROM kv WHERE k='token'").fetchone()
        return row[0] if row else None

    def put_raw(self, value, expires=0):
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("INSERT OR REPLACE INTO kv VALUES('token', ?, ?)", (value, expires))

    def assert_no_plaintext_token(self):
        marker = self.token["token"].encode("utf-8")
        for path in (self.db, pathlib.Path(str(self.db) + "-wal")):
            if path.exists():
                self.assertNotIn(marker, path.read_bytes(), str(path))

    def test_round_trip_survives_reopen_without_plaintext_in_database(self):
        self.store.set("token", self.token)
        envelope = json.loads(self.raw_value())
        self.assertEqual(set(envelope), {"_protected"})
        self.assertNotIn(self.token["token"], self.raw_value())
        reopened = hw_store.HealthStore(str(self.db))
        self.assertEqual(reopened.get("token"), self.token)
        self.assertTrue(reopened.has("token"))
        self.assert_no_plaintext_token()

    def test_each_write_uses_a_new_ciphertext(self):
        self.store.set("token", self.token)
        first = self.raw_value()
        self.store.set("token", self.token)
        self.assertNotEqual(self.raw_value(), first)
        self.assertEqual(self.store.get("token"), self.token)

    def test_missing_key_refuses_write_and_preserves_existing_value(self):
        self.store.set("token", self.token)
        before = self.raw_value()
        self.key.unlink()
        with self.assertRaises(hw_credentials.CredentialsUnavailableError):
            self.store.set("token", {"token": "another-synthetic-value"})
        self.assertEqual(self.raw_value(), before)
        with self.assertRaises(hw_credentials.CredentialsUnavailableError):
            self.store.get("token", "must-not-hide-locked-storage")
        self.assert_no_plaintext_token()

    def test_wrong_key_is_reported_instead_of_treated_as_missing(self):
        self.store.set("token", self.token)
        before = self.raw_value()
        self.key.write_bytes(os.urandom(32))
        with self.assertRaises(hw_credentials.CredentialsLockedError):
            self.store.get("token", {})
        with self.assertRaises(hw_credentials.CredentialsLockedError):
            self.store.has("token")
        self.assertEqual(self.raw_value(), before)

    def test_wrong_key_cannot_replace_existing_ciphertext_without_explicit_clear(self):
        self.store.set("token", self.token)
        before = self.raw_value()
        self.key.write_bytes(os.urandom(32))
        with self.assertRaises(hw_credentials.CredentialsLockedError):
            self.store.set("token", {"token": "new-synthetic-token"})
        self.assertEqual(self.raw_value(), before)
        self.store.delete("token")
        self.store.set("token", {"token": "new-synthetic-token"})
        self.assertEqual(self.store.get("token"), {"token": "new-synthetic-token"})

    def test_tampered_ciphertext_is_rejected_without_losing_it(self):
        self.store.set("token", self.token)
        value = json.loads(self.raw_value())
        blob = bytearray(base64.b64decode(value["_protected"]))
        blob[-1] ^= 1
        value["_protected"] = base64.b64encode(blob).decode("ascii")
        self.put_raw(json.dumps(value))
        before = self.raw_value()
        with self.assertRaises(hw_credentials.CredentialsLockedError):
            self.store.get("token")
        self.assertEqual(self.raw_value(), before)

    def test_ciphertext_for_another_purpose_cannot_be_used_as_token(self):
        blob = hw_credentials.protect_persistent_secret(b"{}", "credentials", str(self.data))
        self.put_raw(json.dumps({"_protected": base64.b64encode(blob).decode("ascii")}))
        with self.assertRaises(hw_credentials.CredentialsLockedError):
            self.store.get("token")

    def test_non_object_decrypted_payload_is_rejected(self):
        blob = hw_credentials.protect_persistent_secret(b"[]", "token", str(self.data))
        self.put_raw(json.dumps({"_protected": base64.b64encode(blob).decode("ascii")}))
        with self.assertRaises(hw_credentials.CredentialsCorruptError):
            self.store.get("token")

    def test_malformed_envelopes_are_reported_without_returning_a_default(self):
        for raw in ("invalid-json", "[]", "null", '{"_protected": 42}',
                    '{"_protected": "not-base64!"}', '{"_protected": "", "token": "dummy"}'):
            with self.subTest(raw=raw):
                self.put_raw(raw)
                with self.assertRaises(hw_credentials.CredentialsCorruptError):
                    self.store.get("token", "default")

    def test_non_object_token_input_does_not_replace_saved_token(self):
        self.store.set("token", self.token)
        before = self.raw_value()
        with self.assertRaises(hw_credentials.CredentialsCorruptError):
            self.store.set("token", "synthetic-token")
        self.assertEqual(self.raw_value(), before)

    def test_legacy_plaintext_token_is_invalidated_on_startup(self):
        self.put_raw(json.dumps(self.token))
        self.store.set("sleep:7", {"value": 42})
        reopened = hw_store.HealthStore(str(self.db))
        self.assertIsNone(reopened.get("token"))
        self.assertIsNone(self.raw_value())
        self.assertEqual(reopened.get("sleep:7"), {"value": 42})
        self.assert_no_plaintext_token()

    def test_legacy_plaintext_added_after_startup_is_also_invalidated(self):
        self.put_raw(json.dumps(self.token))
        self.assertFalse(self.store.has("token"))
        self.assertIsNone(self.raw_value())
        self.assert_no_plaintext_token()

    def test_legacy_cleanup_does_not_delete_a_new_protected_token(self):
        legacy = json.dumps(self.token)
        self.put_raw(legacy)
        self.store.set("token", self.token)
        self.store._forget_legacy_token(legacy)
        self.assertEqual(self.store.get("token"), self.token)

    def test_expired_protected_token_is_removed_without_needing_its_key(self):
        self.store.set("token", self.token, ttl=-1)
        self.key.unlink()
        self.assertIsNone(self.store.get("token"))
        self.assertIsNone(self.raw_value())

    def test_health_cache_does_not_require_a_master_key(self):
        self.key.unlink()
        self.store.set("sleep:7", {"value": 42})
        self.store.set("empty", None)
        self.assertEqual(self.store.get("sleep:7"), {"value": 42})
        self.assertTrue(self.store.has("empty"))
        self.assertIsNone(self.store.get("empty"))

    def test_connections_enable_secure_delete(self):
        with self.store._conn() as connection:
            self.assertEqual(connection.execute("PRAGMA secure_delete").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
