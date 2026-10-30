"""Offline AES-GCM/key-source regressions; never accesses the real keychain."""

import base64
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
import boot

boot.install_paths()
import hw_secure_storage as secure


class SecureStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hw-secure-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data_dir = self.root / "plugin-data"
        self.data_dir.mkdir()
        self.key_file = self.root / "external.key"
        self.key = os.urandom(32)
        self.key_file.write_bytes(self.key)
        self.key_file.chmod(0o600)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        os.environ[secure.KEY_FILE_ENV] = str(self.key_file)
        self.storage = secure.AesSecretStorage(self.data_dir)

    def test_roundtrip_survives_new_instance_and_uses_fresh_nonce(self):
        payload = b'{"account":"example","password":"fake-password"}'
        first = self.storage.encrypt(payload, "credentials")
        second = self.storage.encrypt(payload, "credentials")
        self.assertTrue(first.startswith(secure.AES_MAGIC))
        self.assertNotEqual(first, second)
        self.assertNotIn(payload, first)
        stored = self.data_dir / "example.bin"
        stored.write_bytes(first)
        restarted = secure.AesSecretStorage(self.data_dir)
        self.assertEqual(restarted.decrypt(stored.read_bytes(), "credentials"), payload)

    def test_all_three_purposes_are_cryptographically_isolated(self):
        for source in ("credentials", "cookies", "token"):
            blob = self.storage.encrypt(b"example", source)
            self.assertEqual(self.storage.decrypt(blob, source), b"example")
            for target in ("credentials", "cookies", "token"):
                if target != source:
                    with self.subTest(source=source, target=target), self.assertRaises(secure.StorageLockedError):
                        self.storage.decrypt(blob, target)

    def test_wrong_key_and_tampering_have_same_error(self):
        blob = self.storage.encrypt(b"example", "cookies")
        self.key_file.write_bytes(os.urandom(32))
        with self.assertRaises(secure.StorageLockedError) as wrong:
            self.storage.decrypt(blob, "cookies")
        self.key_file.write_bytes(self.key)
        tampered = blob[:-1] + bytes([blob[-1] ^ 1])
        with self.assertRaises(secure.StorageLockedError) as changed:
            self.storage.decrypt(tampered, "cookies")
        self.assertEqual(str(wrong.exception), str(changed.exception))

    def test_truncated_and_wrong_magic_are_corrupt(self):
        blob = self.storage.encrypt(b"", "token")
        for invalid in (b"", b"plaintext", blob[:7], blob[:-1], b"HWAEAD2\0" + blob[8:]):
            with self.subTest(length=len(invalid)), self.assertRaises(secure.StorageCorruptError):
                self.storage.decrypt(invalid, "token")

    def test_missing_key_never_writes_or_falls_back_to_plaintext(self):
        os.environ.pop(secure.KEY_FILE_ENV)
        self.assertEqual(self.storage.status(), {
            "available": False, "method": "aes-256-gcm", "key_source": "none",
            "error": "未配置外部主密钥，安全持久化不可用"})
        with self.assertRaises(secure.StorageUnavailableError):
            self.storage.encrypt(b"do-not-persist", "credentials")
        self.assertEqual(list(self.data_dir.iterdir()), [])

    def test_status_is_safe_and_reports_source(self):
        status = self.storage.status()
        self.assertTrue(status["available"])
        self.assertEqual(status["key_source"], "file")
        rendered = json.dumps(status)
        self.assertNotIn(str(self.key_file), rendered)
        self.assertNotIn(base64.b64encode(self.key).decode(), rendered)
        with patch.object(secure.os, "open", side_effect=PermissionError(str(self.key_file))):
            failed = self.storage.status()
        self.assertFalse(failed["available"])
        self.assertNotIn(str(self.key_file), json.dumps(failed))

    def test_explicit_invalid_file_does_not_switch_to_systemd_or_keychain(self):
        credentials = self.root / "systemd"
        credentials.mkdir()
        provided = credentials / secure.SYSTEMD_KEY_NAME
        provided.write_bytes(self.key)
        provided.chmod(0o600)
        os.environ["CREDENTIALS_DIRECTORY"] = str(credentials)
        os.environ[secure.KEYCHAIN_ENV] = "1"
        for path in ("", "relative.key", str(self.root / "missing")):
            os.environ[secure.KEY_FILE_ENV] = path
            with self.subTest(path=path), patch.object(secure, "_macos_keyring") as backend:
                self.assertFalse(self.storage.available)
                self.assertEqual(self.storage.status()["key_source"], "file")
                backend.assert_not_called()

    def test_systemd_file_auto_discovery_and_explicit_file_precedence(self):
        credentials = self.root / "systemd"
        credentials.mkdir()
        provided = credentials / secure.SYSTEMD_KEY_NAME
        provided.write_bytes(os.urandom(32))
        provided.chmod(0o400)
        os.environ["CREDENTIALS_DIRECTORY"] = str(credentials)
        self.assertEqual(self.storage.status()["key_source"], "file")
        os.environ.pop(secure.KEY_FILE_ENV)
        self.assertEqual(self.storage.status()["key_source"], "systemd")
        blob = self.storage.encrypt(b"example", "cookies")
        self.assertEqual(self.storage.decrypt(blob, "cookies"), b"example")
        provided.chmod(0o600)  # Windows read-only attribute otherwise prevents cleanup.
        provided.unlink()
        self.assertEqual(self.storage.status()["key_source"], "none")

    def test_invalid_systemd_source_does_not_fall_back_to_keychain(self):
        credentials = self.root / "systemd"
        credentials.mkdir()
        (credentials / secure.SYSTEMD_KEY_NAME).mkdir()
        os.environ.pop(secure.KEY_FILE_ENV)
        os.environ["CREDENTIALS_DIRECTORY"] = str(credentials)
        os.environ[secure.KEYCHAIN_ENV] = "1"
        with patch.object(secure, "_macos_keyring") as backend:
            self.assertEqual(self.storage.status()["key_source"], "systemd")
            self.assertFalse(self.storage.available)
            backend.assert_not_called()

    def test_rejects_keys_inside_plugin_data_or_non_regular_sources(self):
        inside = self.data_dir / "bad.key"
        inside.write_bytes(self.key)
        for path in (inside, self.root):
            os.environ[secure.KEY_FILE_ENV] = str(path)
            with self.subTest(path=path), self.assertRaises(secure.StorageUnavailableError):
                self.storage.encrypt(b"example", "credentials")

    def test_runtime_rejects_key_inside_plugin_code_without_opening_it(self):
        # Pretend this temporary directory is the plugin code directory; never
        # create a key in the checkout itself.
        with patch.object(secure, "__file__", str(self.root / "hw_secure_storage.py")), \
                patch.object(secure.os, "open") as opened:
            with self.assertRaises(secure.StorageUnavailableError):
                self.storage.encrypt(b"example", "credentials")
            self.assertFalse(self.storage.status()["available"])
            opened.assert_not_called()

    def test_rejects_final_symlink(self):
        link = self.root / "link.key"
        try:
            link.symlink_to(self.key_file)
        except (NotImplementedError, OSError):
            self.skipTest("host does not permit creating test symlinks")
        os.environ[secure.KEY_FILE_ENV] = str(link)
        with self.assertRaises(secure.StorageUnavailableError):
            self.storage.encrypt(b"example", "credentials")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO only")
    def test_fifo_is_rejected_before_opening(self):
        fifo = self.root / "key.pipe"
        os.mkfifo(fifo, 0o600)
        os.environ[secure.KEY_FILE_ENV] = str(fifo)
        with patch.object(secure.os, "open", side_effect=AssertionError("must not open FIFO")):
            with self.assertRaises(secure.StorageUnavailableError):
                self.storage.encrypt(b"example", "credentials")

    def test_rejects_replaced_file_descriptor(self):
        original = os.fstat

        def changed(descriptor):
            info = original(descriptor)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid,
                                   st_dev=info.st_dev, st_ino=info.st_ino + 1, st_size=32)

        with patch.object(secure.os, "fstat", side_effect=changed):
            with self.assertRaises(secure.StorageUnavailableError):
                self.storage.encrypt(b"example", "credentials")

    def test_key_size_is_exact_and_reads_at_most_33_bytes(self):
        real_read = os.read
        for size in (0, 31, 33, 4096):
            self.key_file.write_bytes(os.urandom(size))
            with self.subTest(size=size), patch.object(secure.os, "read", wraps=real_read) as read:
                with self.assertRaises(secure.StorageUnavailableError):
                    self.storage.encrypt(b"example", "credentials")
                self.assertEqual(read.call_args.args[1], 33)

    def test_posix_permissions_require_private_mode_and_safe_owner(self):
        with patch.object(secure.os, "name", "posix"), \
                patch.object(secure.os, "geteuid", return_value=1000, create=True):
            for mode, uid in ((0o400, 0), (0o600, 1000)):
                secure._validate_file_stat(SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid))
            for mode, uid in ((0o640, 1000), (0o604, 1000), (0o601, 1000), (0o600, 1001)):
                with self.subTest(mode=mode, uid=uid), self.assertRaises(secure.StorageUnavailableError):
                    secure._validate_file_stat(SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid))

    def test_keychain_requires_explicit_opt_in_and_uses_exact_backend(self):
        os.environ.pop(secure.KEY_FILE_ENV)
        backend = Mock()
        backend.get_password.return_value = base64.b64encode(self.key).decode("ascii")
        module = SimpleNamespace(Keyring=Mock(return_value=backend))
        with patch.object(secure.sys, "platform", "darwin"), \
                patch.object(secure.importlib, "import_module", return_value=module) as imports:
            self.assertFalse(self.storage.available)
            imports.assert_not_called()
            os.environ[secure.KEYCHAIN_ENV] = "1"
            blob = self.storage.encrypt(b"example", "credentials")
            self.assertEqual(self.storage.decrypt(blob, "credentials"), b"example")
            imports.assert_called_with("keyring.backends.macOS")
            backend.get_password.assert_called_with(secure.KEYCHAIN_SERVICE, secure.KEYCHAIN_USERNAME)
            backend.set_password.assert_not_called()

    def test_invalid_or_locked_keychain_never_creates_a_key(self):
        os.environ.pop(secure.KEY_FILE_ENV)
        os.environ[secure.KEYCHAIN_ENV] = "1"
        for value in (None, "bad base64", base64.b64encode(os.urandom(31)).decode()):
            backend = Mock()
            backend.get_password.return_value = value
            with self.subTest(value=value), patch.object(secure, "_macos_keyring", return_value=backend):
                with self.assertRaises(secure.StorageUnavailableError):
                    self.storage.encrypt(b"example", "credentials")
                backend.set_password.assert_not_called()
        backend = Mock()
        backend.get_password.side_effect = RuntimeError("sensitive example")
        with patch.object(secure, "_macos_keyring", return_value=backend):
            self.assertFalse(self.storage.available)
            self.assertNotIn("sensitive example", self.storage.status()["error"])

    def test_explicit_keychain_on_other_platform_is_unavailable(self):
        os.environ.pop(secure.KEY_FILE_ENV)
        os.environ[secure.KEYCHAIN_ENV] = "1"
        with patch.object(secure.sys, "platform", "linux"), \
                patch.object(secure.importlib, "import_module") as imports:
            self.assertFalse(self.storage.available)
            self.assertEqual(self.storage.status()["key_source"], "keychain")
            imports.assert_not_called()


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hw-key-provision-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_create_file_is_32_bytes_and_never_overwrites(self):
        path = self.root / "master.key"
        secure.create_master_key_file(str(path))
        original = path.read_bytes()
        self.assertEqual(len(original), 32)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(secure.StorageUnavailableError):
            secure.create_master_key_file(str(path))
        self.assertEqual(path.read_bytes(), original)

    def test_create_file_rejects_plugin_code_and_data_directories(self):
        code_path = Path(secure.__file__).parent / "must-not-be-created.key"
        with self.assertRaises(secure.StorageUnavailableError):
            secure.create_master_key_file(str(code_path))
        data_dir = self.root / "data"
        data_dir.mkdir()
        with self.assertRaises(secure.StorageUnavailableError):
            secure.create_master_key_file(str(data_dir / "key"), data_dir=str(data_dir))
        self.assertEqual(list(data_dir.iterdir()), [])

    def test_cli_does_not_print_the_key_or_target_path(self):
        path = self.root / "master.key"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(secure._main(["create-file", "--output", str(path)]), 0)
            self.assertEqual(secure._main(["create-file", "--output", str(path)]), 1)
        rendered = out.getvalue() + err.getvalue()
        self.assertNotIn(str(path), rendered)
        self.assertNotIn(base64.b64encode(path.read_bytes()).decode(), rendered)

    def test_keychain_provision_refuses_existing_and_verifies_write(self):
        backend = Mock()
        backend.get_password.return_value = "existing"
        with patch.object(secure, "_macos_keyring", return_value=backend), \
                patch.object(secure, "_keychain_process_lock", side_effect=contextlib.nullcontext):
            with self.assertRaises(secure.StorageUnavailableError):
                secure.provision_keychain()
        backend.set_password.assert_not_called()
        backend = Mock()
        stored = {}
        backend.get_password.side_effect = lambda *_args: stored.get("value")
        backend.set_password.side_effect = lambda _service, _name, value: stored.update(value=value)
        with patch.object(secure, "_macos_keyring", return_value=backend), \
                patch.object(secure, "_keychain_process_lock", side_effect=contextlib.nullcontext):
            secure.provision_keychain()
        self.assertEqual(len(base64.b64decode(stored["value"], validate=True)), 32)

    def test_keychain_failed_or_silent_write_is_not_success(self):
        for fail in (True, False):
            backend = Mock()
            backend.get_password.return_value = None
            if fail:
                backend.set_password.side_effect = RuntimeError("must not appear")
            with self.subTest(fail=fail), patch.object(secure, "_macos_keyring", return_value=backend), \
                    patch.object(secure, "_keychain_process_lock", side_effect=contextlib.nullcontext):
                with self.assertRaises(secure.StorageLockedError) as raised:
                    secure.provision_keychain()
                self.assertNotIn("must not appear", str(raised.exception))

    def test_keychain_provision_reads_and_writes_only_while_process_lock_is_held(self):
        held = []

        @contextlib.contextmanager
        def lock():
            held.append(True)
            try:
                yield
            finally:
                held.clear()

        stored = {}

        def get(*_args):
            self.assertEqual(held, [True])
            return stored.get("value")

        def put(_service, _username, value):
            self.assertEqual(held, [True])
            stored["value"] = value

        backend = Mock(get_password=Mock(side_effect=get), set_password=Mock(side_effect=put))
        with patch.object(secure, "_macos_keyring", return_value=backend), \
                patch.object(secure, "_keychain_process_lock", side_effect=lock):
            secure.provision_keychain()
        self.assertFalse(held)
        with patch.object(secure, "_macos_keyring", return_value=backend), \
                patch.object(secure, "_keychain_process_lock", side_effect=secure.StorageLockedError("busy")):
            backend.reset_mock()
            with self.assertRaises(secure.StorageLockedError):
                secure.provision_keychain()
            backend.get_password.assert_not_called()
            backend.set_password.assert_not_called()

    @contextlib.contextmanager
    def _fake_lock_api(self, info=None, path_infos=None, flock_error=None):
        normal = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000,
                                 st_nlink=1, st_dev=1, st_ino=7)
        fcntl = SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=Mock(side_effect=flock_error))
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {"fcntl": fcntl}))
            stack.enter_context(patch.object(secure.os, "geteuid", return_value=1000, create=True))
            stack.enter_context(patch.object(secure.os, "O_NOFOLLOW", 0x200000, create=True))
            stack.enter_context(patch.object(secure.os, "O_NONBLOCK", 0x400000, create=True))
            opened = stack.enter_context(patch.object(secure.os, "open", return_value=123))
            stack.enter_context(patch.object(secure.os, "fstat", return_value=info or normal))
            stack.enter_context(patch.object(secure.os, "lstat", side_effect=path_infos or [normal, normal]))
            closed = stack.enter_context(patch.object(secure.os, "close"))
            unlinked = stack.enter_context(patch.object(secure.os, "unlink"))
            yield SimpleNamespace(fcntl=fcntl, opened=opened, closed=closed, unlinked=unlinked)

    def test_process_lock_is_nonblocking_nofollow_and_released_without_unlink(self):
        with self._fake_lock_api() as api:
            with secure._keychain_process_lock():
                api.fcntl.flock.assert_called_once_with(123, 6)
                api.closed.assert_not_called()
            args = api.opened.call_args.args
            self.assertEqual(args[0], "/tmp/astrbot-huawei-health-1000.keychain.lock")
            self.assertEqual(args[2], 0o600)
            self.assertTrue(args[1] & secure.os.O_NOFOLLOW)
            self.assertTrue(args[1] & secure.os.O_NONBLOCK)
            api.closed.assert_called_once_with(123)
            api.unlinked.assert_not_called()
        with self._fake_lock_api(flock_error=BlockingIOError("secret path")) as api:
            with self.assertRaises(secure.StorageLockedError) as raised:
                with secure._keychain_process_lock():
                    self.fail("contender must not enter the locked section")
            self.assertNotIn("secret path", str(raised.exception))
            api.closed.assert_called_once_with(123)
            api.unlinked.assert_not_called()

    def test_process_lock_rejects_unsafe_files_and_replaced_inodes(self):
        for mode, uid, nlink in ((stat.S_IFREG | 0o644, 1000, 1),
                                 (stat.S_IFREG | 0o600, 0, 1),
                                 (stat.S_IFIFO | 0o600, 1000, 1),
                                 (stat.S_IFREG | 0o600, 1000, 2)):
            info = SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=nlink, st_dev=1, st_ino=7)
            with self.subTest(mode=mode, uid=uid, nlink=nlink), self._fake_lock_api(info=info) as api:
                with self.assertRaises(secure.StorageUnavailableError):
                    with secure._keychain_process_lock():
                        self.fail("unsafe lock must not be used")
                api.fcntl.flock.assert_not_called()
                api.closed.assert_called_once_with(123)
        normal = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=1, st_ino=7)
        changed = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=1, st_ino=8)
        symlink = SimpleNamespace(st_mode=stat.S_IFLNK | 0o600, st_dev=1, st_ino=7)
        for checks in ([changed], [symlink], [normal, changed]):
            with self.subTest(checks=checks), self._fake_lock_api(path_infos=checks) as api:
                with self.assertRaises(secure.StorageUnavailableError):
                    with secure._keychain_process_lock():
                        self.fail("replaced lock must not be used")
                api.closed.assert_called_once_with(123)
                api.unlinked.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "real flock requires POSIX")
    def test_real_process_lock_contends_and_releases_after_process_exit(self):
        lock_path = self.root / "provision.lock"
        script = """
import os, sys
sys.path.insert(0, sys.argv[1])
import hw_secure_storage as secure
secure._keychain_lock_path = lambda uid: sys.argv[2]
try:
    with secure._keychain_process_lock():
        print('acquired', flush=True)
        if sys.argv[3] == 'exit':
            os._exit(0)
except secure.StorageLockedError:
    print('busy', flush=True)
"""

        def other_process(action="normal"):
            result = subprocess.run(
                [sys.executable, "-B", "-c", script, str(Path(secure.__file__).parent),
                 str(lock_path), action], capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

        with patch.object(secure, "_keychain_lock_path", return_value=str(lock_path)):
            with secure._keychain_process_lock():
                original_inode = lock_path.stat().st_ino
                self.assertEqual(other_process(), "busy")
            self.assertEqual(other_process(), "acquired")
            self.assertEqual(other_process("exit"), "acquired")
            with secure._keychain_process_lock():
                self.assertEqual(lock_path.stat().st_ino, original_inode)
        self.assertEqual(lock_path.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
