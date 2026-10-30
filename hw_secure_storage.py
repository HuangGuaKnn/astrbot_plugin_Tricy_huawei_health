"""AES-GCM protection backed by an externally provisioned 32-byte master key.

The plugin never creates a key implicitly or falls back to plaintext. The
format version in AES_MAGIC is independent of the plugin release version so
upgrading the plugin does not make existing ciphertext unreadable.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import contextmanager
import hmac
import importlib
import os
import stat
import sys
import threading


AES_MAGIC = b"HWAEAD1\0"
KEY_FILE_ENV = "HUAWEI_HEALTH_MASTER_KEY_FILE"
SYSTEMD_KEY_NAME = "huawei-health-master"
KEYCHAIN_ENV = "HUAWEI_HEALTH_KEYCHAIN"
KEYCHAIN_SERVICE = "astrbot.huawei_health"
KEYCHAIN_USERNAME = "master-key-v1"
_NONCE_SIZE = 12
_TAG_SIZE = 16
_KEY_SIZE = 32
_PROVISION_LOCK = threading.Lock()


class StorageError(RuntimeError):
    """Safe-to-display storage error; messages never contain secret material."""


class StorageUnavailableError(StorageError):
    """The configured secure storage source is missing or unusable."""


class StorageLockedError(StorageError):
    """The source is inaccessible, or authentication of the ciphertext failed."""


class StorageCorruptError(StorageError):
    """The encrypted envelope is structurally invalid or truncated."""


def _aesgcm_type():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise StorageUnavailableError("缺少 cryptography 依赖，无法使用安全存储") from None
    return AESGCM


def _absolute_path(path):
    try:
        value = os.fspath(path)
    except TypeError:
        raise StorageUnavailableError("主密钥文件必须使用绝对路径") from None
    if not isinstance(value, str) or not value or "\0" in value or not os.path.isabs(value):
        raise StorageUnavailableError("主密钥文件必须使用绝对路径")
    return value


def _canonical(path):
    return os.path.normcase(os.path.realpath(path))


def _outside_directory(path, directory):
    target, parent = _canonical(path), _canonical(directory)
    try:
        inside = os.path.commonpath((target, parent)) == parent
    except ValueError:  # Different Windows volumes are necessarily separate.
        inside = False
    if inside:
        raise StorageUnavailableError("主密钥必须存放在插件代码和数据目录之外")


def _validate_file_stat(info):
    if not stat.S_ISREG(info.st_mode):
        raise StorageUnavailableError("主密钥来源必须是普通文件，不能是目录或特殊设备")
    if os.name != "nt":
        current_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if info.st_uid not in (0, current_uid):
            raise StorageUnavailableError("主密钥文件所有者必须是当前用户或 root")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise StorageUnavailableError("主密钥文件权限过宽，请限制为仅所有者可访问")


def _read_key_file(path, data_dir):
    path = _absolute_path(path)
    _outside_directory(path, data_dir)
    code_dir = os.path.dirname(os.path.abspath(__file__))
    _outside_directory(path, code_dir)
    canonical_before = _canonical(path)
    descriptor = None
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode):
            raise StorageUnavailableError("主密钥文件不能是符号链接")
        _validate_file_stat(before)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        _validate_file_stat(opened)
        # Verify the opened object rather than trusting the path checked above.
        # This also protects Windows hosts which do not expose O_NOFOLLOW.
        after = os.lstat(path)
        if (stat.S_ISLNK(after.st_mode) or
                (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or
                (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino) or
                _canonical(path) != canonical_before):
            raise StorageUnavailableError("主密钥文件在读取时发生变化，请重试")
        _outside_directory(path, data_dir)
        _outside_directory(path, code_dir)
        # Never perform an unbounded read, even if a path was replaced by a FIFO.
        data = os.read(descriptor, _KEY_SIZE + 1)
        if len(data) != _KEY_SIZE or opened.st_size != _KEY_SIZE:
            raise StorageUnavailableError("主密钥文件必须包含恰好 32 字节的原始随机密钥")
        return data
    except StorageError:
        raise
    except FileNotFoundError:
        raise StorageUnavailableError("主密钥文件不存在，请先配置外部主密钥") from None
    except PermissionError:
        raise StorageLockedError("无权读取主密钥文件，请检查服务用户与文件权限") from None
    except OSError:
        raise StorageUnavailableError("无法读取主密钥文件，请检查文件类型与访问权限") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _macos_keyring():
    if sys.platform != "darwin":
        raise StorageUnavailableError("macOS 钥匙串后端仅可在 macOS 使用")
    try:
        module = importlib.import_module("keyring.backends.macOS")
        return module.Keyring()
    except ImportError:
        raise StorageUnavailableError("缺少 macOS keyring 依赖") from None
    except Exception:
        raise StorageUnavailableError("macOS 钥匙串后端无法初始化") from None


def _read_keychain_key():
    backend = _macos_keyring()
    try:
        value = backend.get_password(KEYCHAIN_SERVICE, KEYCHAIN_USERNAME)
    except Exception:
        raise StorageLockedError("无法读取 macOS 钥匙串主密钥，请先解锁钥匙串") from None
    if value is None:
        raise StorageUnavailableError("macOS 钥匙串中尚未配置主密钥")
    try:
        key = base64.b64decode(value, validate=True)
    except (ValueError, TypeError, binascii.Error):
        raise StorageUnavailableError("macOS 钥匙串主密钥格式不正确") from None
    if len(key) != _KEY_SIZE:
        raise StorageUnavailableError("macOS 钥匙串主密钥必须解码为 32 字节")
    return key


class AesSecretStorage:
    """Small stateless protector shared by password, cookie and token storage."""

    def __init__(self, data_dir):
        self.data_dir = os.path.abspath(os.fspath(data_dir))

    def _source(self):
        # Explicit configuration wins even when it is empty, invalid or unreadable.
        if KEY_FILE_ENV in os.environ:
            return "file", os.environ[KEY_FILE_ENV]
        credentials_dir = os.environ.get("CREDENTIALS_DIRECTORY")
        if credentials_dir:
            candidate = os.path.join(credentials_dir, SYSTEMD_KEY_NAME)
            if os.path.lexists(candidate):
                return "systemd", candidate
        if os.environ.get(KEYCHAIN_ENV) == "1":
            return "keychain", None
        return "none", None

    def _key(self, source=None):
        kind, location = source or self._source()
        if kind in ("file", "systemd"):
            return _read_key_file(location, self.data_dir)
        if kind == "keychain":
            return _read_keychain_key()
        raise StorageUnavailableError("未配置外部主密钥，安全持久化不可用")

    @staticmethod
    def _aad(purpose):
        if not isinstance(purpose, str) or not purpose or "\0" in purpose or len(purpose) > 128:
            raise StorageError("安全存储用途标识无效")
        return b"astrbot_plugin_Tricy_huawei_health\0" + AES_MAGIC + purpose.encode("utf-8")

    @property
    def available(self):
        return self.status()["available"]

    def status(self):
        source = self._source()
        result = {"available": False, "method": "aes-256-gcm",
                  "key_source": source[0], "error": ""}
        try:
            _aesgcm_type()
            self._key(source)
        except StorageError as exc:
            result["error"] = str(exc)
        else:
            result["available"] = True
        return result

    def encrypt(self, payload: bytes, purpose: str) -> bytes:
        if not isinstance(payload, bytes):
            raise StorageError("待加密内容必须是字节数据")
        aad = self._aad(purpose)
        aesgcm = _aesgcm_type()(self._key())
        nonce = os.urandom(_NONCE_SIZE)
        return AES_MAGIC + nonce + aesgcm.encrypt(nonce, payload, aad)

    def decrypt(self, blob: bytes, purpose: str) -> bytes:
        if (not isinstance(blob, bytes) or not blob.startswith(AES_MAGIC) or
                len(blob) < len(AES_MAGIC) + _NONCE_SIZE + _TAG_SIZE):
            raise StorageCorruptError("加密文件格式不正确或已截断")
        aad = self._aad(purpose)
        aesgcm = _aesgcm_type()(self._key())
        from cryptography.exceptions import InvalidTag
        offset = len(AES_MAGIC)
        nonce, ciphertext = blob[offset:offset + _NONCE_SIZE], blob[offset + _NONCE_SIZE:]
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            # Wrong keys and tampered ciphertext are intentionally indistinguishable.
            raise StorageLockedError("无法解锁加密文件：主密钥不匹配或文件已被修改") from None


def create_master_key_file(path, *, data_dir=None):
    """Provision a new raw key explicitly; never replace an existing object."""
    path = _absolute_path(path)
    _outside_directory(path, os.path.dirname(os.path.abspath(__file__)))
    if data_dir is not None:
        _outside_directory(path, data_dir)
    descriptor = None
    created_info = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags, 0o600)
        created_info = os.fstat(descriptor)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(os.urandom(_KEY_SIZE))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        raise StorageUnavailableError("目标已存在，拒绝覆盖主密钥") from None
    except OSError:
        # Remove only the incomplete file this call created, never a replacement.
        if created_info is not None:
            try:
                current = os.lstat(path)
                if (current.st_dev, current.st_ino) == (created_info.st_dev, created_info.st_ino):
                    os.unlink(path)
            except OSError:
                pass
        raise StorageUnavailableError("无法创建主密钥文件，请检查目标目录和权限") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _keychain_lock_path(uid):
    # Keep the namespace stable across CLI processes with different TMPDIR values.
    # macOS /tmp resolves to /private/tmp; no secret is stored in this lock file.
    return "/tmp/astrbot-huawei-health-%s.keychain.lock" % uid


@contextmanager
def _keychain_process_lock():
    """Serialize provisioning across processes; closing/crashing releases flock."""
    try:
        import fcntl
    except ImportError:
        raise StorageUnavailableError("当前系统不支持钥匙串初始化进程锁") from None
    uid = os.geteuid()
    path = _keychain_lock_path(uid)
    descriptor = None
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        flags |= getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags, 0o600)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or
                stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1):
            raise StorageUnavailableError("钥匙串初始化锁必须由当前用户独占并具有 0600 权限")
        path_info = os.lstat(path)
        if (stat.S_ISLNK(path_info.st_mode) or
                (path_info.st_dev, path_info.st_ino) != (opened.st_dev, opened.st_ino)):
            raise StorageUnavailableError("钥匙串初始化锁文件发生变化，请重试")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StorageLockedError("其他进程正在初始化钥匙串主密钥，请稍后重试") from None
        path_info = os.lstat(path)
        if (stat.S_ISLNK(path_info.st_mode) or
                (path_info.st_dev, path_info.st_ino) != (opened.st_dev, opened.st_ino)):
            raise StorageUnavailableError("钥匙串初始化锁文件发生变化，请重试")
        yield
    except StorageError:
        raise
    except OSError:
        raise StorageLockedError("无法取得钥匙串初始化锁，请检查临时目录权限") from None
    finally:
        if descriptor is not None:
            # Never unlink: another process may already be waiting on this inode.
            os.close(descriptor)


def provision_keychain():
    """Provision the explicit macOS backend; status/encryption never call this."""
    backend = _macos_keyring()
    with _PROVISION_LOCK, _keychain_process_lock():
        try:
            existing = backend.get_password(KEYCHAIN_SERVICE, KEYCHAIN_USERNAME)
            if existing is not None:
                raise StorageUnavailableError("钥匙串主密钥已存在，拒绝覆盖")
            value = base64.b64encode(os.urandom(_KEY_SIZE)).decode("ascii")
            backend.set_password(KEYCHAIN_SERVICE, KEYCHAIN_USERNAME, value)
            saved = backend.get_password(KEYCHAIN_SERVICE, KEYCHAIN_USERNAME)
            if not isinstance(saved, str) or not hmac.compare_digest(saved, value):
                raise StorageLockedError("钥匙串主密钥写入后校验失败")
        except StorageError:
            raise
        except Exception:
            raise StorageLockedError("无法写入 macOS 钥匙串主密钥，请检查授权") from None


def _main(argv=None):
    parser = argparse.ArgumentParser(description="显式配置华为健康插件外部主密钥（不会输出密钥内容）")
    commands = parser.add_subparsers(dest="command", required=True)
    file_command = commands.add_parser("create-file", help="创建新的外部 32 字节主密钥文件")
    file_command.add_argument("--output", required=True)
    file_command.add_argument("--data-dir", help="插件数据目录；主密钥不得写入此目录")
    commands.add_parser("create-keychain", help="在 macOS 钥匙串创建主密钥")
    args = parser.parse_args(argv)
    try:
        if args.command == "create-file":
            create_master_key_file(args.output, data_dir=args.data_dir)
        else:
            provision_keychain()
    except StorageError as exc:
        print("失败：%s" % exc, file=sys.stderr)
        return 1
    print("主密钥已创建。请妥善保管；丢失后无法解密已保存的数据。")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
