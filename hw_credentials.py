# -*- coding: utf-8 -*-
"""Protected credentials: Windows DPAPI or AES-GCM with an external key.

Legacy DPAPI files remain readable. New non-Windows writes require a usable
external key; neither missing keys nor encryption failures permit plaintext.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from ctypes import wintypes
from typing import Any, Dict

try:  # 插件作为包加载
    from .hw_privacy import redact_error
    from .hw_secure_storage import (
        AES_MAGIC, AesSecretStorage, StorageUnavailableError,
        StorageLockedError, StorageCorruptError,
    )
except ImportError:  # 插件目录在 sys.path 里
    from hw_privacy import redact_error
    from hw_secure_storage import (
        AES_MAGIC, AesSecretStorage, StorageUnavailableError,
        StorageLockedError, StorageCorruptError,
    )


MAGIC = b"HWCRED1\0"
PERSISTENT_MAGIC = b"HWDATA1\0"
CRYPTPROTECT_UI_FORBIDDEN = 0x1


class CredentialsError(RuntimeError):
    """Base class for credential storage errors."""


class CredentialsUnavailableError(CredentialsError):
    """No usable encryption backend or external master key is configured."""


class DPAPIUnavailableError(CredentialsUnavailableError):
    """Raised when Windows DPAPI cannot be used on this host."""


class CredentialsCorruptError(CredentialsError):
    """Raised when the credentials file is not a valid protected payload."""


class CredentialsLockedError(CredentialsError):
    """Raised when the credentials file exists but cannot be read (lock / ACL)."""


def harden_file_permissions(path: str) -> None:
    """Best-effort 0600 for a secret file on POSIX; no-op on Windows.

    ``open(path, "w")`` yields ``0666 & ~umask`` (usually 0644), which is more
    permissive than ``tempfile.mkstemp`` (0600).  Secret files must not be
    readable by other local users.
    """
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def harden_dir_permissions(dir_path: str) -> str:
    """Best-effort: stop the plugin data dir from inheriting broad ACLs.

    On Windows we drop inheritance and grant only the current user, SYSTEM and
    Administrators.  This needs no elevation for a directory the user owns and
    is a no-op if ``icacls`` is unavailable.

    Returns "" on success, otherwise a short human-readable reason (the caller
    logs it — silently "succeeding" while the ACL is unchanged is worse than
    failing loudly).

    Note: ``/inheritance:r`` only removes **inherited** ACEs; explicit grants
    someone added by hand stay.  README documents this.
    """
    if not dir_path or not os.path.isdir(dir_path):
        return "目录不存在"
    if os.name != "nt":
        try:
            os.chmod(dir_path, 0o700)
            return ""
        except OSError as exc:
            return "chmod 失败：%s" % redact_error(exc)
    user = os.environ.get("USERNAME") or ""
    if not user:
        return "读不到 USERNAME，跳过 ACL 收紧"
    try:
        proc = subprocess.run(
            [
                "icacls", dir_path, "/inheritance:r",
                "/grant:r", user + ":(OI)(CI)F",
                "SYSTEM:(OI)(CI)F",
                "Administrators:(OI)(CI)F",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except Exception as exc:
        return "icacls 无法执行：%s" % redact_error(exc)
    if proc.returncode != 0:
        return "icacls 返回码 %d（账户名与 SID 可能对不上）" % proc.returncode
    return ""


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _require_dpapi():
    if sys.platform != "win32":
        raise DPAPIUnavailableError("Windows DPAPI is unavailable on this platform")
    try:
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        protect = crypt32.CryptProtectData
        unprotect = crypt32.CryptUnprotectData
        protect.argtypes = [
            ctypes.POINTER(_DATA_BLOB), ctypes.c_wchar_p,
            ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(_DATA_BLOB),
            wintypes.DWORD, ctypes.POINTER(_DATA_BLOB),
        ]
        protect.restype = wintypes.BOOL
        unprotect.argtypes = [
            ctypes.POINTER(_DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p),
            ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(_DATA_BLOB),
            wintypes.DWORD, ctypes.POINTER(_DATA_BLOB),
        ]
        unprotect.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        return protect, unprotect, kernel32.LocalFree
    except (AttributeError, OSError) as exc:
        raise DPAPIUnavailableError("Windows DPAPI is unavailable") from exc


def _blob(data: bytes):
    raw = ctypes.create_string_buffer(data)
    return _DATA_BLOB(len(data), ctypes.cast(raw, ctypes.POINTER(ctypes.c_ubyte))), raw


def _protect(data: bytes) -> bytes:
    protect, _unprotect, local_free = _require_dpapi()
    src, keepalive = _blob(data)
    dst = _DATA_BLOB()
    if not protect(ctypes.byref(src), "AstrBot Huawei Health credentials",
                   None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(dst)):
        raise CredentialsError("Windows DPAPI encryption failed")
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        if dst.pbData:
            local_free(dst.pbData)
        del keepalive


def _unprotect(data: bytes) -> bytes:
    _protect_fn, unprotect, local_free = _require_dpapi()
    src, keepalive = _blob(data)
    dst = _DATA_BLOB()
    description = ctypes.c_wchar_p()
    if not unprotect(ctypes.byref(src), ctypes.byref(description), None, None, None,
                     CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(dst)):
        raise CredentialsError("Windows DPAPI decryption failed")
    try:
        return ctypes.string_at(dst.pbData, dst.cbData)
    finally:
        if dst.pbData:
            local_free(dst.pbData)
        if description:
            local_free(description)
        del keepalive


def _aes_operation(data: bytes, purpose: str, data_dir: str, *, decrypt=False) -> bytes:
    storage = AesSecretStorage(data_dir)
    try:
        return storage.decrypt(data, purpose) if decrypt else storage.encrypt(data, purpose)
    except StorageUnavailableError as exc:
        raise CredentialsUnavailableError(str(exc)) from exc
    except StorageLockedError as exc:
        raise CredentialsLockedError(str(exc)) from exc
    except StorageCorruptError as exc:
        raise CredentialsCorruptError(str(exc)) from exc


def persistent_storage_status(data_dir: str) -> Dict[str, Any]:
    """Safe write-capability metadata, never key material or key paths."""
    if sys.platform != "win32":
        return AesSecretStorage(data_dir).status()
    try:
        _require_dpapi()
        error = ""
    except DPAPIUnavailableError:
        error = "Windows DPAPI 不可用，请检查当前 Windows 用户环境"
    return {"available": not error, "method": "dpapi", "key_source": "windows-user", "error": error}


def protect_persistent_secret(data: bytes, purpose: str, data_dir: str) -> bytes:
    """Protect a cache secret with a purpose-bound, versioned envelope."""
    if sys.platform == "win32":
        prefix = ("astrbot.huawei_health:v1:" + purpose + "\0").encode("utf-8")
        return PERSISTENT_MAGIC + _protect(prefix + data)
    return _aes_operation(data, purpose, data_dir)


def unprotect_persistent_secret(blob: bytes, purpose: str, data_dir: str) -> bytes:
    # Detect the stored format before choosing any backend: OS changes must not
    # cause a DPAPI blob to be mistaken for AES-GCM or plaintext.
    if blob.startswith(AES_MAGIC):
        return _aes_operation(blob, purpose, data_dir, decrypt=True)
    if not blob.startswith(PERSISTENT_MAGIC) or len(blob) <= len(PERSISTENT_MAGIC):
        raise CredentialsCorruptError("受保护数据格式无效")
    try:
        plain = _unprotect(blob[len(PERSISTENT_MAGIC):])
    except CredentialsUnavailableError:
        raise
    except CredentialsError as exc:
        raise CredentialsLockedError("无法解密缓存，请检查原 Windows 用户环境") from exc
    prefix = ("astrbot.huawei_health:v1:" + purpose + "\0").encode("utf-8")
    if not plain.startswith(prefix):
        raise CredentialsCorruptError("受保护数据用途不匹配")
    return plain[len(prefix):]


def mask_account(account: str) -> str:
    """Return a display mask that never reveals the whole secret.

    Invariant (covered by tests): stripping ``*`` from the result must leave
    strictly fewer characters than the input, for every input length.
    """
    value = str(account or "").strip()
    if not value:
        return ""
    if "@" in value:
        local, _, domain = value.partition("@")
        head, dot, tld = domain.rpartition(".")
        if dot and head:
            shown_domain = "*" * max(1, len(head)) + "." + tld
        else:
            shown_domain = "*" * len(domain)
        # Only show one leading char of a reasonably long local part.
        shown_local = local[:1] if len(local) > 3 else ""
        return (shown_local + "***" if shown_local else "***") + "@" + shown_domain
    if value.isdigit():
        if len(value) <= 8:
            # 3 + 4 == 7 used to cover the whole string for 7-digit accounts.
            return "*" * len(value)
        return value[:2] + "****" + value[-2:]
    if len(value) <= 4:
        return "*" * len(value)
    return value[:1] + "***" + value[-1:]


class HuaweiCredentialsStore:
    """Read/write encrypted ``credentials.bin`` for one plugin instance."""

    def __init__(self, data_dir: str):
        self.data_dir = os.path.abspath(os.fspath(data_dir))
        self.path = os.path.join(self.data_dir, "credentials.bin")
        self._lock = threading.RLock()

    @property
    def available(self) -> bool:
        return bool(persistent_storage_status(self.data_dir)["available"])

    def save(self, account: str, password: str) -> Dict[str, Any]:
        account = str(account or "").strip()
        password = str(password or "")
        if not account:
            raise CredentialsError("account is required")
        if not password:
            raise CredentialsError("password is required")
        # JSON is created in memory and is immediately encrypted; it is never
        # written to a temporary plaintext file.
        with self._lock:
            # A typo/replaced master key must never destroy the last readable
            # copy. Explicit clear is required to discard an unrecoverable file.
            if os.path.exists(self.path):
                self.load()
            payload = json.dumps(
                {"account": account, "password": password, "updated_at": int(time.time())},
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            ciphertext = (MAGIC + _protect(payload) if sys.platform == "win32"
                          else _aes_operation(payload, "credentials", self.data_dir))
            os.makedirs(self.data_dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".credentials.", suffix=".tmp", dir=self.data_dir)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(ciphertext)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(tmp, self.path)
                harden_file_permissions(self.path)
            finally:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass
        return self.status()

    def load(self) -> Dict[str, str]:
        with self._lock:
            if not os.path.isfile(self.path):
                raise CredentialsError("credentials are not set")
            try:
                with open(self.path, "rb") as stream:
                    raw = stream.read(1024 * 1024 + 1)
            except OSError as exc:
                # Locked / permission denied is NOT "never saved" — callers must
                # be able to tell the user to close whatever holds the file.
                raise CredentialsLockedError("cannot read credentials") from exc
        if len(raw) > 1024 * 1024:
            raise CredentialsCorruptError("credentials file is invalid")
        try:
            if raw.startswith(AES_MAGIC):
                payload = _aes_operation(raw, "credentials", self.data_dir, decrypt=True)
            elif raw.startswith(MAGIC) and len(raw) > len(MAGIC):
                payload = _unprotect(raw[len(MAGIC):])
            else:
                raise CredentialsCorruptError("credentials file is invalid")
            value = json.loads(payload.decode("utf-8"))
        except (CredentialsUnavailableError, CredentialsLockedError, CredentialsCorruptError):
            raise
        except Exception as exc:
            raise CredentialsCorruptError("credentials cannot be decrypted") from exc
        if not isinstance(value, dict) or not isinstance(value.get("account"), str) or not isinstance(value.get("password"), str):
            raise CredentialsCorruptError("credentials payload is invalid")
        return {"account": value["account"], "password": value["password"]}

    def clear(self) -> bool:
        with self._lock:
            try:
                os.unlink(self.path)
                return True
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise CredentialsError("cannot remove credentials") from exc

    def status(self, masked: bool = True) -> Dict[str, Any]:
        """Return safe metadata; the ``masked`` flag is accepted for API clarity.

        Even when a caller passes ``masked=False`` this method never exposes an
        account or credential value.  There is intentionally no unmasked
        status mode.

        ``state`` distinguishes the three cases the UI must tell apart:
        ``absent`` / ``ok`` / ``corrupt`` / ``locked`` / ``unavailable``.
        """
        result: Dict[str, Any] = {
            "mode": "cookie",
            "password_set": False,
            "account_masked": "",
            "updated_at": None,
            "state": "absent",
            "error": "",
            "storage": persistent_storage_status(self.data_dir),
        }
        if not os.path.isfile(self.path):
            return result
        try:
            with self._lock, open(self.path, "rb") as stream:
                header = stream.read(len(AES_MAGIC))
                if header == AES_MAGIC:
                    result["storage"] = AesSecretStorage(self.data_dir).status()
                elif header == MAGIC and sys.platform != "win32":
                    result["storage"] = {
                        "available": False, "method": "dpapi", "key_source": "windows-user",
                        "error": "现有凭据使用 Windows DPAPI，需原 Windows 用户和机器解密；确认放弃时先清除再保存",
                    }
        except OSError:
            # load() below returns the existing, precise locked/error state.
            pass
        try:
            value = self.load()
        except CredentialsUnavailableError as exc:
            result["state"] = "unavailable"
            result["error"] = redact_error(exc)
            return result
        except CredentialsLockedError:
            result["state"] = "locked"
            result["error"] = "凭据已锁定，请检查文件权限、原主密钥及数据完整性；不要直接覆盖"
            return result
        except CredentialsCorruptError:
            result["state"] = "corrupt"
            result["error"] = "凭据文件损坏或无法解密；确认无法恢复后先清除再保存"
            return result
        except CredentialsError:
            result["state"] = "corrupt"
            result["error"] = "凭据读取失败"
            return result
        result["mode"] = "password"
        result["state"] = "ok"
        result["password_set"] = bool(value.get("password"))
        result["account_masked"] = mask_account(value.get("account", ""))
        try:
            result["updated_at"] = int(os.path.getmtime(self.path))
        except OSError:
            pass
        return result


# Short alias for integrations that prefer a generic name.
CredentialsStore = HuaweiCredentialsStore


__all__ = [
    "CredentialsError", "CredentialsCorruptError", "CredentialsLockedError", "CredentialsUnavailableError",
    "DPAPIUnavailableError", "HuaweiCredentialsStore", "CredentialsStore",
    "mask_account", "harden_file_permissions", "harden_dir_permissions",
    "protect_persistent_secret", "unprotect_persistent_secret", "persistent_storage_status",
]
