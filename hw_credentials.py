# -*- coding: utf-8 -*-
"""Protected Huawei Health login credentials.

The file written by :class:`HuaweiCredentialsStore` contains only a small
header and a Windows DPAPI ciphertext.  DPAPI is deliberately the only
backend in this module: silently falling back to plaintext (or to a key kept
next to the plugin) would turn an optional feature into a credential leak.
Callers should treat :class:`DPAPIUnavailableError` as "password login is
disabled" and continue offering cookie/manual login.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
import tempfile
import threading
import time
from ctypes import wintypes
from typing import Any, Dict


MAGIC = b"HWCRED1\0"
CRYPTPROTECT_UI_FORBIDDEN = 0x1


class CredentialsError(RuntimeError):
    """Base class for credential storage errors."""


class DPAPIUnavailableError(CredentialsError):
    """Raised when Windows DPAPI cannot be used on this host."""


class CredentialsCorruptError(CredentialsError):
    """Raised when the credentials file is not a valid protected payload."""


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


def mask_account(account: str) -> str:
    """Return a server-generated display mask without exposing the secret."""
    value = str(account or "").strip()
    if not value:
        return ""
    if value.isdigit() and len(value) >= 7:
        return value[:3] + "****" + value[-4:]
    if "@" in value:
        local, domain = value.split("@", 1)
        shown = local[:1] + "***" if local else "***"
        return shown + "@" + domain
    if len(value) <= 2:
        return "*" * len(value)
    return value[:1] + "***" + value[-1:]


class HuaweiCredentialsStore:
    """Read/write DPAPI-protected ``credentials.bin`` for one plugin instance."""

    def __init__(self, data_dir: str):
        self.data_dir = os.path.abspath(os.fspath(data_dir))
        self.path = os.path.join(self.data_dir, "credentials.bin")
        self._lock = threading.RLock()

    @property
    def available(self) -> bool:
        try:
            _require_dpapi()
            return True
        except DPAPIUnavailableError:
            return False

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
            payload = json.dumps(
                {"account": account, "password": password, "updated_at": int(time.time())},
                ensure_ascii=False, separators=(",", ":"),
            ).encode("utf-8")
            ciphertext = MAGIC + _protect(payload)
            os.makedirs(self.data_dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".credentials.", suffix=".tmp", dir=self.data_dir)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(ciphertext)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(tmp, self.path)
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
                    raw = stream.read()
            except OSError as exc:
                raise CredentialsError("cannot read credentials") from exc
        if not raw.startswith(MAGIC) or len(raw) <= len(MAGIC):
            raise CredentialsCorruptError("credentials file is invalid")
        try:
            value = json.loads(_unprotect(raw[len(MAGIC):]).decode("utf-8"))
        except DPAPIUnavailableError:
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
        """
        result: Dict[str, Any] = {
            "mode": "cookie",
            "password_set": False,
            "account_masked": "",
            "updated_at": None,
        }
        if not os.path.isfile(self.path):
            return result
        try:
            value = self.load()
        except DPAPIUnavailableError:
            # Keep status safe and useful on non-Windows hosts; callers can
            # inspect ``available`` without receiving any ciphertext.
            return result
        except CredentialsError:
            return result
        result["mode"] = "password"
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
    "CredentialsError", "CredentialsCorruptError", "DPAPIUnavailableError",
    "HuaweiCredentialsStore", "CredentialsStore", "mask_account",
]
