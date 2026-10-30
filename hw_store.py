# -*- coding: utf-8 -*-
"""华为运动健康 · 极简 SQLite 缓存（token + 数据快照）

连接策略（v0.4.1）：
    - 每次操作仍然新建连接并显式关闭（Windows 上不长期占用 health.db，
      备份/卸载不会被锁）；
    - 但 ``PRAGMA journal_mode=WAL`` 只在建库时设一次——它是持久化到库头的，
      每次连接重复执行要拿库级写锁 + fsync，实测把 0.38 ms 抬到 3.52 ms。
"""

import base64
import binascii
import json
import os
import sqlite3
import time
from contextlib import contextmanager

try:
    from . import hw_credentials as credential_storage
except ImportError:
    import hw_credentials as credential_storage


_PROTECTED_TOKEN_FIELD = "_protected"


class HealthStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.data_dir = os.path.dirname(os.path.abspath(db_path))
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init()

    @contextmanager
    def _conn(self):
        # 每次操作都显式关闭连接，避免 Windows 锁住 health.db 使备份/卸载失败。
        conn = sqlite3.connect(self.db_path, timeout=15)
        try:
            conn.row_factory = sqlite3.Row
            # busy_timeout 是连接级的，必须每次设；journal_mode 是库级持久设置。
            conn.execute("PRAGMA busy_timeout=15000")
            # Token deletion must not leave the old plaintext in freed SQLite cells.
            # This does not erase backups, filesystem snapshots or historical copies.
            conn.execute("PRAGMA secure_delete=ON")
            yield conn
            # 显式提交，保持调用方原有的 with self._conn() as c 事务语义。
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init(self):
        removed_legacy_token = False
        with self._conn() as c:
            # WAL 与 busy_timeout 让读写并发时少遇到 database is locked。
            c.execute("PRAGMA journal_mode=WAL")
            c.execute(
                "CREATE TABLE IF NOT EXISTS kv ("
                "k TEXT PRIMARY KEY, v TEXT NOT NULL, expire_at REAL NOT NULL)"
            )
            row = c.execute("SELECT v FROM kv WHERE k='token'").fetchone()
            if row and self._is_legacy_token(row["v"]):
                c.execute("DELETE FROM kv WHERE k='token' AND v=?", (row["v"],))
                removed_legacy_token = True
            # 启动时清掉已过期快照，避免换账号或长期运行后旧健康数据残留。
            c.execute("DELETE FROM kv WHERE expire_at > 0 AND expire_at < ?", (time.time(),))
        if removed_legacy_token:
            self._checkpoint_removed_token()

    @staticmethod
    def _is_legacy_token(raw):
        try:
            value = json.loads(raw)
        except (ValueError, TypeError):
            return False
        return isinstance(value, dict) and _PROTECTED_TOKEN_FIELD not in value

    def _checkpoint_removed_token(self):
        # Remove obsolete WAL frames where possible after a legacy plaintext row
        # was deleted. A live reader may keep older pages pinned; SQLite then
        # reports busy and retries via its normal later checkpoints. Never unlink
        # the WAL ourselves: that would risk corruption of concurrent users.
        try:
            with self._conn() as c:
                c.execute("PRAGMA busy_timeout=0")
                c.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        except sqlite3.OperationalError:
            # Another connection may already be checkpointing. The committed
            # deletion remains valid and is not undone by this best-effort step.
            pass

    def _forget_legacy_token(self, raw):
        with self._conn() as c:
            # A concurrent authenticated writer may already have replaced this
            # value. In that case its new protected token must survive.
            deleted = c.execute("DELETE FROM kv WHERE k='token' AND v=?", (raw,)).rowcount
        if deleted:
            self._checkpoint_removed_token()

    def _protect_token(self, value):
        if not isinstance(value, dict):
            raise credential_storage.CredentialsCorruptError("token payload must be an object")
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        blob = credential_storage.protect_persistent_secret(payload, "token", self.data_dir)
        return {_PROTECTED_TOKEN_FIELD: base64.b64encode(blob).decode("ascii")}

    def _unprotect_token(self, value):
        if (not isinstance(value, dict) or set(value) != {_PROTECTED_TOKEN_FIELD}
                or not isinstance(value[_PROTECTED_TOKEN_FIELD], str)):
            raise credential_storage.CredentialsCorruptError("token storage envelope is invalid")
        try:
            blob = base64.b64decode(value[_PROTECTED_TOKEN_FIELD], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise credential_storage.CredentialsCorruptError("token storage envelope is invalid") from exc
        # Unavailable keys, a wrong key and authenticated decryption failures are
        # surfaced to the caller. Treating these as a cache miss could hide a
        # locked credential store and start a fresh login over existing state.
        payload = credential_storage.unprotect_persistent_secret(blob, "token", self.data_dir)
        try:
            value = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise credential_storage.CredentialsCorruptError("token payload is invalid") from exc
        if not isinstance(value, dict):
            raise credential_storage.CredentialsCorruptError("token payload must be an object")
        return value

    def _set_token(self, value, expire_at):
        removed_legacy_token = False
        with self._conn() as c:
            # Validate an existing ciphertext before replacing it. A configured
            # but wrong key is not a request to destroy the old login state.
            # Reserve the write transaction so another process cannot swap the
            # row between this validation and the replacement.
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT v FROM kv WHERE k='token'").fetchone()
            if row:
                try:
                    previous = json.loads(row["v"])
                except (ValueError, TypeError) as exc:
                    raise credential_storage.CredentialsCorruptError("token storage envelope is invalid") from exc
                if isinstance(previous, dict) and _PROTECTED_TOKEN_FIELD not in previous:
                    removed_legacy_token = True
                else:
                    self._unprotect_token(previous)
            # Encryption precedes the actual write. Any key/provider failure
            # rolls back the transaction and preserves the existing row.
            protected = self._protect_token(value)
            c.execute(
                "INSERT INTO kv(k, v, expire_at) VALUES('token',?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v, expire_at=excluded.expire_at",
                (json.dumps(protected, ensure_ascii=False), expire_at),
            )
        if removed_legacy_token:
            self._checkpoint_removed_token()

    def set(self, key: str, value, ttl: int = 0):
        # ttl <= 0 表示「不缓存」由调用方决定；这里保持 0 = 永不过期（token 行语义）。
        expire_at = (time.time() + ttl) if ttl else 0.0
        if key == "token":
            return self._set_token(value, expire_at)
        with self._conn() as c:
            # 单次写入放在连接事务中，确保值和过期时间一起提交。
            c.execute(
                "INSERT INTO kv(k, v, expire_at) VALUES(?,?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v, expire_at=excluded.expire_at",
                (key, json.dumps(value, ensure_ascii=False), expire_at),
            )

    def get(self, key: str, default=None):
        with self._conn() as c:
            row = c.execute("SELECT v, expire_at FROM kv WHERE k=?", (key,)).fetchone()
        if not row:
            return default
        if row["expire_at"] and row["expire_at"] < time.time():
            # 读到过期项立即删除，降低过期健康数据继续残留的时间。
            with self._conn() as c:
                c.execute("DELETE FROM kv WHERE k=? AND expire_at > 0 AND expire_at < ?", (key, time.time()))
            return default
        try:
            value = json.loads(row["v"])
        except (ValueError, TypeError) as exc:
            if key == "token":
                raise credential_storage.CredentialsCorruptError("token storage envelope is invalid") from exc
            return default
        if key == "token":
            if isinstance(value, dict) and _PROTECTED_TOKEN_FIELD not in value:
                self._forget_legacy_token(row["v"])
                return default
            return self._unprotect_token(value)
        return value

    def has(self, key: str) -> bool:
        """键存在、未过期，且值能解析（用于区分「缓存了 None」和「没有缓存」）。

        ``v`` 损坏（外部改库 / 断电截断）时必须算「不命中」：否则 ``_cached`` 会
        认为「缓存了一个 None」，producer 再也不执行，那个数据项永远返回 None。
        """
        if key == "token":
            missing = object()
            return self.get(key, missing) is not missing
        with self._conn() as c:
            row = c.execute("SELECT v, expire_at FROM kv WHERE k=?", (key,)).fetchone()
        if not row:
            return False
        if row["expire_at"] and row["expire_at"] < time.time():
            return False
        try:
            json.loads(row["v"])
        except Exception:
            return False
        return True

    def delete(self, key: str):
        with self._conn() as c:
            c.execute("DELETE FROM kv WHERE k=?", (key,))

    def clear_except(self, keep: str) -> int:
        """一条 SQL 清掉除 ``keep`` 之外的全部键，返回删除行数。

        原来的实现是 ``keys()`` + 逐键 ``delete()``，即 N+1 条连接（约 19 ms/条），
        在事件循环线程上 300 个键会卡 5.6 秒。
        """
        with self._conn() as c:
            cur = c.execute("DELETE FROM kv WHERE k != ?", (keep,))
            return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    def keys(self):
        with self._conn() as c:
            c.execute("DELETE FROM kv WHERE expire_at > 0 AND expire_at < ?", (time.time(),))
            return [r["k"] for r in c.execute("SELECT k FROM kv").fetchall()]
