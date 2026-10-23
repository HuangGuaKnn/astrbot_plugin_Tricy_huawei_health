# -*- coding: utf-8 -*-
"""华为运动健康 · 极简 SQLite 缓存（token + 数据快照）"""

import json
import os
import sqlite3
import time
from contextlib import contextmanager


class HealthStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
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
            # WAL 与 busy_timeout 让读写并发时少遇到 database is locked。
            conn.execute("PRAGMA busy_timeout=15000")
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
            # 显式提交，保持调用方原有的 with self._conn() as c 事务语义。
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init(self):
        with self._conn() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS kv ("
                "k TEXT PRIMARY KEY, v TEXT NOT NULL, expire_at REAL NOT NULL)"
            )
            # 启动时清掉已过期快照，避免换账号或长期运行后旧健康数据残留。
            c.execute("DELETE FROM kv WHERE expire_at > 0 AND expire_at < ?", (time.time(),))

    def set(self, key: str, value, ttl: int = 0):
        expire_at = (time.time() + ttl) if ttl else 0.0
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
            return json.loads(row["v"])
        except Exception:
            return default

    def delete(self, key: str):
        with self._conn() as c:
            c.execute("DELETE FROM kv WHERE k=?", (key,))

    def keys(self):
        with self._conn() as c:
            c.execute("DELETE FROM kv WHERE expire_at > 0 AND expire_at < ?", (time.time(),))
            return [r["k"] for r in c.execute("SELECT k FROM kv").fetchall()]
