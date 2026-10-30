# -*- coding: utf-8 -*-
"""astrbot_plugin_Tricy_huawei_health —— 把华为运动健康接进 AstrBot

数据源：health.cloud.huawei.com（华为运动健康网页端）
认证：注入浏览器 cookie → 自动走 OAuth（信任设备，无二次验证）→ accessToken
取数：纯 HTTP（不需要浏览器常开）

2026-10-22 实机验证通过的链路，见 hw_auth.py 顶部注释。

v0.4.1 修复（对应检测报告 P0-1 / P1-1 / P1-8 / P1-10 / P2-1 / P2-2 / P2-3 / P2-4 /
P2-5 / P2-6 / P2-7 / P2-13 / P2-14 / P3-1 / P3-2 / P3-3）：
    - 启动时不再用配置快照覆盖认证回写的滚续 cookie（只按配置指纹判重导入）；
    - 账号密码模式：额度语义改为「失败次数」、成功归还、失败可回退 cookie 路线；
    - ``_token`` 统一 ``compute_expire_at``，``_password_token`` 不再空等 420 秒；
    - 数据层引入 ``SchemaDrift``，把「接口改版」和「真的没数据」分开；
    - 体重「最新」不再等于均值、运动记录的距离/时长补上单位；
    - 配置/参数类型守卫，非数字不再把 TypeError 抛给用户。
"""

import asyncio
import datetime
import json
import os
import threading
import time

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register

try:  # 插件作为包加载
    from .hw_auth import HuaweiAuth, HuaweiAuthError, MIN_COOKIE_SPECS, compute_expire_at
    from .hw_client import (
        AuthExpired, ClientPool, HuaweiHealthClient, HuaweiHealthError, SchemaDrift, parse_timezone,
        format_distance_m, format_duration_ms, format_duration_s,
    )
    from .hw_store import HealthStore
    from .hw_login import HuaweiLoginManager, LoginFlowError
    from .hw_credentials import HuaweiCredentialsStore, harden_dir_permissions
    from .hw_privacy import redact_error
except ImportError:  # 插件目录在 sys.path 里
    from hw_auth import HuaweiAuth, HuaweiAuthError, MIN_COOKIE_SPECS, compute_expire_at
    from hw_client import (
        AuthExpired, ClientPool, HuaweiHealthClient, HuaweiHealthError, SchemaDrift, parse_timezone,
        format_distance_m, format_duration_ms, format_duration_s,
    )
    from hw_store import HealthStore
    from hw_login import HuaweiLoginManager, LoginFlowError
    from hw_credentials import HuaweiCredentialsStore, harden_dir_permissions
    from hw_privacy import redact_error

PLUGIN_NAME = "astrbot_plugin_Tricy_huawei_health"
DEFAULT_CLIENT_ID = "106533743"
DEFAULT_VERSION = "HealthKitRunningGroupPortal_6.26.4.200"
DEFAULT_TIMEZONE = "+0800"

# v0.3.1 对齐实际装饰器注册结果，health_overview 也属于可用工具。
TOOL_NAMES = [
    "health_status", "health_today", "health_sleep", "health_heart",
    "health_activities", "health_performance", "health_overview", "health_refresh",
]

#: AstrBot 会话 UMO 里合法的 MessageType（core/platform/message_type.py 只有这三个）。
VALID_MESSAGE_TYPES = {"FriendMessage", "GroupMessage", "OtherMessage"}
#: 权限配置在 _conf_schema.json 里的分组键。
PERMISSION_SECTION = "permission_settings"


def _data_dir() -> str:
    """插件数据目录（cookie / 数据库都放这儿）。"""
    try:
        from astrbot.core.utils.astrbot_path import get_astrbot_data_path

        base = get_astrbot_data_path()
    except Exception:
        base = os.path.join(os.path.expanduser("~"), ".astrbot", "data")
    path = os.path.join(base, "plugin_data", PLUGIN_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def _int_cfg(value, default: int, lo: int = None, hi: int = None) -> int:
    """配置/参数取值守卫：非数字不要变成裸 TypeError 抛给用户。"""
    try:
        out = int(value)
    except (TypeError, ValueError, OverflowError):
        out = default
    if lo is not None and out < lo:
        out = lo
    if hi is not None and out > hi:
        out = hi
    return out


class LoginNeedsHuman(HuaweiAuthError):
    """自动登录正等着用户在 WebUI 里输入验证码/账号密码/信任选择。

    单独一个类型，是因为这种「失败」**不该**被 cookie 回退盖掉——用户需要的是
    「去 WebUI 输验证码」，而不是「重新导出 cookie」。
    """


class StateChanged(HuaweiAuthError):
    """A result belongs to a session which the user has already replaced."""


class _PooledClient:
    def __init__(self, pool, token, **options):
        self.pool, self.token, self.options = pool, token, options

    def run(self, producer, deadline):
        return self.pool.run(self.token, producer, deadline=deadline, **self.options)


# 版本号与 metadata、WebUI 状态和 README 保持一致，便于升级后核对。
@register(
    PLUGIN_NAME,
    "HuangGuaKnn",
    "把华为运动健康（网页端）的睡眠 / 静息心率 / HRV / 训练数据接进 AstrBot",
    "v0.5.1",
)
class HuaweiHealthPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.config = config
        self.data_dir = _data_dir()
        self.cookie_file = os.path.join(self.data_dir, "hw_cookies.json")
        self.db_path = os.path.join(self.data_dir, "health.db")
        self.store = HealthStore(self.db_path)
        self.credentials = HuaweiCredentialsStore(self.data_dir)
        self._lock = asyncio.Lock()
        self._auth_change_lock = asyncio.Lock()
        self._state_lock = threading.RLock()
        self._auth_epoch = 0
        self._data_epoch = 0
        self._state_error = False
        self._closed = False
        self._client_pool = ClientPool(max_size=3)
        # 记录每个缓存键的进行中任务，避免并发请求重复打华为接口。
        self._cache_inflight = {}
        # 历史遗留：这里原本打算用 generation 拦截「刷新后旧请求回写」，但实际防线
        # 已经换成 (auth_epoch, data_epoch) 的 publish 复核（见 _cached）。这个字典
        # 目前只被 _clear_health_cache 自增、被 test_v041 断言，**没有任何读取点**
        # 参与放行/拒绝——保留字段本身只是为了不动 v0.4.1 验收基线。
        # 判断防线位置时看 epoch，不要看这里（见 AUDIT_concurrency.md 发现 9）。
        self._cache_generation = {}
        self._warmup_task = None
        self.login_manager = HuaweiLoginManager(self)
        # 允许用插件配置覆盖登录额度（默认 3 次/天，语义是「失败次数」）。
        # 走 set_daily_limit 而不是直接赋值：它会同步 login_config.json，
        # 否则配置页和磁盘会出现「3 / 10」这种不一致。
        limit = config.get("login_daily_limit")
        if limit is not None:
            try:
                self.login_manager.set_daily_limit(limit)
            except (TypeError, ValueError):
                pass
        # 权限白名单在 initialize() 里构建（含格式校验）；None 表示「尚未构建」。
        self._umo_whitelist = None
        self._invalid_umos = []
        self.logger = logger

    async def initialize(self):
        # 数据目录里有真实会话凭据，收紧 ACL（Windows）/ 0700（POSIX），失败不影响功能。
        try:
            reason = await asyncio.to_thread(harden_dir_permissions, self.data_dir)
            if reason:
                self.logger.warning("[华为健康] 收紧数据目录权限失败：%s" % redact_error(reason))
        except Exception as exc:
            self.logger.warning("[华为健康] 收紧数据目录权限失败：%s" % redact_error(exc))
        # 清掉崩溃残留的明文 cookie 临时文件。
        try:
            await asyncio.to_thread(self.auth.purge_stale_tmp)
        except Exception:
            pass
        # 配置同时兼容旧整段 JSON 和新分条值，避免升级后必须重新导出全部 cookie。
        raw = (self.config.get("cookie_json") or "").strip()
        fields = {
            name: self.config.get("cookie_" + name, "")
            for name, _, _ in MIN_COOKIE_SPECS
        }
        if raw or any(str(value or "").strip() for value in fields.values()):
            try:
                # only_if_changed：配置没变就什么都不做。否则每次插件启动都会用
                # 几天前的配置快照整份覆盖 hw_cookies.json，把认证回写的滚续结果
                # （含 OAuth 期间下发的 __uni__uid / JSESSIONID）冲掉。
                n = await asyncio.to_thread(
                    self._import_config_cookies, raw, fields)
                if n:
                    self.logger.info("[华为健康] 已从配置导入 %d 条 cookie（配置有变更）" % n)
                else:
                    self.logger.info("[华为健康] 配置里的 cookie 未变化，保留现有 cookie 文件")
            except Exception as exc:
                self.logger.warning("[华为健康] 配置里的 cookie 解析失败：%s" % redact_error(exc))
        # 会话白名单：格式非法的条目在这里就报错，WebUI 的 /status 也会回显。
        try:
            self._build_umo_whitelist()
        except Exception as exc:
            self.logger.warning("[华为健康] 会话白名单解析失败：%s" % redact_error(exc))
        self.logger.info("[华为健康] 插件已就绪，数据目录：%s" % self.data_dir)
        # 注册 WebUI 页面 API（页面在 pages/health_console/）
        try:
            try:
                from .hw_webapi import HuaweiHealthWebApi
            except ImportError:
                from hw_webapi import HuaweiHealthWebApi
            HuaweiHealthWebApi(self).register()
            self.logger.info("[华为健康] WebUI 页面 API 已注册")
        except Exception as exc:
            self.logger.warning("[华为健康] WebUI API 注册失败：%s" % redact_error(exc))
        # 后台预热 token：首次查询就不用等 30 多秒的浏览器启动
        if self.config.get("warmup", True):
            self._warmup_task = asyncio.create_task(self._warmup())

    async def _warmup(self):
        try:
            await asyncio.sleep(8)
            await self._token()
            self.logger.info("[华为健康] token 预热完成，后续查询可秒回")
        except Exception as exc:
            self.logger.warning("[华为健康] token 预热失败（不影响后续使用）：%s" % redact_error(exc))

    # ================= 内部：认证 / 客户端 =================

    @property
    def auth(self) -> HuaweiAuth:
        return HuaweiAuth(
            cookie_file=self.cookie_file,
            profile_dir=os.path.join(self.data_dir, "browser_profile"),
            browser_path=(self.config.get("browser_path") or "").strip(),
            headless=bool(self.config.get("headless", True)),
            page_timeout=_int_cfg(self.config.get("page_timeout"), 90, 1, 600),
            logger=self.logger,
            commit_lock=self._state_lock,
            is_current=lambda epoch=self._auth_epoch: (
                not self._closed and not self._state_error and epoch == self._auth_epoch),
        )

    async def _password_token(self) -> str:
        holder = {}
        cancelled = threading.Event()
        try:
            return await self._password_token_impl(holder, cancelled, self._auth_epoch)
        except asyncio.CancelledError:
            # start() may still be running in a worker. Its completion checks this flag.
            cancelled.set()
            session = holder.get("session")
            if session is not None:
                await asyncio.to_thread(session.cancel)
            raise

    async def _password_token_impl(self, holder, cancelled, epoch) -> str:
        """跑（或加入）唯一的加密凭据自动登录会话，拿到 token。

        v0.4.1 的两个关键变化：
          1. 需要人工介入（验证码 / 账号密码 / 信任选择）时**立刻返回**可行动的
             提示，不再占着插件锁空等 420 秒（AstrBot 的工具超时只有 120 秒）；
          2. 真正超时才 cancel 会话——v0.4.0 放弃后会话继续跑，下一次调用
             ``manager.start()`` 又拿到同一个非终态会话，再等 420 秒。
        """
        manager = self.login_manager

        def fail(message: str, code: str = "") -> HuaweiAuthError:
            exc = HuaweiAuthError(message)
            # 带上 code，_token() 才能决定「要不要回退 cookie」以及怎么拼提示。
            exc.code = code
            return exc

        def start_session():
            with self._state_lock:
                self._assert_current(epoch)
                if cancelled.is_set():
                    return
                manager.start("auto", manual=False)
                current = getattr(manager, "current_session", None)
                holder["session"] = current() if callable(current) else None
                if cancelled.is_set() and holder["session"] is not None:
                    holder["session"].cancel()
        try:
            await asyncio.to_thread(start_session)
        except LoginFlowError as exc:
            messages = {
                "credentials_missing": "尚未保存账号密码，请先在 WebUI 凭据区保存。",
                "credentials_corrupt": "账号密码凭据已损坏，请在 WebUI 重新保存。",
                "credentials_locked": "账号密码凭据已锁定，请检查文件权限和原主密钥。",
                "credentials_unavailable": "安全凭据存储不可用，请配置外部主密钥或检查系统加密服务。",
                "daily_limit": "今日自动登录失败次数已达上限，请稍后再试。",
                "cooldown": "自动登录失败冷却中，请稍后再试。",
            }
            raise fail(messages.get(exc.code, "自动登录无法启动，请查看 WebUI 登录状态。"),
                       exc.code) from exc

        # 一次工具调用最多等这么久；再长就会撞上 AstrBot 的 120 秒工具超时。
        timeout = _int_cfg(manager.session_timeout, 300, 60, 1800)
        deadline = time.monotonic() + min(100, max(60, timeout))
        state = "IDLE"
        while time.monotonic() < deadline:
            self._assert_current(epoch)
            session = holder.get("session")
            status = session.snapshot() if session is not None else manager.status()
            state = status.get("state") or "IDLE"
            if state == "DONE":
                cached = self.store.get("token") or {}
                token = cached.get("token")
                if token:
                    return token
                raise fail("自动登录完成但未拿到有效 token。", "no_token")
            if state == "FAILED":
                raise fail(
                    "自动登录失败：%s" % (status.get("message") or "请查看 WebUI 登录状态"),
                    "session_failed")
            if state in ("NEED_SMS", "NEED_CRED", "NEED_TRUST"):
                break
            await asyncio.sleep(0.5)
        else:
            # 等满也没结果：真正超时，把会话收掉，别让它继续占着浏览器和额度。
            try:
                session = holder.get("session")
                await asyncio.to_thread(session.cancel if session is not None else manager.cancel)
            except Exception:
                pass
            raise fail("自动登录等待超时，已取消本次会话，请重新开始。", "timeout")

        hint = {
            "NEED_SMS": "手机验证码",
            "NEED_CRED": "账号密码",
            "NEED_TRUST": "是否信任此浏览器",
        }.get(state, "登录")
        raise LoginNeedsHuman(
            "自动登录需要你输入%s。请打开 WebUI 控制台的「账号登录」区完成，"
            "完成后再问一次即可（会话会保留 5 分钟）。" % hint)

    def _assert_current(self, epoch, data_epoch=None):
        if self._closed:
            raise StateChanged("插件已停用，请重新启用后查询。")
        if self._state_error:
            raise StateChanged("登录状态更新未完成，请在控制台重新刷新或导入凭据。")
        if epoch != self._auth_epoch or (data_epoch is not None and data_epoch != self._data_epoch):
            raise StateChanged("登录状态或缓存已更新，旧查询已作废，请重新查询。")

    def _load_token(self, epoch):
        with self._state_lock:
            self._assert_current(epoch)
            return self.store.get("token") or {}

    async def _fetch_auth(self, auth):
        try:
            return await asyncio.to_thread(auth.fetch_token)
        except asyncio.CancelledError:
            # to_thread cannot stop its worker; prevent that instance committing later.
            cancel = getattr(auth, "cancel", None)
            if callable(cancel):
                cancel()
            raise

    async def _token(self, force: bool = False, stale_token: str = "") -> str:
        epoch = self._auth_epoch
        if not force:
            cached = await asyncio.to_thread(self._load_token, epoch)
            self._assert_current(epoch)
            if cached.get("token") and cached.get("expire_at", 0) > time.time():
                return cached["token"]
        async with self._lock:
            cached = await asyncio.to_thread(self._load_token, epoch)
            self._assert_current(epoch)
            if cached.get("token") and cached.get("expire_at", 0) > time.time():
                if not force or (stale_token and cached["token"] != stale_token):
                    return cached["token"]
            ttl = _int_cfg(self.config.get("token_ttl"), 3000, 0, 86400)
            mode = getattr(getattr(self, "login_manager", None), "login_mode", "cookie")
            auth = self.auth
            manager = getattr(self, "login_manager", None)
            session = manager.current_session() if manager and callable(getattr(manager, "current_session", None)) else None
            if mode != "password" and session and session.is_running() and session.snapshot()["state"] not in ("DONE", "FAILED"):
                raise LoginNeedsHuman("网页登录正在进行，请在控制台完成或取消后再查询。")
            if mode == "password":
                try:
                    token = await self._password_token()
                except (LoginNeedsHuman, StateChanged):
                    raise
                except HuaweiAuthError as exc:
                    self._assert_current(epoch)
                    if not os.path.exists(self.cookie_file):
                        raise
                    self.logger.warning("[华为健康] 账号密码登录不可用（%s），退回 cookie 路线" % redact_error(exc))
                    auth = self.auth
                    try:
                        token = await self._fetch_auth(auth)
                    except Exception as fallback_exc:
                        raise HuaweiAuthError("%s；另外 cookie 路线也不可用：%s" % (exc, fallback_exc)) from fallback_exc
            else:
                token = await self._fetch_auth(auth)

            def commit():
                with self._state_lock:
                    self._assert_current(epoch)
                    stored = self.store.get("token") or {}
                    if mode == "password" and stored.get("token") == token and stored.get("expire_at"):
                        expire_at = float(stored["expire_at"])
                    else:
                        expire_at = compute_expire_at(getattr(auth, "token_expire_at", 0.0), ttl)
                    self.store.set("token", {"token": token, "expire_at": expire_at,
                                             "obtained_at": time.strftime("%Y-%m-%d %H:%M:%S")})
            await asyncio.to_thread(commit)
            self._assert_current(epoch)
            return token

    async def _client(self, force: bool = False, stale_token: str = ""):
        token = await self._token(force=force, stale_token=stale_token)
        return _PooledClient(
            self._client_pool, token,
            client_id=(self.config.get("client_id") or DEFAULT_CLIENT_ID).strip(),
            version=(self.config.get("api_version") or DEFAULT_VERSION).strip(),
            timezone=(self.config.get("timezone") or DEFAULT_TIMEZONE).strip(),
        )

    QUERY_TIMEOUT = 90

    async def _cached(self, key: str, producer, ttl: int = None, force: bool = False, deadline=None):
        """Share work only within the current account/cache generation."""
        epoch, data_epoch = self._auth_epoch, self._data_epoch
        self._assert_current(epoch, data_epoch)
        enabled = _int_cfg(self.config.get("data_ttl"), 600, 0, 86400) > 0
        ttl = _int_cfg(self.config.get("data_ttl"), 600, 0, 86400) if ttl is None else ttl
        if not enabled:
            ttl = 0
        deadline = time.monotonic() + self.QUERY_TIMEOUT if deadline is None else deadline

        def lookup():
            with self._state_lock:
                self._assert_current(epoch, data_epoch)
                missing = object()
                value = self.store.get(key, missing)
                return value is not missing, value

        if enabled and not force:
            async with asyncio.timeout(max(0, deadline - time.monotonic())):
                found, hit = await asyncio.to_thread(lookup)
            if time.monotonic() >= deadline:
                raise TimeoutError("取数超时，请稍后重试")
            self._assert_current(epoch, data_epoch)
            if found:
                return hit
        flight_key = (epoch, data_epoch, key)
        task = self._cache_inflight.get(flight_key)
        if task is None or task.done():
            async def produce():
                used_token = ""
                async def run(force_auth=False):
                    nonlocal used_token
                    self._assert_current(epoch, data_epoch)
                    client = await self._client(force=force_auth, stale_token=used_token if force_auth else "")
                    self._assert_current(epoch, data_epoch)
                    used_token = client.token
                    if isinstance(client, _PooledClient):
                        return await asyncio.to_thread(client.run, producer, deadline)
                    # Also supports injected clients used by offline contract tests.
                    return await asyncio.to_thread(producer, client)
                try:
                    async with asyncio.timeout(max(0, deadline - time.monotonic())):
                        try:
                            result = await run()
                        except AuthExpired:
                            self.logger.warning("[华为健康] token 失效，重新认证…")
                            result = await run(True)
                        def publish():
                            with self._state_lock:
                                self._assert_current(epoch, data_epoch)
                                if time.monotonic() >= deadline:
                                    raise TimeoutError("取数超时，请稍后重试")
                                if ttl > 0:
                                    self.store.set(key, result, ttl=ttl)
                        await asyncio.to_thread(publish)
                        self._assert_current(epoch, data_epoch)
                        return result
                finally:
                    if self._cache_inflight.get(flight_key) is asyncio.current_task():
                        self._cache_inflight.pop(flight_key, None)
            task = asyncio.create_task(produce())
            self._cache_inflight[flight_key] = task
            # A timed-out caller may leave the shared task running for another caller.
            task.add_done_callback(lambda done: None if done.cancelled() else done.exception())
        async with asyncio.timeout(max(0, deadline - time.monotonic())):
            result = await asyncio.shield(task)
        self._assert_current(epoch, data_epoch)
        return result

    def _clear_health_cache(self, strict: bool = False):
        with self._state_lock:
            self._data_epoch += 1
            for key in set(self._cache_generation):
                self._cache_generation[key] += 1
            try:
                self.store.clear_except("token")
            except Exception as exc:
                self.logger.warning("[华为健康] 清理健康缓存失败：%s" % redact_error(exc))
                if strict:
                    raise HuaweiHealthError("健康缓存清理失败（%s），请重试" % redact_error(exc)) from exc

    def _clear_auth_cache_blocking(self):
        with self._state_lock:
            self._auth_epoch += 1
            self._state_error = True
            manager = getattr(self, "login_manager", None)
            if manager and callable(getattr(manager, "invalidate", None)):
                manager.invalidate()
            self._client_pool.invalidate()
            self.store.delete("token")
            self._clear_health_cache(strict=True)
            self._state_error = False

    def _change_auth_state_blocking(self, mutator=None, clear_cookies=False,
                                    keep_blocked=False):
        with self._state_lock:
            if self._closed:
                raise StateChanged("插件已停用，请重新启用后修改登录状态。")
            self._clear_auth_cache_blocking()
            self._state_error = True
            try:
                # Validate and persist new credentials before discarding the old
                # cookie file. Wrong/missing keys must preserve recoverable data.
                result = mutator() if mutator else None
                if clear_cookies:
                    self.auth.clear_cookies()
            except Exception:
                # No query may use partially updated credentials after a failed change.
                raise
            else:
                self._state_error = keep_blocked
                return result

    async def _change_auth_state(self, mutator=None, clear_cookies=False):
        return await self._change_auth_state_async(mutator, clear_cookies=clear_cookies)

    async def _change_auth_state_async(self, mutator=None, finalize=None,
                                       clear_cookies=False, check_current=None):
        """Serialize credential changes through asynchronous configuration persistence.

        Queries remain blocked until both the encrypted write and the optional
        async finalizer succeed. Never hold the thread lock across an await.
        """
        async with self._auth_change_lock:
            def begin():
                with self._state_lock:
                    if check_current is not None:
                        check_current()
                    result = self._change_auth_state_blocking(
                        mutator, clear_cookies, keep_blocked=finalize is not None)
                    return result, self._auth_epoch

            worker = asyncio.create_task(asyncio.to_thread(begin))
            try:
                result, epoch = await asyncio.shield(worker)
            except asyncio.CancelledError:
                # to_thread keeps running after request cancellation. Keep the
                # mutation lock until it exits, and leave the state blocked.
                while not worker.done():
                    try:
                        await asyncio.shield(worker)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                if not worker.cancelled():
                    worker.exception()
                with self._state_lock:
                    self._state_error = True
                raise
            if finalize is not None:
                await finalize(result)
            with self._state_lock:
                if self._closed or epoch != self._auth_epoch:
                    raise StateChanged("登录状态已更新，本次修改未完成，请刷新后重试。")
                self._state_error = False
            return result

    async def _invalidate_auth_cache(self):
        await self._change_auth_state()

    def _import_config_cookies(self, raw, fields):
        with self._state_lock:
            auth = self.auth
            n = auth.import_cookie_sources(raw, fields, True, replace_existing=True)
            if n:
                try:
                    self._clear_auth_cache_blocking()
                except Exception:
                    # Retry invalidation on the next startup even if import already succeeded.
                    try:
                        os.unlink(auth._marker_path())
                    except OSError:
                        pass
                    raise
            return n

    def _commit_login_result(self, session, cookies, token, expire_at):
        with self._state_lock:
            manager = self.login_manager
            if manager.current_session() is not session:
                return False
            with session._lock:
                if (self._closed or self._state_error or session._cancel.is_set()
                        or session._auth_epoch != self._auth_epoch):
                    return False
                # Cookie, token and health snapshots share the same account transition lock.
                self.store.delete("token")
                self.store.clear_except("token")
                # 这里的账号切换同样是一次「数据代际」变更：在飞的旧账号查询会在
                # publish 时用 (auth_epoch, data_epoch) 复核，不推进代际就会被放行，
                # 把上一个账号的健康数据写进新账号的缓存（最长 data_ttl）。
                self._data_epoch += 1
                self._client_pool.invalidate()
                if not session._auth.save_cookies(cookies):
                    return False
                self.store.set("token", {"token": token, "expire_at": expire_at,
                                         "obtained_at": time.strftime("%Y-%m-%d %H:%M:%S")})
                return True

    @staticmethod
    def _err(exc: Exception) -> str:
        # 异常原文可能带 cookie / accessToken / 本机路径（浏览器启动失败时
        # OSError 里就有 profile 的绝对路径），统一洗过再交给用户和 LLM。
        if isinstance(exc, TimeoutError):
            return "取数超时，请稍后重试；已经完成的数据不受影响。"
        reason = redact_error(exc)
        if isinstance(exc, HuaweiAuthError):
            return "拿不到登录态：%s" % reason
        if isinstance(exc, AuthExpired):
            return "登录态失效了，请重新导入 cookie。"
        if isinstance(exc, SchemaDrift):
            return ("华为接口结构变了（%s）。这通常意味着华为网页端改版，请升级插件。" % reason)
        if isinstance(exc, HuaweiHealthError):
            return "华为接口报错：%s" % reason
        return "出错了：%s: %s" % (type(exc).__name__, reason)

    # ================= 内部：格式化 =================

    @staticmethod
    def _stat_line(stats: dict, count_label: str = "条") -> str:
        if not stats:
            return "无数据"
        parts = []
        for k, label in (("avg", "均"), ("min", "最低"), ("max", "最高")):
            if stats.get(k) is not None:
                parts.append("%s%s" % (label, stats[k]))
        if stats.get("count") is not None:
            parts.append("%s %s" % (stats["count"], count_label))
        return " / ".join(parts) if parts else "无数据"

    @staticmethod
    def _daily_has_value(daily: list) -> bool:
        """按天明细里到底有没有真数值（HRV 那种只回 count 的就没有）。"""
        for item in daily or []:
            for field, stats in item.items():
                if field == "day" or not isinstance(stats, dict):
                    continue
                if stats.get("avg") is not None or stats.get("max") is not None:
                    return True
        return False

    def _metric_text(self, parsed: dict, unit: str, days: int, name: str,
                     count_label: str = "条") -> str:
        overall = parsed.get("overall") or {}
        daily = parsed.get("daily") or []
        if not overall and not daily:
            return "最近 %d 天没有 %s 数据（可能没戴表 / 没同步）。" % (days, name)
        lines = []
        for field, stats in overall.items():
            lines.append("%s %s：%s" % (name, field, self._stat_line(stats, count_label)))
        if daily and self._daily_has_value(daily):
            lines.append("按天：")
            for item in daily:
                day = item.get("day")
                vals = []
                for field, stats in item.items():
                    if field == "day" or not isinstance(stats, dict):
                        continue
                    if stats.get("avg") is not None:
                        vals.append("%s" % stats["avg"])
                    elif stats.get("max") is not None:
                        vals.append("%s" % stats["max"])
                lines.append("  %s  %s %s" % (day, " / ".join(vals) if vals else "-", unit))
        elif daily:
            lines.append("（云端只回了记录条数，没有逐日数值）")
        return "\n".join(lines)

    @staticmethod
    def _is_nap(rec: dict) -> bool:
        """华为云端会把「零星小睡」也塞进睡眠记录，用类型 / 时长判一下。"""
        def v(*keys):
            for item in (rec.get("value") or []):
                if item.get("fieldName") in keys:
                    for k in ("floatValue", "integerValue", "longValue", "doubleValue"):
                        if item.get(k) is not None:
                            return item[k]
            return None
        stype = v("sleep_type", "sleepType")
        if stype is not None and stype != 1:
            return True
        total = v("all_sleep_time", "allSleepTime")
        return total is not None and total < 180

    @classmethod
    def _sleep_text(cls, records: list, days: int, night_only: bool = False,
                    timezone: str = DEFAULT_TIMEZONE, limit: int = None) -> str:
        if night_only:
            records = [r for r in records if not cls._is_nap(r)]
        if not records:
            return "最近 %d 天没有睡眠记录（可能没戴表）。" % days
        def record_time(rec):
            try:
                return int(rec.get("startTime") or 0)
            except (TypeError, ValueError):
                return 0
        records = sorted(records, key=record_time)
        total_records = len(records)
        if limit is not None:
            records = records[-max(1, limit):]
        tz = parse_timezone(timezone)
        lines = []
        for rec in records:
            def val(*keys):
                for item in (rec.get("value") or []):
                    if item.get("fieldName") in keys:
                        for k in ("floatValue", "integerValue", "longValue", "doubleValue"):
                            if item.get(k) is not None:
                                return item[k]
                return None

            start = rec.get("startTime")
            end = rec.get("endTime")
            try:
                day = datetime.datetime.fromtimestamp(int(start) / 1e9, tz).strftime("%m-%d")
            except Exception:
                day = "?"
            span = ""
            try:
                if start and end:
                    t0 = datetime.datetime.fromtimestamp(int(start) / 1e9, tz)
                    t1 = datetime.datetime.fromtimestamp(int(end) / 1e9, tz)
                    span = " %s→%s" % (t0.strftime("%H:%M"), t1.strftime("%H:%M"))
            except Exception:
                span = ""
            total = val("all_sleep_time", "allSleepTime")
            score = val("sleep_score", "sleepScore")
            deep = val("deep_sleep_time", "deepSleepTime")
            light = val("light_sleep_time", "lightSleepTime")
            dream = val("dream_time", "dreamTime")
            awake = val("awake_time", "awakeTime")
            latency = val("sleep_latency", "sleepLatency")
            wakeup = val("wakeup_count", "wakeupCount")
            bits = []
            if total:
                bits.append("总睡 %s 分" % total)
            if score:
                bits.append("得分 %s" % score)
            if deep is not None or light is not None or dream is not None:
                bits.append("深 %s / 浅 %s / REM %s" % (
                    "-" if deep is None else deep,
                    "-" if light is None else light,
                    "-" if dream is None else dream))
            if awake is not None:
                bits.append("清醒 %s 分" % awake)
            if latency is not None:
                bits.append("入睡用 %s 分" % latency)
            if wakeup is not None:
                bits.append("夜醒 %s 次" % wakeup)
            tag = "（小睡）" if cls._is_nap(rec) else ""
            lines.append("  %s%s%s  %s" % (
                day, tag, span, "，".join(bits) if bits else "有记录但字段未识别"))
        notice = "（共 %d 条，显示最近 %d 条）" % (total_records, len(records)) if total_records > len(records) else ""
        return "最近睡眠%s：\n" % notice + "\n".join(lines)

    # ---------- 其它数据项的格式化 ----------

    @staticmethod
    def _fmt_duration(sec) -> str:
        return format_duration_s(sec)

    @classmethod
    def _fmt_perf(cls, d: dict) -> str:
        if not d:
            return "没有运动能力评估数据"
        pt = d.get("predictedTimes") or {}
        try:
            rank = round(float(d.get("ranking") or 0), 1)
        except (TypeError, ValueError):
            rank = "-"
        return "\n".join([
            "跑力指数 %s ｜ 排名超过 %s%% 的跑者" % (d.get("runningAbility", "-"), rank),
            "状态 %s ｜ 体能 %s ｜ 疲劳 %s" % (
                d.get("condition", "-"), d.get("fitness", "-"), d.get("fatigue", "-")),
            "预测成绩：1km %s ｜ 3km %s ｜ 5km %s ｜ 10km %s" % (
                cls._fmt_duration(pt.get("km1")), cls._fmt_duration(pt.get("km3")),
                cls._fmt_duration(pt.get("km5")), cls._fmt_duration(pt.get("km10"))),
            "　　　　　半马 %s ｜ 全马 %s" % (
                cls._fmt_duration(pt.get("halfMarathon")), cls._fmt_duration(pt.get("marathon"))),
        ])

    @staticmethod
    def _fmt_pb(d: dict) -> str:
        names = {
            "bestRunDistance": "最长跑步距离",
            "bestRunPartTime5KM": "5 公里最快",
            "bestRunPartTime3KM": "3 公里最快",
            "bestRunPace": "最佳配速",
            "accumulatedRunDistance": "累计跑量",
        }

        def fmt(name: str, v):
            if v is None:
                return "-"
            if "Distance" in name:
                try:
                    return "%.2f 公里" % (float(v) / 1000.0)
                except (TypeError, ValueError):
                    return str(v)
            if "Pace" in name:
                try:
                    m, s = divmod(int(v), 60)
                    return "%d'%02d''" % (m, s)
                except (TypeError, ValueError):
                    return str(v)
            if "Time" in name:
                try:
                    m, s = divmod(int(v), 60)
                    return "%d 分 %02d 秒" % (m, s)
                except (TypeError, ValueError):
                    return str(v)
            return str(v)

        lines = []
        for rep in (d.get("sportReports") or []):
            for item in (rep.get("personalBest") or []):
                n = str(item.get("name"))
                lines.append("  %s：%s" % (names.get(n, n), fmt(n, item.get("value"))))
            for item in (rep.get("accumulate") or []):
                n = str(item.get("name"))
                lines.append("  %s：%s" % (names.get(n, n), fmt(n, item.get("value"))))
        if not lines:
            return "没有个人纪录"
        return "个人纪录：\n" + "\n".join(lines)

    @staticmethod
    def _fmt_zones(z: dict) -> str:
        if not z:
            return "没有心率区间配置"
        order = [
            ("anaerobic_advance", "无氧进阶"), ("anaerobic", "无氧耐力"), ("anaerobic_base", "无氧基础"),
            ("lactic_acid", "乳酸阈值"), ("aerobic_advance", "有氧进阶"), ("aerobic", "有氧耐力"),
            ("aerobic_base", "有氧基础"), ("fat_burn", "燃脂"), ("warm_up", "热身"),
        ]
        lines = ["静息 %s ｜ 最大 %s bpm" % (z.get("rest", "-"), z.get("max", "-"))]
        for key, name in order:
            if z.get(key) is not None:
                lines.append("  %s ≥ %s bpm" % (name, z[key]))
        return "\n".join(lines)

    @staticmethod
    def _fmt_weight(parsed: dict) -> str:
        """体重概览。

        v0.4.1：不再读 ``statistics["last"]``——``STRATEGY`` 里从来没有 ``LAST``，
        服务端不会返回这个字段，v0.4.0 的「最新」其实一直是区间均值。
        现在用「按天明细的最后一天」作为最近一天的值；**只有那一天真的有这个字段**
        才标「最近一天（日期）」，否则老老实实写「均」。
        """
        overall = parsed.get("overall") or {}
        daily = parsed.get("daily") or []
        if not overall and not daily:
            return "没有体重记录"
        last = daily[-1] if daily else {}
        lines = []
        for field, st in overall.items():
            latest = st.get("avg")
            label = "均"
            day_stats = last.get(field) if isinstance(last, dict) else None
            if isinstance(day_stats, dict) and (day_stats.get("avg") is not None
                                                or day_stats.get("max") is not None):
                latest = day_stats.get("avg", day_stats.get("max"))
                if last.get("day"):
                    label = "最近一天（%s）" % last["day"]
            lines.append("%s：%s %s kg ｜ 均 %s ｜ 共 %s 条" % (
                field, label, latest, st.get("avg"), st.get("count")))
        # 日明细只打印 overall 里出现过的字段，避免把桶里别的指标当体重
        for item in daily[-5:]:
            day = item.get("day")
            for field in overall:
                st = item.get(field)
                if isinstance(st, dict):
                    lines.append("  %s  %s kg" % (day, st.get("avg", st.get("max", "-"))))
                    break
        return "\n".join(lines)

    @classmethod
    def _fmt_acts(cls, acts: list, days: int = 30, limit: int = 5, timezone: str = DEFAULT_TIMEZONE) -> str:
        """运动记录列表（距离按米、时长按毫秒换算后带单位输出）。"""
        if not acts:
            return "最近 %d 天没有运动记录" % days
        lines = ["最近 %d 天共 %d 条：" % (days, len(acts))]
        for a in acts[:limit]:
            def v(*ks):
                for k in ks:
                    if a.get(k) is not None:
                        return a[k]
                return None
            when = ""
            ts = v("endTime", "startTime")
            try:
                ms = int(ts)
                ms = ms / 1e6 if ms > 1e13 else ms
                when = datetime.datetime.fromtimestamp(ms / 1000, parse_timezone(timezone)).strftime("%m-%d %H:%M")
            except Exception:
                when = str(ts)
            bits = [when]
            if v("activityType") is not None:
                bits.append("类型%s" % v("activityType"))
            if v("distance"):
                bits.append("距离%s" % format_distance_m(v("distance")))
            if v("duration"):
                bits.append("时长%s" % format_duration_ms(v("duration")))
            if v("avgHeartRate", "averageHeartRate"):
                bits.append("均心率%s" % v("avgHeartRate", "averageHeartRate"))
            lines.append("  " + " ｜ ".join(str(b) for b in bits if b))
        return "\n".join(lines)

    # ================= 内部：总览 =================

    #: 总览的 9 项数据（key, 标题, 缓存秒数）。LLM 工具与 WebUI 共用这一份定义。
    OVERVIEW_ITEMS = (
        ("heart", "静息心率（近 7 天）", 600),
        ("sleep", "睡眠（近 7 晚）", 600),
        ("hrv", "睡眠 HRV", 600),
        ("stress", "压力（近 7 天）", 600),
        ("weight", "体重", 600),
        ("zones", "心率区间", 600),
        ("perf", "运动能力与预测成绩", 3600),
        ("pb", "个人纪录", 3600),
        ("acts", "近期运动", 600),
    )
    #: 总览的整体预算。单次 HTTP 最坏 95 秒、并发上限 3 → 3 轮最坏 285 秒，
    #: 远超 AstrBot 的 120 秒工具超时，所以这里必须自己兜一个上限。
    OVERVIEW_TIMEOUT = 90

    def _timezone(self):
        return (self.config.get("timezone") or DEFAULT_TIMEZONE).strip()

    def _query_key(self, key):
        # Changing timezone, API interpretation or calendar day must not reuse an old window.
        tz = parse_timezone(self._timezone())
        now = datetime.datetime.now(tz)
        return json.dumps([key, now.strftime("%z"), now.strftime("%Y-%m-%d"),
                           self.config.get("client_id") or DEFAULT_CLIENT_ID,
                           self.config.get("api_version") or DEFAULT_VERSION], separators=(",", ":"))

    async def _query(self, key, producer, ttl=None, deadline=None):
        return await self._cached(self._query_key(key), producer, ttl=ttl, deadline=deadline)

    def _overview_specs(self):
        tz = self._timezone()
        return {
            "heart": ("hr:7", lambda c: c.resting_heart_rate(7),
                      lambda d: self._metric_text(d, "bpm", 7, "静息心率", count_label="天")),
            "sleep": ("sleep:7", lambda c: c.sleep_records(7),
                      lambda d: self._sleep_text(d, 7, timezone=tz)),
            "hrv": ("hrv:7", lambda c: c.hrv_stats(7), lambda d: self._metric_text(d, "", 7, "HRV")),
            "stress": ("stress:7", lambda c: c.stress_stats(7), lambda d: self._metric_text(d, "", 7, "压力")),
            "weight": ("weight:1095", lambda c: c.body_weight(1095), self._fmt_weight),
            "zones": ("zones", lambda c: c.heart_rate_zones(), self._fmt_zones),
            "perf": ("perf", lambda c: c.athletic_performance(), self._fmt_perf),
            "pb": ("pb", lambda c: c.personal_bests("running"), self._fmt_pb),
            "acts": ("act:30:5", lambda c: c.activities(30, 5),
                     lambda d: self._fmt_acts(d, 30, 5, timezone=tz)),
        }

    async def _run_items(self, specs, timeout=None):
        """All composite tools share one deadline and retain successful sections."""
        timeout = self.QUERY_TIMEOUT if timeout is None else timeout
        deadline = time.monotonic() + timeout
        epoch, data_epoch = self._auth_epoch, self._data_epoch
        sem = asyncio.Semaphore(3)

        async def one(key, title, producer, formatter, ttl):
            async with sem:
                try:
                    raw = await self._query(key, producer, ttl=ttl, deadline=deadline)
                    return {"key": key, "title": title, "ok": True, "text": formatter(raw)}
                except Exception as exc:
                    return {"key": key, "title": title, "ok": False, "text": self._err(exc)}

        tasks = [asyncio.create_task(one(*spec)) for spec in specs]
        try:
            done, _ = await asyncio.wait(tasks, timeout=max(0, deadline - time.monotonic()))
            results = []
            for spec, task in zip(specs, tasks):
                if task in done:
                    results.append(task.result())
                else:
                    results.append({"key": spec[0], "title": spec[1], "ok": False,
                                    "text": "取数超时（超过 %s 秒），请稍后重试" % timeout})
            self._assert_current(epoch, data_epoch)
            return results
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _overview_items(self, timeout=None):
        producers = self._overview_specs()
        specs = []
        for key, title, ttl in self.OVERVIEW_ITEMS:
            cache_key, producer, formatter = producers[key]
            specs.append((cache_key, title, producer, formatter, ttl))
        items = await self._run_items(specs, self.OVERVIEW_TIMEOUT if timeout is None else timeout)
        for item, (key, _, _) in zip(items, self.OVERVIEW_ITEMS):
            item["key"] = key
        return items

    @staticmethod
    def _items_text(items):
        return "\n\n".join("【%s】\n%s" % (i["title"], i["text"]) for i in items)

    # ================= 权限（会话准入 + 成员准入）=================
    #
    # 两层正交，顺序不能换：
    #   成员维度（admin_only）是硬门，任何会话白名单都救不了它；
    #   会话维度（allow_private / allow_group）才允许被 UMO 白名单覆盖。
    # 「把某个群加进白名单」只表示允许这个群，**不等于**允许群里每个人。

    def _permission_config(self) -> dict:
        """实时读权限分组（不缓存成模块级常量：热路径可能再次用到配置）。"""
        raw = self.config.get(PERMISSION_SECTION)
        return raw if isinstance(raw, dict) else {}

    def _cfg_bool(self, key: str, default: bool) -> bool:
        """配置布尔取值：容忍字符串/数字写法，非法值退回默认。"""
        value = self._permission_config().get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            text = value.strip().lower()
            if text in ("true", "1", "yes", "on"):
                return True
            if text in ("false", "0", "no", "off"):
                return False
        return default

    def _parse_umos(self, raw_items):
        """拆分合法/非法 UMO。非法项不生效（fail-closed），但不影响其它合法项。"""
        valid, invalid = [], []
        for raw in raw_items or []:
            s = str(raw).strip()
            if not s:
                continue
            # session_id 本身可能含冒号，所以只切两刀。
            parts = s.split(":", 2)
            if len(parts) == 3 and parts[0] and parts[2] and parts[1] in VALID_MESSAGE_TYPES:
                valid.append(s)
            else:
                invalid.append(s)
        return valid, invalid

    def _build_umo_whitelist(self):
        raw = self._permission_config().get("extra_umo_whitelist") or []
        if isinstance(raw, str):
            raw = [raw]
        try:
            items = list(raw)
        except TypeError:
            items = []
        valid, invalid = self._parse_umos(items)
        self._umo_whitelist = set(valid)
        self._invalid_umos = invalid
        if invalid:
            self.logger.error("[华为健康] 以下会话 UMO 格式不合法，已忽略：%s", invalid)
        if valid:
            self.logger.info("[华为健康] 会话白名单已加载 %d 项" % len(valid))
        return valid, invalid

    def _whitelist(self) -> set:
        if self._umo_whitelist is None:
            self._build_umo_whitelist()
        return self._umo_whitelist or set()

    def _is_allowed(self, event) -> bool:
        """fail-closed：任何异常都按拒绝处理。"""
        try:
            if event is None:
                # fail-closed：与 AstrBot 自身的取向一致——框架在
                # event is None 时同样直接判「无权限」（见
                # core/provider/func_tool_manager.py 的 admin 工具守卫）。
                # 拿不到事件上下文就说明无法证明调用方有权，一律拒绝。
                return False
            # —— 成员维度：硬门，白名单救不了 ——
            if self._cfg_bool("admin_only", True) and not event.is_admin():
                return False
            # —— 会话维度：白名单可以覆盖下面两个开关 ——
            umo = (getattr(event, "unified_msg_origin", "") or "").strip()
            if umo and umo in self._whitelist():
                return True
            if event.is_private_chat():
                return self._cfg_bool("allow_private", True)
            return self._cfg_bool("allow_group", False)
        except Exception:
            return False

    def _deny_reason(self, event) -> str:
        """拒绝原因：not_admin（成员维度）或 session_not_allowed（会话维度）。"""
        try:
            if self._cfg_bool("admin_only", True):
                is_admin = getattr(event, "is_admin", None)
                if not (callable(is_admin) and is_admin()):
                    return "not_admin"
        except Exception:
            return "not_admin"
        return "session_not_allowed"

    def _deny_text(self, event) -> str:
        """拒绝文案必须是「终局」：本设计不做前置注入，tool result 是唯一能让模型停下的地方。"""
        if self._deny_reason(event) == "not_admin":
            return ("（该功能当前不可用：本会话仅限 AstrBot 管理员使用健康数据。"
                    "请勿再次调用本工具，直接告知用户「该会话中健康数据仅管理员可查」。）")
        return ("（该功能当前不可用：本会话未获授权使用健康数据。"
                "请勿再次调用本工具，直接告知用户「健康数据查询需在私聊中进行」。）")

    def _event_umo(self, event) -> str:
        return (getattr(event, "unified_msg_origin", "") or "") if event is not None else ""

    def _event_sender(self, event) -> str:
        try:
            getter = getattr(event, "get_sender_id", None)
            return getter() if callable(getter) else ""
        except Exception:
            return ""

    @filter.on_llm_request()
    async def _gate_health_tools(self, event, req):
        """第一层：不放行就把 8 个工具从本次请求的工具集里摘掉。

        省 token，也让模型不会徒劳地试。``req.func_tool`` 是每请求新建的
        ``ToolSet`` 副本（``func_tool_manager.get_full_tool_set()`` 每次构造新
        对象，``astr_main_agent`` 里赋给 ``req.func_tool``），所以
        ``remove_tool()`` 不会污染全局工具表。
        """
        if req.func_tool is None:  # cron / 后台任务路径下可能是 None
            return
        try:
            allowed = self._is_allowed(event)
        except Exception:
            allowed = False
        if allowed:
            return
        for name in TOOL_NAMES:
            try:
                req.func_tool.remove_tool(name)
            except Exception:
                pass
        try:
            self.logger.debug(
                "[华为健康] 已对本会话隐藏健康工具：umo=%s sender=%s reason=%s",
                self._event_umo(event), self._event_sender(event),
                self._deny_reason(event),
            )
        except Exception:
            pass

    # ================= LLM 工具 =================

    @filter.llm_tool(name="health_status")
    async def health_status(self, event: AstrMessageEvent):
        """检查华为运动健康数据通道的状态：用哪种登录方式、凭据/cookie 齐不齐、token 还能用多久。

        用户问「健康数据通道通不通」「健康数据还能用吗」时用这个。
        """
        if not self._is_allowed(event):
            return self._deny_text(event)
        manager = self.login_manager
        mode = getattr(manager, "login_mode", "cookie")
        has_cookie = os.path.exists(self.cookie_file)
        epoch = self._auth_epoch
        try:
            cached = await asyncio.to_thread(self._load_token, epoch)
        except Exception as exc:
            return self._err(exc)
        left = int(cached.get("expire_at", 0) - time.time()) if cached.get("expire_at") else 0
        lines = []
        if mode == "password":
            # v0.4.0 在 password 模式下也只看 cookie 文件，恒定输出「没有，需要导入」。
            lines.append("登录方式：账号密码（加密保存）")
            try:
                st = await asyncio.to_thread(self.credentials.status) if self.credentials else {}
            except Exception:
                st = {}
            state_label = {
                "ok": "已保存", "absent": "未保存", "corrupt": "文件损坏，需重新保存",
                "locked": "已锁定，检查权限和原主密钥", "unavailable": "加密服务或主密钥不可用",
            }.get(st.get("state") or "", "未知")
            lines.append("凭据：%s%s" % (
                state_label,
                ("（%s）" % st["account_masked"]) if st.get("account_masked") else ""))
            session = manager.status()
            lines.append("登录会话：%s %s" % (session.get("state"), session.get("message") or ""))
            if session.get("cooldown_left"):
                lines.append("失败冷却：还剩 %d 秒" % int(session["cooldown_left"]))
            lines.append("今日自动登录失败次数：%s/%s" % (
                session.get("daily_used"), session.get("daily_limit")))
        else:
            lines.append("登录方式：Cookie")
            lines.append("cookie 文件：%s" % (
                "有" if has_cookie else "没有，需要导入"))
        lines.append("token 缓存：%s" % ("有效，剩 %d 秒" % left if left > 0 else "无 / 已过期"))

        # 实测连通性：有缓存 token 就用一个**实测可用**的取数端点验一次
        # （静息心率近 1 天）。不要用 /user/basicInfos —— 那是 v0.4.0 里从未被
        # 真实调用过的死代码，403/404 会被渲染成「实测失败」，把用户吓去查通道。
        token = cached.get("token")
        if token and left > 0:
            try:
                deadline = time.monotonic() + self.QUERY_TIMEOUT
                def probe():
                    client = HuaweiHealthClient(
                        token,
                        client_id=(self.config.get("client_id") or DEFAULT_CLIENT_ID).strip(),
                        version=(self.config.get("api_version") or DEFAULT_VERSION).strip(),
                        timezone=self._timezone(), deadline=deadline,
                    )
                    try:
                        return client.resting_heart_rate(1)
                    finally:
                        close = getattr(client, "close", None)
                        if callable(close):
                            close()
                await asyncio.wait_for(asyncio.to_thread(probe), timeout=self.QUERY_TIMEOUT)
                lines.append("实测：token 可用 ✓")
            except AuthExpired:
                lines.append("实测：token 已失效（下次查询会自动续）")
            except Exception as exc:
                # 探针端点自己出问题 ≠ 通道坏了，别让用户去排查错方向。
                lines.append("实测：无法验证（探针接口异常：%s），不代表取数不可用" % self._err(exc))
        else:
            lines.append("实测：跳过（没有有效缓存 token，下次查询会自动认证）")
        try:
            self._assert_current(epoch)
        except Exception as exc:
            return self._err(exc)
        return "\n".join(lines)

    @filter.llm_tool(name="health_today")
    async def health_today(self, event: AstrMessageEvent):
        """查看今天的健康概况：今天的静息心率、最近一晚睡眠、近期运动记录。

        用户问「今天身体怎么样」「昨晚睡得怎么样」「心率如何」时优先用这个。
        """
        if not self._is_allowed(event):
            return self._deny_text(event)
        tz = self._timezone()
        specs = [
            ("hr:1", "静息心率", lambda c: c.resting_heart_rate(1),
             lambda d: self._metric_text(d, "bpm", 1, "静息心率", count_label="天"), None),
            ("sleep:3", "睡眠", lambda c: c.sleep_records(3),
             lambda d: self._sleep_text(d, 3, night_only=True, timezone=tz, limit=1), None),
            ("act:7:10", "近期运动", lambda c: c.activities(7, 10),
             lambda d: self._fmt_acts(d, 7, 10, timezone=tz), None),
        ]
        try:
            return self._items_text(await self._run_items(specs))
        except Exception as exc:
            return self._err(exc)

    @filter.llm_tool(name="health_overview")
    async def health_overview(self, event: AstrMessageEvent):
        """一次性查看全部已接入的健康数据：静息心率、睡眠、睡眠 HRV、压力、体重、心率区间、运动能力与预测成绩、个人纪录、近期运动。

        用户问「健康状况整体怎么样」「把能看的都给我看看」「健康总览」时用这个。
        """
        if not self._is_allowed(event):
            return self._deny_text(event)
        try:
            return self._items_text(await self._overview_items())
        except Exception as exc:
            return self._err(exc)

    @filter.llm_tool(name="health_sleep")
    async def health_sleep(self, event: AstrMessageEvent, days: int = 7):
        """查看最近 N 天的睡眠记录（每晚的入睡/醒来时间、深浅睡与 REM 分段、总分）。

        Args:
            days(number): 查询天数，默认 7，范围 1~30
        """
        if not self._is_allowed(event):
            return self._deny_text(event)
        days = _int_cfg(days, 7, 1, 30)
        try:
            sl = await self._query("sleep:%d" % days, lambda c: c.sleep_records(days))
            return self._sleep_text(sl, days, timezone=self._timezone())
        except Exception as exc:
            return self._err(exc)

    @filter.llm_tool(name="health_heart")
    async def health_heart(self, event: AstrMessageEvent, days: int = 7):
        """查看最近 N 天的静息心率与睡眠 HRV（恢复状态）。

        Args:
            days(number): 查询天数，默认 7，范围 1~90
        """
        if not self._is_allowed(event):
            return self._deny_text(event)
        days = _int_cfg(days, 7, 1, 90)
        specs = [
            ("hr:%d" % days, "静息心率 bpm", lambda c: c.resting_heart_rate(days),
             lambda d: self._metric_text(d, "bpm", days, "静息心率", count_label="天"), None),
            ("hrv:%d" % days, "睡眠 HRV", lambda c: c.hrv_stats(days),
             lambda d: self._metric_text(d, "", days, "HRV"), None),
        ]
        try:
            return self._items_text(await self._run_items(specs))
        except Exception as exc:
            return self._err(exc)

    @filter.llm_tool(name="health_activities")
    async def health_activities(self, event: AstrMessageEvent, days: int = 30, limit: int = 10):
        """查看最近的运动记录列表。

        Args:
            days(number): 回溯天数，默认 30，范围 1~365
            limit(number): 最多返回几条，默认 10，范围 1~50
        """
        if not self._is_allowed(event):
            return self._deny_text(event)
        days = _int_cfg(days, 30, 1, 365)
        limit = _int_cfg(limit, 10, 1, 50)
        try:
            acts = await self._query("act:%d:%d" % (days, limit),
                                      lambda c: c.activities(days, limit))
        except Exception as exc:
            return self._err(exc)
        if not acts:
            return "最近 %d 天没有运动记录。" % days
        return self._fmt_acts(acts, days, limit, timezone=self._timezone())

    @filter.llm_tool(name="health_performance")
    async def health_performance(self, event: AstrMessageEvent):
        """查看运动能力评估（跑力指数、预测成绩）与跑步个人纪录。

        用户问「跑力多少」「半马能跑多久」「PB 是多少」时用这个。
        """
        if not self._is_allowed(event):
            return self._deny_text(event)
        specs = [
            ("perf", "运动能力评估", lambda c: c.athletic_performance(), self._fmt_perf, 3600),
            ("pb", "跑步个人纪录", lambda c: c.personal_bests("running"), self._fmt_pb, 3600),
        ]
        try:
            return self._items_text(await self._run_items(specs))
        except Exception as exc:
            return self._err(exc)

    @filter.llm_tool(name="health_refresh")
    async def health_refresh(self, event: AstrMessageEvent):
        """清空本地缓存并强制重新认证（token 也一起刷新）。数据在下次查询时重新拉取。

        用户问「刷新一下最新的健康数据」时用这个。
        """
        if not self._is_allowed(event):
            return self._deny_text(event)
        # 刷新时推进 generation，避免尚未结束的旧请求覆盖刷新后的缓存。
        try:
            await self._invalidate_auth_cache()
            await asyncio.wait_for(self._token(force=True), timeout=self.QUERY_TIMEOUT)
            return "缓存已清空，并已重新拿到最新 token。可以继续查询了。"
        except Exception as exc:
            return "刷新未完成：%s" % self._err(exc)

    async def terminate(self):
        def stop_state():
            with self._state_lock:
                self._closed = True
                self._auth_epoch += 1
                self.login_manager.invalidate()
                self._client_pool.close()
        await asyncio.to_thread(stop_state)
        tasks = list(self._cache_inflight.values())
        if self._warmup_task:
            tasks.append(self._warmup_task)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._cache_inflight.clear()
        if self.login_manager:
            await asyncio.to_thread(self.login_manager.stop)
        self.logger.info("[华为健康] 插件已卸载/停用。")
