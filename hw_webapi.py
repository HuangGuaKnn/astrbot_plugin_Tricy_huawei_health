# -*- coding: utf-8 -*-
"""华为运动健康 · 插件 WebUI 后端 API

页面位于 pages/health_console/，由 AstrBot 的 PluginPageService 自动挂载。
前端通过 bridge（window.AstrBotPluginPage）调用本模块注册的接口，
route 前缀：astrbot_plugin_Tricy_huawei_health/page/...
"""

import asyncio
import copy
import json
import os
import time

from astrbot.api.web import json_response, request

try:
    from .hw_login import LoginFlowError
    from .hw_credentials import CredentialsError, CredentialsUnavailableError, CredentialsLockedError
    from .hw_privacy import redact_error
    from .hw_client import format_timezone
except ImportError:
    from hw_login import LoginFlowError
    from hw_credentials import CredentialsError, CredentialsUnavailableError, CredentialsLockedError
    from hw_privacy import redact_error
    from hw_client import format_timezone

PAGE_PREFIX = "astrbot_plugin_Tricy_huawei_health/page"

#: cookie 里最关键的几个（决定「信任设备」是否还在）。
#: v0.4.1：与 hw_auth.MIN_COOKIE_SPECS 统一——v0.4.0 这里列了两个永远配不出来的名字
#: （HUAWEI_ID_CAS_ISCASLOGIN / __uni__uid），而 CASLOGINSITE / LOGINACCSITE 配了却
#: 永远显示不出来。
try:
    from .hw_auth import MIN_COOKIE_SPECS, REQUIRED_COOKIES, cookies_from_fields, parse_cookie_input
except ImportError:
    from hw_auth import MIN_COOKIE_SPECS, REQUIRED_COOKIES, cookies_from_fields, parse_cookie_input

KEY_COOKIES = tuple(name for name, _, _ in MIN_COOKIE_SPECS)

# ==================== T8：配置同源（WebUI 直接读写 AstrBot 配置）====================
#
# 普通设置只读写 self.plugin.config 这一份配置，不另建配置副本。
# Cookie 表单是只写安全导入入口；导入成功后清空普通配置中的七个敏感字段。
# AstrBotConfig.__setattr__ 只做 self[key] = value（不落盘），所以保存必须显式调用
# save_config_async()（异步 + 内部 revision 防旧快照覆盖）。

#: 敏感配置项：cookie 相关 7 项。GET /config 一律返回掩码，任何响应体都不许回显真实值。
SENSITIVE_KEYS = (
    "cookie_json",
    "cookie_CASTGC",
    "cookie_sid",
    "cookie_hwid_cas_sid",
    "cookie_HuaweiID_CAS_ISCASLOGIN",
    "cookie_CASLOGINSITE",
    "cookie_LOGINACCSITE",
)

#: 掩码占位符。前端回传这个值表示「该项未修改」，服务端直接跳过——
#: 绝不允许把掩码写进配置，否则会清空用户真正的 cookie。
MASK = "***"

#: 与 main.PERMISSION_SECTION 保持一致。这里不 import main，避免循环导入。
PERMISSION_SECTION = "permission_settings"

#: int 型配置的上下界，必须与 main.py 里 _int_cfg / login_daily_limit 的钳制语义一致。
INT_BOUNDS = {
    "page_timeout": (1, 600),
    "token_ttl": (0, 86400),
    "data_ttl": (0, 86400),
    "login_daily_limit": (1, 10),
}


#: 区分「键不存在」与「键的值是 None」用的哨兵。
_MISSING = object()


class ConfigValueError(Exception):
    """单个配置项校验失败。field 供前端定位到具体控件。"""

    def __init__(self, field, message):
        super().__init__(message)
        self.field = field
        self.message = message


class ConfigPersistError(Exception):
    """A validated update could not be committed to the AstrBot config."""


class ConfigRevisionError(Exception):
    """The account/config changed while this request waited for its transaction."""


def _schema_path() -> str:
    """_conf_schema.json 与本文件同目录（插件根目录）。"""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "_conf_schema.json")


def _load_schema() -> dict:
    """读取 _conf_schema.json 并原样返回。读不到就当空 schema（接口仍可用，但不接受写入）。"""
    try:
        with open(_schema_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _schema_leaves(schema: dict) -> dict:
    """把 schema 摊平成 {点号路径: 叶子定义}，供白名单校验与前端表单渲染使用。"""
    leaves = {}
    for key, spec in (schema or {}).items():
        if not isinstance(spec, dict):
            continue
        if spec.get("type") == "object":
            for sub_key, sub_spec in (spec.get("items") or {}).items():
                if isinstance(sub_spec, dict):
                    leaves["%s.%s" % (key, sub_key)] = sub_spec
        else:
            leaves[key] = spec
    return leaves


def _as_bool(value, default: bool = False) -> bool:
    """宽容布尔取值，口径与 main._cfg_bool 一致。"""
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


def _get_path(values: dict, path: str):
    """按点号路径取值（只支持一层嵌套，与配置结构一致）。"""
    if "." in path:
        group_key, sub_key = path.split(".", 1)
        group = values.get(group_key)
        return group.get(sub_key) if isinstance(group, dict) else None
    return values.get(path)



class HuaweiHealthWebApi:
    def __init__(self, plugin):
        self.plugin = plugin
        self._config_lock = asyncio.Lock()

    # ---------- 注册 ----------

    def register(self):
        reg = self.plugin.context.register_web_api
        reg(f"{PAGE_PREFIX}/status", self.get_status, ["GET"], "通道状态")
        reg(f"{PAGE_PREFIX}/overview", self.overview, ["GET"], "数据概览")
        reg(f"{PAGE_PREFIX}/cookie/import", self.import_cookie, ["POST"], "导入 cookie")
        reg(f"{PAGE_PREFIX}/cookie/clear", self.clear_cookie, ["POST"], "清除 cookie")
        reg(f"{PAGE_PREFIX}/refresh", self.refresh, ["POST"], "清缓存并重新认证")
        reg(f"{PAGE_PREFIX}/login/start", self.login_start, ["POST"], "开始网页登录")
        reg(f"{PAGE_PREFIX}/login/status", self.login_status, ["GET"], "网页登录状态")
        reg(f"{PAGE_PREFIX}/login/sms", self.login_sms, ["POST"], "提交网页登录验证码")
        reg(f"{PAGE_PREFIX}/login/trust", self.login_trust, ["POST"], "提交网页登录信任选择")
        reg(f"{PAGE_PREFIX}/login/cancel", self.login_cancel, ["POST"], "取消网页登录")
        reg(f"{PAGE_PREFIX}/credentials", self.credentials_write, ["POST"], "保存账号密码凭据")
        reg(f"{PAGE_PREFIX}/credentials/status", self.credentials_status, ["GET"], "账号密码凭据状态")
        # T8：配置同源（WebUI 直接读写 AstrBot 配置）。只增不改：12 -> 14 条。
        # 同一路径不同 method 是两条独立注册，框架按 method 精确匹配。
        reg(f"{PAGE_PREFIX}/config", self.get_config, ["GET"], "读取插件配置（敏感项掩码）")
        reg(f"{PAGE_PREFIX}/config", self.post_config, ["POST"], "保存插件配置（立即生效）")
        # v0.4.1：删掉 login/account —— 注册了但前端从不调用，且 handler 恒返回 409。

    # ---------- 工具 ----------

    @staticmethod
    def _fmt_ts(ts) -> str:
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            return "-"
        if ts <= 0:
            return "会话级"
        try:
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
        except Exception:
            return "-"

    def _browser(self) -> dict:
        p = self.plugin
        try:
            try:
                from .hw_auth import find_browser
            except ImportError:
                from hw_auth import find_browser
            configured = (p.config.get("browser_path") or "").strip()
            path = find_browser(configured)
        except Exception:
            return {"path": "", "found": False, "configured": "", "configured_ok": True}
        # find_browser 在「填了路径但文件不存在」时会静默回退到默认浏览器。
        # 页面必须把这件事说出来，否则用户会以为自己填的路径生效了——
        # 这正是「配置填错但查不出原因」的常见来源。
        configured_ok = (not configured) or os.path.exists(configured)
        return {
            "path": path,
            "found": bool(path),
            "configured": configured,
            "configured_ok": configured_ok,
        }

    def _cookie_storage_data(self) -> dict:
        """只返回存储保护方式，不把 Cookie 内容或文件路径交给页面。"""
        try:
            return self.plugin.auth.cookie_storage_status()
        except Exception:
            return {"mode": "error", "encrypted": False, "message": "Cookie 存储状态暂时不可用"}

    # ---------- 接口 ----------

    @staticmethod
    def _permission_snapshot(p) -> dict:
        """权限状态快照（T7）。

        AstrBot 没有「插件侧配置保存前校验」钩子，所以采用等效方案：
        保存 → 自动重载 → 立刻把不合法的 UMO 回显出来。字段缺失时按
        fail-closed 的默认值回显，本方法绝不抛异常。
        """

        def flag(key, default):
            getter = getattr(p, "_cfg_bool", None)
            if callable(getter):
                try:
                    return bool(getter(key, default))
                except Exception:
                    return default
            return default

        try:
            extra_umo_count = len(p._whitelist())
        except Exception:
            extra_umo_count = 0
        try:
            invalid = [str(item) for item in (getattr(p, "_invalid_umos", None) or [])]
        except Exception:
            invalid = []
        return {
            "allow_private": flag("allow_private", True),
            "allow_group": flag("allow_group", False),
            "admin_only": flag("admin_only", True),
            "extra_umo_count": extra_umo_count,
            "invalid_umos": invalid,
        }

    async def get_status(self):
        p = self.plugin
        manager = getattr(p, "login_manager", None)
        data = {
            # 页面状态版本与插件元数据统一，避免前端误判部署版本。
            "version": "v0.5.0",
            "data_dir": p.data_dir,
            "cookie_file": p.cookie_file,
            "login_mode": getattr(manager, "login_mode", "cookie"),
            "browser": self._browser(),
            "config": {
                "headless": bool(p.config.get("headless", True)),
                "token_ttl": p.config.get("token_ttl", 3000),
                "data_ttl": p.config.get("data_ttl", 600),
                "warmup": bool(p.config.get("warmup", True)),
            },
            # T7：权限可见范围 + 不合法的 UMO 回显（不改动上面的现有字段）。
            "permission": self._permission_snapshot(p),
        }

        # cookie
        cf = p.cookie_file
        cinfo = {"exists": os.path.exists(cf), "count": 0, "mtime": "-", "keys": [], "error": ""}
        cinfo["storage"] = await asyncio.to_thread(self._cookie_storage_data)
        if cinfo["exists"]:
            try:
                cookies = await asyncio.to_thread(p.auth.load_cookies)
                cinfo["count"] = len(cookies)
                cinfo["mtime"] = time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(cf)))
                for c in cookies:
                    if c.get("name") in KEY_COOKIES:
                        cinfo["keys"].append({
                            "name": c.get("name"),
                            "domain": c.get("domain"),
                            # CASTGC 有 /CAS 和 /UnifiedIDMPortal 两条，不给 path 列
                            # 页面上会出现两行一模一样的名字。
                            "path": c.get("path") or "/",
                            "expires": self._fmt_ts(c.get("expires")),
                        })
            except Exception as exc:
                # 前端会把这句直接显示出来，异常原文可能带 cookie 文件路径。
                cinfo["error"] = redact_error(exc)
        data["cookie"] = cinfo

        # token
        tinfo = {"cached": False, "left": 0, "obtained_at": "-",
                 "state": "absent", "error": ""}
        try:
            # Secret providers may access Keychain or files. Keep that work off
            # the event loop, and never treat a locked store as a cache miss.
            tok = await asyncio.to_thread(p.store.get, "token") or {}
            left = int(float(tok["expire_at"]) - time.time()) if tok.get("expire_at") else 0
            cached = bool(tok.get("token"))
            tinfo.update({"cached": cached, "left": max(0, left),
                          "obtained_at": tok.get("obtained_at") or "-",
                          "state": ("ready" if left > 0 else "expired") if cached else "absent"})
        except CredentialsError:
            tinfo.update({"state": "locked", "error":
                          "token 缓存已锁定，请检查原主密钥、系统加密服务或文件完整性；原记录未被覆盖"})
        except Exception:
            # Database exceptions can include paths or raw values. The status
            # endpoint should remain usable for recovery without echoing them.
            tinfo.update({"state": "error", "error": "token 缓存读取失败，请检查数据库访问权限或文件状态"})
        data["token"] = tinfo

        # 缓存
        try:
            keys = await asyncio.to_thread(p.store.keys)
        except Exception:
            keys = []
        data["cache"] = {"count": len(keys), "keys": keys[:20]}

        return json_response({"status": "ok", "data": data})

    async def overview(self):
        """把所有已接入的数据项一次拉齐，给 WebUI 的「概览窗口」用。

        与 LLM 的 `health_overview` 共用 `main._overview_items()`：同一份项目定义、
        同样的并发上限、同样的整体超时兜底（v0.4.0 这里是复制粘贴的一份实现）。
        """
        p = self.plugin
        try:
            items = await p._overview_items()
        except Exception as exc:
            return json_response({"status": "error", "message": p._err(exc)}, status_code=500)
        return json_response({"status": "ok", "data": {
            "items": items,
            "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }})

    async def import_cookie(self):
        p = self.plugin
        try:
            body = await request.json()
        except Exception:
            return json_response({"status": "error", "message": "请求体不是合法 JSON"},
                                 status_code=400)
        if not isinstance(body, dict):
            return json_response({"status": "error", "message": "请求体必须是 JSON 对象"},
                                 status_code=400)
        text = body.get("json", "")
        if not isinstance(text, str):
            return json_response({"status": "error", "message": "json 字段必须是字符串"}, status_code=400)
        text = text.strip()
        fields = body.get("fields", {})
        if not isinstance(fields, dict) or any(not isinstance(v, str) for v in fields.values()):
            return json_response({"status": "error", "message": "fields 必须是 Cookie 名称与字符串值组成的对象"},
                                 status_code=400)
        if not text and not any(v.strip() for v in fields.values()):
            return json_response({"status": "error", "message": "cookie 内容为空"},
                                 status_code=400)
        try:
            # 显式导入替换整个 Cookie 集合；不混入上一账号的辅助会话 Cookie。
            n = await p._change_auth_state(lambda: p.auth.import_cookie_sources(text, fields, replace_existing=True))
        except Exception as exc:
            return json_response(
                {"status": "error", "message": redact_error(exc)}, status_code=400)
        p.logger.info("[华为健康] WebUI 导入了 %d 条 cookie" % n)
        return json_response({
            "status": "ok",
            "message": "已导入 %d 条 cookie（已替换旧会话），token 缓存已作废，下次查询会重新认证" % n,
            "count": n,
        })

    async def clear_cookie(self):
        p = self.plugin
        try:
            await p._change_auth_state(clear_cookies=True)
        except Exception as exc:
            return json_response(
                {"status": "error", "message": redact_error(exc)}, status_code=500)
        p.logger.warning("[华为健康] WebUI 清除了 cookie 文件")
        return json_response({"status": "ok", "message": "cookie 已清除，token 缓存已作废"})

    async def refresh(self):
        p = self.plugin
        try:
            # 清理失败必须中止，不可继续认证后把失败误报为成功。
            await p._change_auth_state()
            await asyncio.wait_for(p._token(force=True), timeout=getattr(p, "QUERY_TIMEOUT", 90))
        except Exception as exc:
            return json_response({"status": "error", "message": p._err(exc)}, status_code=500)
        return json_response({"status": "ok", "message": "缓存已清空，并已重新拿到最新 token"})

    # ---------- 账号凭据（只写接口，状态只包含保护方式与掩码） ----------

    def _credentials_status_data(self):
        store = getattr(self.plugin, "credentials", None)
        raw = store.status() if store is not None else {}
        storage = raw.get("storage") if isinstance(raw.get("storage"), dict) else {}
        available = (bool(storage["available"]) if "available" in storage else
                     bool(getattr(store, "available", False)))
        password_set = bool(raw.get("password_set"))
        login_manager = getattr(self.plugin, "login_manager", None)
        configured_mode = getattr(login_manager, "login_mode", "cookie")
        if configured_mode not in ("cookie", "password"):
            configured_mode = "cookie"
        mode = "password" if password_set else configured_mode
        updated_at = raw.get("updated_at")
        if isinstance(updated_at, (int, float)) and updated_at > 0:
            try:
                updated_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(updated_at))
            except (OverflowError, OSError, ValueError):
                updated_at = "-"
        if not updated_at:
            updated_at = "-"
        return {
            "mode": mode,
            "password_set": password_set,
            "account_masked": str(raw.get("account_masked") or ""),
            "updated_at": updated_at,
            # 区分「没保存 / 已保存 / 损坏 / 已锁定 / 加密存储未配置」，
            # 不再把损坏的文件谎报成「未保存」。
            "state": str(raw.get("state") or "absent"),
            "error": str(raw.get("error") or ""),
            "available": available,
            "storage": {
                "available": available,
                "method": str(storage.get("method") or "unknown"),
                "key_source": str(storage.get("key_source") or "none"),
                "error": redact_error(storage["error"]) if storage.get("error") else "",
            },
            "cookie_storage": self._cookie_storage_data(),
        }

    async def credentials_status(self):
        data = await asyncio.to_thread(self._credentials_status_data)
        return json_response({"status": "ok", "data": data})

    async def credentials_write(self):
        try:
            body = await request.json()
        except Exception:
            return json_response({"status": "error", "message": "请求体不是合法 JSON"}, status_code=400)
        if not isinstance(body, dict):
            return json_response({"status": "error", "message": "请求体必须是 JSON 对象"}, status_code=400)
        store = getattr(self.plugin, "credentials", None)
        if store is None:
            return json_response({"status": "error", "message": "当前版本不支持安全凭据存储"}, status_code=409)

        mode = str(body.get("mode") or "").strip().lower()
        clear = body.get("clear") is True or mode == "cookie"
        if clear:
            def clear_credentials():
                store.clear()
                self.plugin.login_manager.set_login_mode("cookie")
                try:
                    self.plugin.login_manager.clear_cooldown()
                except Exception:
                    pass
            try:
                await self.plugin._change_auth_state(clear_credentials)
            except Exception:
                return json_response({"status": "error", "message": "凭据清除失败，请稍后重试"}, status_code=500)
            return json_response({
                "status": "ok", "data": await asyncio.to_thread(self._credentials_status_data),
                "message": "账号密码凭据已清除，已切换到 Cookie 模式并清空缓存",
            })

        account = body.get("account")
        password = body.get("password")
        if mode not in ("", "password") or not isinstance(account, str) or not isinstance(password, str):
            return json_response({"status": "error", "message": "请输入账号和密码"}, status_code=400)
        if not account.strip() or not password or len(account) > 150 or len(password) > 512:
            return json_response({"status": "error", "message": "请输入有效的账号和密码"}, status_code=400)
        storage_status = await asyncio.to_thread(self._credentials_status_data)
        if not storage_status["available"]:
            return json_response({
                "status": "error", "message": storage_status["storage"]["error"] or
                "加密存储尚未就绪，请先按 README 配置主密钥，再保存账号密码",
            }, status_code=409)
        def save_credentials():
            store.save(account, password)
            self.plugin.login_manager.set_login_mode("password")
            # 用户刚把密码改对：把 6 小时失败冷却立刻清掉，否则提示会自相矛盾
            # （「请重新保存账号密码」→ 保存完 → 「冷却中，请稍后再试」）。
            try:
                self.plugin.login_manager.clear_cooldown()
            except Exception:
                pass

        try:
            # 保存新账号时撤销旧登录态，避免新账号认证失败后回退到旧账号 Cookie。
            await self.plugin._change_auth_state(save_credentials, clear_cookies=True)
        except CredentialsUnavailableError as exc:
            return json_response({
                "status": "error", "message": redact_error(exc) or "加密存储不可用，请检查主密钥配置",
            }, status_code=409)
        except CredentialsLockedError:
            return json_response({
                "status": "error", "message": "凭据已锁定，请检查主密钥或文件权限；原文件已保留",
            }, status_code=409)
        except Exception:
            return json_response({"status": "error", "message": "凭据保存失败，请稍后重试"}, status_code=500)
        finally:
            # Do not retain request fields after the write path returns.
            account = None
            password = None
        return json_response({
            "status": "ok", "data": await asyncio.to_thread(self._credentials_status_data),
            "message": "账号密码已加密保存，旧登录态已清除，下次查询会重新登录",
        })

    # ---------- 登录会话（v0.4.0 第 4 阶段：自动登录与降级） ----------

    async def login_start(self):
        p = self.plugin
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        mode = str(body.get("mode") or "manual").strip().lower()
        auto_trust = body.get("auto_trust") if isinstance(body.get("auto_trust"), bool) else None
        allow_visible_fallback = (
            body.get("allow_visible_fallback")
            if isinstance(body.get("allow_visible_fallback"), bool) else None
        )
        prefer_auto = body.get("prefer_auto") if isinstance(body.get("prefer_auto"), bool) else None
        try:
            session = p.login_manager.current_session()
            if (session is not None and session.is_running()
                    and session.snapshot().get("state") not in ("DONE", "FAILED")):
                return json_response({"status": "ok", "data": p.login_manager.status()})
            # 用户在 WebUI 主动点「开始登录」不占用每日自动登录额度，
            # 只有取数路径触发的自动登录才计入额度与失败冷却。
            # 清理与启动共用状态锁、同一个线程任务，避免中间查询用旧 Cookie 认证。
            await p._change_auth_state(lambda: p.login_manager.start(
                mode,
                auto_trust=auto_trust,
                allow_visible_fallback=allow_visible_fallback,
                manual=True,
                prefer_auto=prefer_auto,
            ))
        except LoginFlowError as exc:
            message = {
                "trust_invalid": "自动信任选项无效",
                "fallback_invalid": "可见窗口兜底选项无效",
                "prefer_invalid": "无头自动登录选项无效",
                "credentials_missing": "尚未保存账号密码，请先在凭据区保存",
                "credentials_unavailable": "加密存储尚未就绪，请检查系统凭据或主密钥配置",
                "credentials_corrupt": "账号密码凭据已损坏，请在凭据区重新保存",
                "credentials_locked": "账号密码凭据已锁定，请检查主密钥或文件权限",
                "daily_limit": "今日自动登录失败次数已达上限，请稍后再试",
                "cooldown": "自动登录失败冷却中，请稍后再试",
                "unsupported": "登录模式无效",
            }.get(exc.code, "登录启动失败，请稍后重试")
            status = 429 if exc.code in ("daily_limit", "cooldown") else 409
            return json_response({
                "status": "error",
                "message": message,
            }, status_code=status)
        except Exception as exc:
            return json_response({"status": "error", "message": p._err(exc)}, status_code=500)
        # v0.4.1：返回体与 /login/status 统一（原来用 session.snapshot()，
        # 少 daily_used / daily_limit / prefer_auto，点完登录那一次额度行不刷新）。
        return json_response({"status": "ok", "data": p.login_manager.status()})

    async def login_status(self):
        return json_response({"status": "ok", "data": self.plugin.login_manager.status()})

    async def login_sms(self):
        try:
            body = await request.json()
        except Exception:
            body = {}
        code = body.get("code") if isinstance(body, dict) else ""
        try:
            data = self.plugin.login_manager.submit_sms(code)
        except LoginFlowError as exc:
            message = {
                "sms_invalid": "验证码必须是 4~8 位数字",
                "sms_unavailable": "当前登录状态不需要提交验证码",
                "sms_busy": "上一条验证码正在提交，请稍候",
            }.get(exc.code, "验证码提交失败，请稍后重试")
            status = 400 if exc.code == "sms_invalid" else 409
            return json_response({"status": "error", "message": message}, status_code=status)
        return json_response({"status": "ok", "data": data, "message": "验证码已提交"})

    async def login_trust(self):
        try:
            body = await request.json()
        except Exception:
            body = {}
        choice = body.get("trust") if isinstance(body, dict) else ""
        if isinstance(choice, bool):
            choice = "true" if choice else "false"
        try:
            data = self.plugin.login_manager.submit_trust(choice)
        except LoginFlowError as exc:
            message = {
                "trust_invalid": "信任选择无效",
                "trust_unavailable": "当前登录状态不需要选择信任方式",
                "trust_busy": "上一条信任选择正在提交，请稍候",
            }.get(exc.code, "信任选择提交失败，请稍后重试")
            status = 400 if exc.code == "trust_invalid" else 409
            return json_response({"status": "error", "message": message}, status_code=status)
        return json_response({"status": "ok", "data": data, "message": "信任选择已提交"})

    async def login_cancel(self):
        data = await asyncio.to_thread(self.plugin.login_manager.cancel)
        return json_response({"status": "ok", "data": data, "message": "登录已取消"})

    # ================= 配置同源（T8）=================
    #
    # 目标：在 WebUI 里改 = 在 AstrBot 配置页里改，且 21 项全部立即生效、不用重启。
    # 因此这里只有一条数据通路：plugin.config（AstrBotConfig）。
    # 不写第二份文件、不缓存配置影子副本。

    # ---------- 版本戳 / 快照 ----------

    def _config_revision(self) -> str:
        """并发覆盖防护用的版本戳。

        方案：框架自增的 ``_save_revision`` + ``_save_committed_revision`` + 配置文件
        ``mtime_ns``。前两者覆盖「任何走 save_config_async 的保存」（含 AstrBot 配置页
        那条路径），后者兜住「绕过配置对象直接改文件」的情况。

        注意 AstrBotConfig.__getattr__ 对缺失属性返回 None 而不是抛异常，
        所以统一用 getattr(..., None)；测试桩没有这些属性时退化成常量子串。
        """
        cfg = self.plugin.config
        revision = getattr(cfg, "_save_revision", None)
        committed = getattr(cfg, "_save_committed_revision", None)
        mtime = 0
        path = getattr(cfg, "config_path", None)
        if path:
            try:
                mtime = os.stat(path).st_mtime_ns
            except OSError:
                mtime = 0
        # A dedicated Cookie/credentials update also invalidates a form opened
        # before that account change, even when the AstrBot config was untouched.
        return "%s-%s-%s-%s-%s" % (
            revision, committed, mtime,
            getattr(self.plugin, "_auth_epoch", 0), getattr(self.plugin, "_data_epoch", 0))

    def _config_mtime_text(self) -> str:
        path = getattr(self.plugin.config, "config_path", None)
        if not path:
            return "-"
        try:
            return time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(os.stat(path).st_mtime))
        except OSError:
            return "-"

    def _read_values(self) -> dict:
        """当前配置的完整视图（21 个叶子，敏感项始终为掩码）。

        缺失项按 schema 的 default 补齐，保证前端拿到的永远是完整表单数据。
        """
        schema = _load_schema()
        cfg = self.plugin.config
        values = {}
        for key, spec in schema.items():
            if not isinstance(spec, dict):
                continue
            if key in SENSITIVE_KEYS:
                values[key] = MASK
            elif spec.get("type") == "object":
                raw = cfg.get(key)
                group = raw if isinstance(raw, dict) else {}
                children = {}
                for sub_key, sub_spec in (spec.get("items") or {}).items():
                    if not isinstance(sub_spec, dict):
                        continue
                    value = group.get(sub_key)
                    children[sub_key] = sub_spec.get("default") if value is None else value
                values[key] = children
            else:
                value = cfg.get(key)
                values[key] = spec.get("default") if value is None else value
        return values

    @staticmethod
    def _mask(values: dict) -> dict:
        """深拷贝后把 7 个敏感项替换成掩码。任何响应体都只经过这一层。"""
        masked = copy.deepcopy(values)
        for key in SENSITIVE_KEYS:
            if key in masked:
                masked[key] = MASK
        return masked

    def _has_value(self) -> dict:
        """Expose presence only, from secure storage or an unmigrated legacy config."""
        values = self.plugin.config
        present = {key: bool(str(values.get(key) or "").strip()) for key in SENSITIVE_KEYS}
        try:
            cookies = self.plugin.auth.load_cookies()
        except Exception:
            cookies = []
        if cookies:
            present["cookie_json"] = True
            for cookie in cookies:
                name = "cookie_" + str(cookie.get("name") or "")
                if name in present and str(cookie.get("value") or "").strip():
                    present[name] = True
        return present

    def _meta(self, values: dict = None) -> dict:
        if values is None:
            values = self._read_values()
        return {
            "revision": self._config_revision(),
            "sensitive": list(SENSITIVE_KEYS),
            "has_value": self._has_value(),
            "bounds": {key: list(pair) for key, pair in INT_BOUNDS.items()},
            "updated_at": self._config_mtime_text(),
            "source": "astrbot_config",
        }

    # ---------- 校验（纯计算，无副作用）----------

    def _check_leaf(self, path: str, value, spec: dict):
        """按 schema 校验单个叶子，返回 (写入值, 是否被钳制)。失败抛 ConfigValueError。"""
        leaf_type = spec.get("type")
        name = path.split(".")[-1]

        if leaf_type == "bool":
            # 严格：不接受 "true" / 1，避免把脏值写进配置。
            if not isinstance(value, bool):
                raise ConfigValueError(path, "%s 必须是布尔值（true / false）" % name)
            return value, False

        if leaf_type == "int":
            # bool 是 int 的子类，必须显式排除，否则 true 会被当成 1 混进来。
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigValueError(path, "%s 必须是整数" % name)
            result, clamped = value, False
            bounds = INT_BOUNDS.get(name)
            if bounds:
                low, high = bounds
                if result < low:
                    result, clamped = low, True
                elif result > high:
                    result, clamped = high, True
            return result, clamped

        if leaf_type == "float":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ConfigValueError(path, "%s 必须是数字" % name)
            return float(value), False

        if leaf_type in ("string", "text"):
            if not isinstance(value, str):
                raise ConfigValueError(path, "%s 必须是字符串" % name)
            if name == "timezone":
                # 时区是自由文本输入，非法值会让每次取数都在 parse_timezone 抛 ValueError。
                # 在入口处归一化成 ±HHMM 并校验，比运行时崩掉友好得多。
                try:
                    return format_timezone(value), False
                except ValueError as exc:
                    raise ConfigValueError(path, "时区格式不合法：%s" % exc) from None
            if name in ("client_id", "api_version"):
                # 这两项会原样拼进 HTTP header。requests 对含换行/制表符的值抛
                # InvalidHeader，而 main.py 只做了 .strip()，中间的控制字符挡不住。
                # 单行输入框填不出换行，但 POST /page/config 的 JSON 可以。
                cleaned = value.strip()
                if not cleaned.isprintable():
                    raise ConfigValueError(
                        path, "%s 不能包含换行、制表符等控制字符" % name)
                return cleaned, False
            return value, False

        if leaf_type == "list":
            if not isinstance(value, list) or any(
                    not isinstance(item, str) for item in value):
                raise ConfigValueError(path, "%s 必须是字符串列表" % name)
            return list(value), False

        if leaf_type == "object":
            if not isinstance(value, dict):
                raise ConfigValueError(path, "%s 必须是对象" % name)
            return value, False

        # schema 里出现不支持的类型：拒绝而不是放行，避免写脏数据。
        raise ConfigValueError(path, "%s 的配置类型 %r 不受支持" % (name, leaf_type))

    def _check_umos(self, path: str, items) -> list:
        """复用 main._parse_umos 的既有规则；非法条目整单拒绝，不写进配置。"""
        if not isinstance(items, list) or any(
                not isinstance(item, str) for item in items):
            raise ConfigValueError(
                path, "会话 UMO 格式不合法：必须是字符串列表，每条形如 "
                      "platform:MessageType:session_id")
        parser = getattr(self.plugin, "_parse_umos", None)
        if not callable(parser):
            return list(items)
        try:
            valid, invalid = parser(items)
        except Exception as exc:
            raise ConfigValueError(path, "会话 UMO 校验失败：%s" % redact_error(exc))
        if invalid:
            raise ConfigValueError(path, "会话 UMO 格式不合法：%s" % "、".join(invalid))
        return list(valid)

    @staticmethod
    def _is_mask(value) -> bool:
        """是不是掩码占位符。

        容忍前后空白：``" *** "`` 也不许被当成真实值写进配置（否则会覆盖真实 cookie）。
        """
        return isinstance(value, str) and value.strip() == MASK

    @staticmethod
    def _expand_dotted(raw_values: dict) -> dict:
        """把 ``"group.sub"`` 形式的顶层键展开成嵌套 dict。

        schema 叶子是用点号路径表示的，如果直接拿点号键去查白名单，它会精确命中叶子表、
        从而绕过「分组分支」里的 UMO 校验（``{"permission_settings.extra_umo_whitelist":
        ["garbage"]}`` 就会 200 并把脏值落盘）。这里统一归一化，保证两种写法走
        **完全相同**的校验路径。

        同一分组既给 dict 又给点号键时按出现顺序合并（后者覆盖同名子键）；但如果同一分组
        在同一请求里**既给了非对象值、又给了子键**，直接按契约要求报「必须是对象」——
        否则结果会依赖 JSON 成员的书写顺序（这里绝不允许静默丢弃非法值）。
        """
        out = {}
        for key, value in raw_values.items():
            if isinstance(key, str) and "." in key:
                group, sub = key.split(".", 1)
                existing = out.get(group, _MISSING)
                if existing is not _MISSING and not isinstance(existing, dict):
                    raise ConfigValueError(group, "%s 必须是对象" % group)
                merged = dict(existing) if isinstance(existing, dict) else {}
                merged[sub] = value
                out[group] = merged
                continue
            existing = out.get(key, _MISSING)
            # _MISSING 是 object()，isinstance(_MISSING, dict) 恒 False，故无需再判它。
            if isinstance(existing, dict) and not isinstance(value, dict):
                # 先出现的是分组子键、后出现的是非对象：冲突。
                raise ConfigValueError(key, "%s 必须是对象" % key)
            if isinstance(existing, dict) and isinstance(value, dict):
                merged = dict(existing)
                merged.update(value)
                out[key] = merged
            else:
                out[key] = value
        return out

    def _validate_patch(self, raw_values, leaves: dict):
        """白名单 + 类型 + 钳制 + UMO 校验。

        返回 ``(writes, clamped, accepted)``：
          - writes：{点号路径: 新值}，只含通过校验的项；
          - clamped：{点号路径: 钳制后的值}；
          - accepted：通过校验的叶子路径（= 保存后会立即生效的项）。
        """
        if not isinstance(raw_values, dict):
            raise ConfigValueError("values", "values 必须是 JSON 对象")

        for key in raw_values:
            if not isinstance(key, str):
                raise ConfigValueError("values", "配置项名称必须是字符串")

        # 先归一化点号键，再走统一校验，避免两条分支口径不一致。
        values = self._expand_dotted(raw_values)

        writes, clamped, accepted = {}, {}, []
        group_prefix = PERMISSION_SECTION + "."

        for key, value in values.items():
            # 分组（object）：只接受 schema 里声明的子键。
            if any(path.startswith(key + ".") for path in leaves):
                if not isinstance(value, dict):
                    raise ConfigValueError(key, "%s 必须是对象" % key)
                for sub_key, sub_value in value.items():
                    path = "%s.%s" % (key, sub_key)
                    if path not in leaves:
                        raise ConfigValueError(path, "未知配置项：%s" % path)
                    if sub_key in SENSITIVE_KEYS and self._is_mask(sub_value):
                        continue
                    if path == group_prefix + "extra_umo_whitelist":
                        # UMO 列表的类型守卫放在 _check_umos 里，这样「含非字符串条目」
                        # 也能给出 UMO 格式相关的可读错误，而不是干巴巴的类型报错。
                        new_value, was_clamped = self._check_umos(path, sub_value), False
                    else:
                        new_value, was_clamped = self._check_leaf(
                            path, sub_value, leaves[path])
                    writes[path] = new_value
                    accepted.append(path)
                    if was_clamped:
                        clamped[path] = new_value
                continue

            if key not in leaves:
                raise ConfigValueError(key, "未知配置项：%s" % key)

            # 敏感项回传掩码 = 「没改」，直接跳过：绝不能把 "***" 写进配置。
            if key in SENSITIVE_KEYS and self._is_mask(value):
                continue

            new_value, was_clamped = self._check_leaf(key, value, leaves[key])
            writes[key] = new_value
            accepted.append(key)
            if was_clamped:
                clamped[key] = new_value

        return writes, clamped, accepted

    @staticmethod
    def _apply_writes(merged: dict, writes: dict, schema: dict = None) -> dict:
        """把点号路径的写入合并进完整配置副本。

        嵌套分组必须逐子键合并：直接塞 {group: {one_key: v}} 会因为
        save_config_async 内部用 dict.update 浅合并而整组替换、丢掉兄弟键。
        若原配置里压根没有这个分组（老版本配置升级上来），先用 schema 默认值补齐，
        避免写出一个「只有半组子键」的残缺分组。
        """
        group_specs = {}
        for key, spec in (schema or {}).items():
            if isinstance(spec, dict) and spec.get("type") == "object":
                items = spec.get("items")
                if isinstance(items, dict):
                    group_specs[key] = items

        for path, value in writes.items():
            if "." in path:
                group_key, sub_key = path.split(".", 1)
                group = merged.get(group_key)
                group = dict(group) if isinstance(group, dict) else {}
                for name, sub_spec in group_specs.get(group_key, {}).items():
                    if name not in group and isinstance(sub_spec, dict) and "default" in sub_spec:
                        group[name] = copy.deepcopy(sub_spec["default"])
                group[sub_key] = value
                merged[group_key] = group
            else:
                merged[path] = value
        return merged

    # ---------- 落盘与热生效 ----------

    async def _persist(self, merged: dict) -> bool:
        """把完整配置写回 AstrBot 的唯一配置对象（异步落盘，不阻塞事件循环）。"""
        cfg = self.plugin.config
        saver = getattr(cfg, "save_config_async", None)
        if callable(saver):
            try:
                committed = await saver(replace_config=merged, indent=2)
            except Exception as exc:
                self.plugin.logger.warning(
                    "[华为健康] 配置落盘失败：%s" % redact_error(exc))
                return False
            # 返回 False 表示有更新的快照已经提交（并发覆盖），本次不生效。
            return committed is not False
        # 测试桩 / 极简 dict 配置没有落盘能力：只更新内存。真实 AstrBot 不会走到这里。
        try:
            cfg.update(merged)
        except Exception:
            return False
        self.plugin.logger.warning(
            "[华为健康] 当前配置对象不支持 save_config_async，仅更新内存")
        return True

    async def _apply_hot_effects(self, merged: dict, changed) -> None:
        """Apply local consumers after persistence; query epochs are handled by the transaction."""
        p = self.plugin
        changed = set(changed)

        # 1) login_daily_limit：__init__ 里缓存进了 login_manager，保存后必须重设。
        if "login_daily_limit" in changed:
            try:
                limit = int(merged.get("login_daily_limit"))
                # 走 set_daily_limit：内部保留 1~10 的钳制，同时把新值写回
                # login_config.json。只改内存的话，下次启动会被磁盘上的旧值盖掉，
                # 配置页和实际生效值就会出现「3 / 10」这种不一致。
                p.login_manager.set_daily_limit(limit)
            except Exception as exc:
                p.logger.warning(
                    "[华为健康] 重设每日登录额度失败：%s" % redact_error(exc))

        # 2) 权限组：_umo_whitelist 是缓存，改完必须重建，否则判定还用旧白名单。
        if any(path.startswith(PERMISSION_SECTION + ".") for path in changed):
            try:
                p._build_umo_whitelist()
            except Exception as exc:
                p.logger.warning(
                    "[华为健康] 重建会话白名单失败：%s" % redact_error(exc))

        # 3) warmup：initialize() 只起过一次任务，开关变化要手动起/停。
        if "warmup" in changed:
            wanted = _as_bool(merged.get("warmup"), True)
            task = getattr(p, "_warmup_task", None)
            running = task is not None and not task.done()
            try:
                if wanted and not running:
                    p._warmup_task = asyncio.create_task(p._warmup())
                    p.logger.info("[华为健康] 配置开启预热，已起后台任务")
                elif not wanted and running:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                    except Exception:
                        pass
                    p.logger.info("[华为健康] 配置关闭预热，已停止后台任务")
            except Exception as exc:
                p.logger.warning(
                    "[华为健康] 应用预热开关失败：%s" % redact_error(exc))

    def _config_payload(self, applied, changed, clamped, message: str) -> dict:
        """成功响应：顶层给派活单要求的字面字段，data 里给前端 unwrap() 用的同一份。"""
        values = self._read_values()
        data = {
            "applied": list(applied),
            "reloaded": [],
            "revision": self._config_revision(),
            "changed": list(changed),
            "clamped": dict(clamped),
            "values": self._mask(values),
            "meta": self._meta(values),
        }
        payload = dict(data)
        payload["status"] = "ok"
        payload["message"] = message
        payload["data"] = data
        return payload

    # ---------- 接口 ----------

    async def get_config(self):
        """GET /page/config：当前值（敏感项掩码）+ 原样 schema + 版本戳。"""
        def snapshot():
            values = self._read_values()
            return {"status": "ok", "data": {
                "values": self._mask(values),
                "schema": _load_schema(),
                "meta": self._meta(values),
            }}
        async with self._config_lock:
            return json_response(await asyncio.to_thread(snapshot))

    async def post_config(self):
        """POST /page/config：白名单 + 类型校验 + UMO 校验 + 并发防护 + 落盘 + 热生效。"""
        try:
            body = await request.json()
        except Exception:
            return json_response(
                {"status": "error", "message": "请求体不是合法 JSON", "field": ""},
                status_code=400)
        if not isinstance(body, dict):
            return json_response(
                {"status": "error", "message": "请求体必须是 JSON 对象", "field": ""},
                status_code=400)

        leaves = _schema_leaves(_load_schema())

        # 第 1 步：纯校验。非法值永远先于 revision 被拒，保证「填错就 400」的确定性。
        try:
            writes, clamped, accepted = self._validate_patch(body.get("values"), leaves)
        except ConfigValueError as exc:
            return json_response(
                {"status": "error", "message": exc.message, "field": exc.field},
                status_code=400)

        # The revision check and the complete write must share one async lock.
        # A framework save revision alone cannot undo prior Cookie side effects.
        async with self._config_lock:
            return await self._post_config_locked(body, writes, clamped, accepted)

    async def _post_config_locked(self, body, writes, clamped, accepted):
        p = self.plugin
        # 第 2 步：并发覆盖防护。
        current_revision = self._config_revision()
        expected = body.get("revision")
        if not isinstance(expected, str) or expected != current_revision:
            return json_response({
                "status": "error",
                "message": "配置已被其他页面修改，请刷新后重试",
                "field": "revision",
            }, status_code=409)

        # 第 3 步：算出真正的变更集（值没变的项不写盘、不触发副作用）。
        cfg = p.config
        before = copy.deepcopy(dict(cfg)) if isinstance(cfg, dict) else {}
        merged = self._apply_writes(copy.deepcopy(before), writes, _load_schema())
        changed = [
            path for path in accepted
            if (_get_path(merged, path) != _get_path(before, path) or
                (path in SENSITIVE_KEYS and bool(str(writes[path]).strip())))
        ]

        if not changed:
            # 值没变：不落盘、不触发副作用。applied 也不该报，否则前端会以为改了东西。
            return json_response(await asyncio.to_thread(
                self._config_payload, [], [], clamped, "配置无变化，未写入"))

        # Sensitive fields are a write-only secure-import form. Never merge an
        # old account's Cookie/config into this request, or persist new secrets
        # in AstrBot's ordinary JSON config.
        cookie_touched = any(path in SENSITIVE_KEYS for path in changed)
        cookie_field = next((path for path in changed if path in SENSITIVE_KEYS), "cookie_json")
        raw_json, fields = "", {}
        if cookie_touched:
            try:
                raw_json = writes.get("cookie_json", "")
                fields = {
                    name: writes.get("cookie_" + name, "")
                    for name, _, _ in MIN_COOKIE_SPECS
                }
                incoming = parse_cookie_input(raw_json) + cookies_from_fields(fields)
                names = {cookie.get("name") for cookie in incoming
                         if str(cookie.get("value") or "").strip()}
                if any(name not in names for name in REQUIRED_COOKIES):
                    raise ConfigValueError(cookie_field,
                        "Cookie 修改需本次同时提供 CASTGC 和 sid，或包含二者的完整 JSON；"
                        "不会沿用旧账号字段。清除请使用 Cookie 清除入口")
            except Exception as exc:
                return json_response({
                    "status": "error",
                    "message": "cookie 导入失败：%s" % redact_error(exc),
                    "field": cookie_field,
                }, status_code=400)
            for key in SENSITIVE_KEYS:
                merged[key] = ""

        imported = False

        def import_cookies():
            nonlocal imported
            # No fingerprint shortcut: an unchanged legacy JSON file must still
            # be encrypted before its config copy is removed.
            result = p.auth.import_cookie_sources(raw_json, fields, replace_existing=True)
            imported = True
            return result

        async def finalize(_result=None):
            if not await self._persist(merged):
                raise ConfigPersistError("配置保存失败")
            await self._apply_hot_effects(merged, changed)

        query_settings = {
            "client_id", "api_version", "timezone", "token_ttl", "data_ttl",
            "browser_path", "headless", "page_timeout",
        }

        def check_current():
            if self._config_revision() != expected:
                raise ConfigRevisionError()

        try:
            if cookie_touched or query_settings.intersection(changed):
                # The plugin keeps its fail-closed state across async persistence,
                # without holding a thread lock across await. This also invalidates
                # inflight work produced with an old timezone/client/TTL setting.
                await p._change_auth_state_async(
                    import_cookies if cookie_touched else None, finalize,
                    check_current=check_current)
            else:
                await finalize()
        except ConfigRevisionError:
            return json_response({"status": "error",
                                  "message": "登录状态或配置已变化，请刷新后重试",
                                  "field": "revision"}, status_code=409)
        except ConfigPersistError:
            message = ("Cookie 已安全更新，但配置副本清理保存失败；查询已暂停，"
                       "请重新提交完整 Cookie 后重试" if imported else "配置保存失败")
            return json_response({"status": "error", "message": message, "field": ""},
                                 status_code=500)
        except Exception as exc:
            message = ("Cookie 已安全更新，但配置更新未完成；查询已暂停，请重试"
                       if imported else "配置更新失败：%s" % redact_error(exc))
            return json_response({"status": "error", "message": message,
                                  "field": cookie_field if cookie_touched else ""},
                                 status_code=400 if cookie_touched and not imported else 500)

        # 契约：applied 只统计「真的写下去并已生效」的项，值没变的不算（那属于 changed 为空）。
        applied = changed
        message = "已生效 %d 项" % len(applied)
        if clamped:
            message += "（其中 %d 项已按上下限调整）" % len(clamped)
        p.logger.info("[华为健康] WebUI 保存配置：已生效 %s" % ", ".join(applied))
        return json_response(await asyncio.to_thread(
            self._config_payload, applied, changed, clamped, message))

