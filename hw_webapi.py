# -*- coding: utf-8 -*-
"""华为运动健康 · 插件 WebUI 后端 API

页面位于 pages/health_console/，由 AstrBot 的 PluginPageService 自动挂载。
前端通过 bridge（window.AstrBotPluginPage）调用本模块注册的接口，
route 前缀：astrbot_plugin_Tricy_huawei_health/page/...
"""

import asyncio
import os
import time

from astrbot.api.web import json_response, request

try:
    from .hw_login import LoginFlowError
    from .hw_credentials import CredentialsError, DPAPIUnavailableError
    from .hw_privacy import redact_error
except ImportError:
    from hw_login import LoginFlowError
    from hw_credentials import CredentialsError, DPAPIUnavailableError
    from hw_privacy import redact_error

PAGE_PREFIX = "astrbot_plugin_Tricy_huawei_health/page"

#: cookie 里最关键的几个（决定「信任设备」是否还在）。
#: v0.4.1：与 hw_auth.MIN_COOKIE_SPECS 统一——v0.4.0 这里列了两个永远配不出来的名字
#: （HUAWEI_ID_CAS_ISCASLOGIN / __uni__uid），而 CASLOGINSITE / LOGINACCSITE 配了却
#: 永远显示不出来。
try:
    from .hw_auth import MIN_COOKIE_SPECS
except ImportError:
    from hw_auth import MIN_COOKIE_SPECS

KEY_COOKIES = tuple(name for name, _, _ in MIN_COOKIE_SPECS)


class HuaweiHealthWebApi:
    def __init__(self, plugin):
        self.plugin = plugin

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
            path = find_browser((p.config.get("browser_path") or "").strip())
        except Exception:
            path = ""
        return {"path": path, "found": bool(path)}

    # ---------- 接口 ----------

    async def get_status(self):
        p = self.plugin
        manager = getattr(p, "login_manager", None)
        data = {
            # 页面状态版本与插件元数据统一，避免前端误判部署版本。
            "version": "v0.4.2",
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
        }

        # cookie
        cf = p.cookie_file
        cinfo = {"exists": os.path.exists(cf), "count": 0, "mtime": "-", "keys": [], "error": ""}
        if cinfo["exists"]:
            try:
                cookies = p.auth.load_cookies()
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
        tok = p.store.get("token") or {}
        left = 0
        if tok.get("expire_at"):
            left = int(tok["expire_at"] - time.time())
        data["token"] = {
            "cached": bool(tok.get("token")),
            "left": max(0, left),
            "obtained_at": tok.get("obtained_at") or "-",
        }

        # 缓存
        try:
            keys = p.store.keys()
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
        items = await p._overview_items()
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
        text = (body.get("json") or "").strip()
        fields = body.get("fields") if isinstance(body.get("fields"), dict) else {}
        if not text and not any(str(v or "").strip() for v in fields.values()):
            return json_response({"status": "error", "message": "cookie 内容为空"},
                                 status_code=400)
        try:
            # v0.4.1：与磁盘上已有的 cookie 合并 + 补齐 CASTGC 两条路径 + 缺关键项直接报错。
            n = p.auth.import_cookie_sources(text, fields)
        except Exception as exc:
            return json_response(
                {"status": "error", "message": redact_error(exc)}, status_code=400)
        # 换 cookie 时清除 token 及全部健康缓存，避免跨账号泄露旧数据。
        await p._invalidate_auth_cache()
        p.logger.info("[华为健康] WebUI 导入了 %d 条 cookie" % n)
        return json_response({
            "status": "ok",
            "message": "已导入 %d 条 cookie（已与现有 cookie 合并），token 缓存已作废，下次查询会重新认证" % n,
            "count": n,
        })

    async def clear_cookie(self):
        p = self.plugin
        try:
            # 通过认证层的共享锁清除，避免与浏览器回写并发时旧 cookie 被恢复。
            p.auth.clear_cookies()
        except Exception as exc:
            return json_response(
                {"status": "error", "message": redact_error(exc)}, status_code=500)
        await p._invalidate_auth_cache()
        p.logger.warning("[华为健康] WebUI 清除了 cookie 文件")
        return json_response({"status": "ok", "message": "cookie 已清除，token 缓存已作废"})

    async def refresh(self):
        p = self.plugin
        try:
            # 统一推进缓存 generation，防止并发旧请求在刷新后写回。
            await p._invalidate_auth_cache()
        except Exception:
            pass
        try:
            await p._token(force=True)
        except Exception as exc:
            return json_response({"status": "error", "message": p._err(exc)}, status_code=500)
        return json_response({"status": "ok", "message": "缓存已清空，并已重新拿到最新 token"})

    # ---------- 账号凭据（v0.4.0 第 3 阶段：DPAPI，只写接口） ----------

    def _credentials_status_data(self):
        store = getattr(self.plugin, "credentials", None)
        raw = store.status() if store is not None else {}
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
            # v0.4.1：区分「没保存 / 已保存 / 损坏 / 被占用 / 不支持 DPAPI」，
            # 不再把损坏的文件谎报成「未保存」。
            "state": str(raw.get("state") or "absent"),
            "error": str(raw.get("error") or ""),
            "available": bool(getattr(store, "available", False)) if store is not None else False,
        }

    async def credentials_status(self):
        return json_response({"status": "ok", "data": self._credentials_status_data()})

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
            try:
                store.clear()
                self.plugin.login_manager.set_login_mode("cookie")
                try:
                    self.plugin.login_manager.clear_cooldown()
                except Exception:
                    pass
            except (CredentialsError, LoginFlowError):
                return json_response({"status": "error", "message": "凭据清除失败，请稍后重试"}, status_code=500)
            return json_response({
                "status": "ok", "data": self._credentials_status_data(), "message": "账号密码凭据已清除",
            })

        account = body.get("account")
        password = body.get("password")
        if mode not in ("", "password") or not isinstance(account, str) or not isinstance(password, str):
            return json_response({"status": "error", "message": "请输入账号和密码"}, status_code=400)
        if not account.strip() or not password or len(account) > 150 or len(password) > 512:
            return json_response({"status": "error", "message": "请输入有效的账号和密码"}, status_code=400)
        if not store.available:
            return json_response({
                "status": "error", "message": "当前系统不支持 DPAPI，账号密码登录未启用",
            }, status_code=409)
        try:
            store.save(account, password)
            self.plugin.login_manager.set_login_mode("password")
            # 用户刚把密码改对：把 6 小时失败冷却立刻清掉，否则提示会自相矛盾
            # （「请重新保存账号密码」→ 保存完 → 「冷却中，请稍后再试」）。
            try:
                self.plugin.login_manager.clear_cooldown()
            except Exception:
                pass
        except DPAPIUnavailableError:
            return json_response({
                "status": "error", "message": "当前系统不支持 DPAPI，账号密码登录未启用",
            }, status_code=409)
        except CredentialsError:
            return json_response({"status": "error", "message": "凭据保存失败，请稍后重试"}, status_code=500)
        finally:
            # Do not retain request fields after the write path returns.
            account = None
            password = None
        return json_response({
            "status": "ok", "data": self._credentials_status_data(), "message": "账号密码已加密保存",
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
            # 用户在 WebUI 主动点「开始登录」不占用每日自动登录额度，
            # 只有取数路径触发的自动登录才计入额度与失败冷却。
            # manager.start() 里有文件 fsync + DPAPI 解密，别在事件循环线程上跑。
            await asyncio.to_thread(
                p.login_manager.start,
                mode,
                auto_trust=auto_trust,
                allow_visible_fallback=allow_visible_fallback,
                manual=True,
                prefer_auto=prefer_auto,
            )
        except LoginFlowError as exc:
            message = {
                "trust_invalid": "自动信任选项无效",
                "fallback_invalid": "可见窗口兜底选项无效",
                "prefer_invalid": "无头自动登录选项无效",
                "credentials_missing": "尚未保存账号密码，请先在凭据区保存",
                "credentials_unavailable": "当前系统不支持安全凭据登录，请使用 Cookie 模式",
                "credentials_corrupt": "账号密码凭据已损坏，请在凭据区重新保存",
                "credentials_locked": "账号密码凭据被占用或无权读取，请稍后重试",
                "daily_limit": "今日自动登录失败次数已达上限，请稍后再试",
                "cooldown": "自动登录失败冷却中，请稍后再试",
                "unsupported": "登录模式无效",
            }.get(exc.code, "登录启动失败，请稍后重试")
            status = 429 if exc.code in ("daily_limit", "cooldown") else 409
            return json_response({
                "status": "error",
                "message": message,
            }, status_code=status)
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
