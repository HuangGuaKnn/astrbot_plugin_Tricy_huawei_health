# -*- coding: utf-8 -*-
"""华为运动健康 · 插件 WebUI 后端 API

页面位于 pages/health_console/，由 AstrBot 的 PluginPageService 自动挂载。
前端通过 bridge（window.AstrBotPluginPage）调用本模块注册的接口，
route 前缀：astrbot_plugin_huawei_health/page/...
"""

import asyncio
import os
import time

from astrbot.api.web import json_response, request

try:
    from .hw_login import LoginFlowError
    from .hw_credentials import CredentialsError, DPAPIUnavailableError
except ImportError:
    from hw_login import LoginFlowError
    from hw_credentials import CredentialsError, DPAPIUnavailableError

PAGE_PREFIX = "astrbot_plugin_huawei_health/page"

#: cookie 里最关键的几个（决定「信任设备」是否还在）
KEY_COOKIES = (
    "sid", "hwid_cas_sid", "CASTGC", "HuaweiID_CAS_ISCASLOGIN",
    "HUAWEI_ID_CAS_ISCASLOGIN", "__uni__uid",
)


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
        reg(f"{PAGE_PREFIX}/login/account", self.login_account, ["POST"], "提交网页登录账号")
        reg(f"{PAGE_PREFIX}/login/sms", self.login_sms, ["POST"], "提交网页登录验证码")
        reg(f"{PAGE_PREFIX}/login/trust", self.login_trust, ["POST"], "提交网页登录信任选择")
        reg(f"{PAGE_PREFIX}/login/cancel", self.login_cancel, ["POST"], "取消网页登录")
        reg(f"{PAGE_PREFIX}/credentials", self.credentials_write, ["POST"], "保存账号密码凭据")
        reg(f"{PAGE_PREFIX}/credentials/status", self.credentials_status, ["GET"], "账号密码凭据状态")

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
        data = {
            # 页面状态版本与插件元数据统一，避免前端误判部署版本。
            "version": "v0.4.0",
            "data_dir": p.data_dir,
            "cookie_file": p.cookie_file,
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
                            "expires": self._fmt_ts(c.get("expires")),
                        })
            except Exception as exc:
                cinfo["error"] = str(exc)
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
        """把所有已接入的数据项一次拉齐，给 WebUI 的「概览窗口」用。"""
        p = self.plugin
        async def add(key, title, producer, ttl=600):
            try:
                text = await p._cached("ov:%s" % key, producer, ttl=ttl)
                return {"key": key, "title": title, "ok": True, "text": text}
            except Exception as exc:
                return {"key": key, "title": title, "ok": False, "text": p._err(exc)}

        def fmt_acts(acts):
            if not acts:
                return "最近 30 天没有运动记录"
            lines = ["最近 30 天共 %d 条：" % len(acts)]
            for a in acts[:5]:
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
                    when = time.strftime("%m-%d %H:%M", time.localtime(ms / 1000))
                except Exception:
                    when = str(ts)
                bits = [when]
                if v("activityType") is not None:
                    bits.append("类型%s" % v("activityType"))
                if v("distance"):
                    bits.append("距离%s" % v("distance"))
                if v("duration"):
                    bits.append("时长%s" % v("duration"))
                lines.append("  " + " ｜ ".join(str(b) for b in bits))
            return "\n".join(lines)

        # 最多同时请求 3 项，避免 WebUI 总览串行等待过久。
        sem = asyncio.Semaphore(3)
        async def limited(*args, **kwargs):
            async with sem:
                return await add(*args, **kwargs)
        # gather 按传入顺序返回，保证并发后页面卡片顺序与原串行版本一致。
        items = await asyncio.gather(
            limited("heart", "静息心率（近 7 天）", lambda c: p._metric_text(c.resting_heart_rate(7), "bpm", 7, "静息心率", count_label="天")),
            limited("sleep", "睡眠（近 7 晚）", lambda c: p._sleep_text(c.sleep_records(7), 7)),
            limited("hrv", "睡眠 HRV", lambda c: p._metric_text(c.hrv_stats(7), "", 7, "HRV")),
            limited("stress", "压力（近 7 天）", lambda c: p._metric_text(c.stress_stats(7), "", 7, "压力")),
            limited("weight", "体重", lambda c: p._fmt_weight(c.body_weight(1095))),
            limited("zones", "心率区间（储备心率）", lambda c: p._fmt_zones(c.heart_rate_zones())),
            limited("perf", "运动能力与预测成绩", lambda c: p._fmt_perf(c.athletic_performance()), ttl=3600),
            limited("pb", "个人纪录", lambda c: p._fmt_pb(c.personal_bests("running")), ttl=3600),
            limited("acts", "近期运动", lambda c: fmt_acts(c.activities(30, 5))),
        )

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
            n = p.auth.import_cookie_sources(text, fields)
        except Exception as exc:
            return json_response({"status": "error", "message": str(exc)}, status_code=400)
        # 换 cookie 时清除 token 及全部健康缓存，避免跨账号泄露旧数据。
        await p._invalidate_auth_cache()
        p.logger.info("[华为健康] WebUI 导入了 %d 条 cookie" % n)
        return json_response({
            "status": "ok",
            "message": "已导入 %d 条 cookie，token 缓存已作废，下次查询会重新认证" % n,
            "count": n,
        })

    async def clear_cookie(self):
        p = self.plugin
        try:
            # 通过认证层的共享锁清除，避免与浏览器回写并发时旧 cookie 被恢复。
            p.auth.clear_cookies()
        except Exception as exc:
            return json_response({"status": "error", "message": str(exc)}, status_code=500)
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
        try:
            data = p.login_manager.start(
                mode, auto_trust=auto_trust, allow_visible_fallback=allow_visible_fallback,
            )
        except LoginFlowError as exc:
            message = {
                "trust_invalid": "自动信任选项无效",
                "fallback_invalid": "可见窗口兜底选项无效",
                "credentials_missing": "尚未保存账号密码，请先在凭据区保存",
                "credentials_unavailable": "当前系统不支持安全凭据登录，请使用 Cookie 模式",
                "daily_limit": "今日自动登录次数已达上限，请稍后再试",
                "cooldown": "自动登录失败冷却中，请稍后再试",
                "unsupported": "登录模式无效",
            }.get(exc.code, "登录启动失败，请稍后重试")
            status = 429 if exc.code in ("daily_limit", "cooldown") else 409
            return json_response({
                "status": "error",
                "message": message,
            }, status_code=status)
        return json_response({"status": "ok", "data": data})

    async def login_status(self):
        return json_response({"status": "ok", "data": self.plugin.login_manager.status()})

    async def login_account(self):
        # 账号密码暂不经过插件接口；第 1 阶段统一在可见浏览器窗口内输入。
        return json_response({
            "status": "error",
            "message": "当前阶段请在已打开的浏览器窗口中输入账号和密码",
        }, status_code=409)

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
                "sms_invalid": "验证码必须是 6 位数字",
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
