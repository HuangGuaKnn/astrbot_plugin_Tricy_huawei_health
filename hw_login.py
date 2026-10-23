# -*- coding: utf-8 -*-
"""华为运动健康 WebUI 登录会话（v0.4.0 第 2 阶段）。

当前仍使用路线 A 的可见浏览器，账号密码在窗口内输入；验证码可从 WebUI
提交，信任设备支持自动选择或 WebUI 手动选择。插件只负责观察会话、收取最终
cookie 并写入现有的 ``hw_cookies.json``。账号密码和验证码不会进入日志或状态响应。
"""

import json
import os
import queue
import re
import subprocess
import threading
import time
import urllib.request

try:
    from .hw_auth import (
        HuaweiAuth,
        TRAINING_CAMP_URL,
        find_browser,
        free_port,
        normalize_cookie,
    )
except ImportError:
    from hw_auth import (
        HuaweiAuth,
        TRAINING_CAMP_URL,
        find_browser,
        free_port,
        normalize_cookie,
    )


LOGIN_STATES = {
    "IDLE", "LAUNCHING", "NEED_CRED", "SUBMITTING", "NEED_SMS",
    "NEED_TRUST", "FINALIZING", "DONE", "FAILED",
}

STATE_DEADLINES = {
    "LAUNCHING": 90,
    "NEED_CRED": 300,
    "SUBMITTING": 90,
    "NEED_SMS": 300,
    "NEED_TRUST": 120,
    "FINALIZING": 90,
}

STATE_MESSAGES = {
    "IDLE": "尚未开始登录",
    "LAUNCHING": "正在启动可见浏览器…",
    "NEED_CRED": "浏览器已打开，请在窗口中完成华为账号登录",
    "SUBMITTING": "正在等待华为页面完成登录…",
    "NEED_SMS": "请在浏览器窗口中输入手机验证码",
    "NEED_TRUST": "请在浏览器窗口中选择是否信任此浏览器",
    "FINALIZING": "登录成功，正在保存会话…",
    "DONE": "登录成功，Cookie 已写入插件",
    "FAILED": "登录失败或已取消，请稍后重试",
}


class LoginFlowError(Exception):
    """内部流程错误；对外只暴露固定的脱敏文案。"""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class HuaweiLoginSession:
    """单个可见浏览器登录会话。所有 CDP 操作都在后台线程内串行执行。"""

    def __init__(self, manager, mode: str = "manual"):
        self.manager = manager
        self.plugin = manager.plugin
        self.mode = mode
        self.auto_trust = bool(manager.auto_trust)
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._wake = threading.Event()
        self._actions = queue.Queue()
        self._pending_action = ""
        self._sms_action_sent = False
        self._trust_action_sent = False
        self._state = "IDLE"
        self._message = STATE_MESSAGES["IDLE"]
        self._deadline = 0.0
        self._updated_at = time.time()
        self._thread = None
        self._proc = None
        self._ws = None
        self._auth = None
        self._profile_dir = os.path.join(self.plugin.data_dir, "login_browser_profile")

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._set_state("LAUNCHING")
            self._thread = threading.Thread(
                target=self._run,
                name="huawei-health-login",
                daemon=True,
            )
            self._thread.start()

    def cancel(self):
        self._cancel.set()
        self._wake.set()
        with self._lock:
            if self._state not in ("DONE", "FAILED"):
                self._set_state("FAILED", "登录已取消")

    def snapshot(self) -> dict:
        with self._lock:
            left = max(0, int(self._deadline - time.time())) if self._deadline else 0
            state = self._state
            return {
                "state": state,
                "mode": self.mode,
                "auto_trust": self.auto_trust,
                "message": self._message,
                "deadline_left": left,
                "need": {
                    "account": state == "NEED_CRED",
                    "sms": state == "NEED_SMS",
                    "trust": state == "NEED_TRUST",
                },
                "updated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._updated_at)),
            }

    def join(self, timeout: float = 5.0):
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=max(0.0, float(timeout)))

    def _set_state(self, state: str, message: str = ""):
        if state not in LOGIN_STATES:
            state = "FAILED"
        self._state = state
        self._message = message or STATE_MESSAGES.get(state, STATE_MESSAGES["FAILED"])
        self._deadline = time.time() + STATE_DEADLINES.get(state, 0)
        self._updated_at = time.time()

    def _fail(self, code: str = "failed"):
        messages = {
            "browser": "找不到可用浏览器，请检查浏览器路径",
            "launch": "浏览器启动失败，请稍后重试",
            "timeout": "登录等待超时，请重新开始",
            "closed": "浏览器已关闭，登录未完成",
            "cookie": "登录完成但未拿到有效会话，请重试",
            "unsupported": "当前阶段只支持在浏览器窗口中手动完成登录",
            "failed": STATE_MESSAGES["FAILED"],
        }
        message = messages.get(code, messages["failed"])
        with self._lock:
            self._set_state("FAILED", message)
        try:
            self.plugin.logger.warning("[华为健康登录] " + message)
        except Exception:
            pass

    def _run(self):
        try:
            if self.mode != "manual":
                raise LoginFlowError("unsupported")
            self._launch()
            if self._cancel.is_set():
                return
            with self._lock:
                self._set_state("NEED_CRED")
            self._wait_for_completion()
        except LoginFlowError as exc:
            if not self._cancel.is_set():
                self._fail(exc.code)
        except Exception:
            if not self._cancel.is_set():
                self._fail("failed")
        finally:
            self._cleanup()

    def _launch(self):
        browser_path = find_browser((self.plugin.config.get("browser_path") or "").strip())
        if not browser_path:
            raise LoginFlowError("browser")
        os.makedirs(self._profile_dir, exist_ok=True)
        self._auth = HuaweiAuth(
            cookie_file=self.plugin.cookie_file,
            profile_dir=self._profile_dir,
            browser_path=browser_path,
            headless=False,
            page_timeout=self.plugin.config.get("page_timeout", 90),
            logger=self.plugin.logger,
        )
        self._auth._cleanup_orphan_browsers()
        port = free_port()
        args = [
            browser_path,
            "--remote-debugging-port=%d" % port,
            "--user-data-dir=" + self._profile_dir,
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-blink-features=AutomationControlled",
            "about:blank",
        ]
        kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        }
        if os.name != "nt":
            kwargs["start_new_session"] = True
        try:
            self._proc = subprocess.Popen(args, **kwargs)
            self._wait_cdp_cancelable(port, timeout=90)
            self._ws = self._auth._attach(port)
            self._auth._call(self._ws, "Network.enable")
            self._auth._call(self._ws, "Page.enable")
            self._auth._call(self._ws, "Runtime.enable")
            self._auth._call(self._ws, "Page.navigate", {"url": TRAINING_CAMP_URL})
            try:
                self._auth._js(self._ws, self._login_click_script())
            except Exception:
                pass
        except Exception as exc:
            raise LoginFlowError("launch") from exc

    def _wait_cdp_cancelable(self, port: int, timeout: float):
        deadline = time.monotonic() + min(float(timeout), self._auth.page_timeout)
        while time.monotonic() < deadline:
            if self._cancel.is_set():
                raise LoginFlowError("cancelled")
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:%d/json/version" % port,
                    timeout=min(2, max(1, self._auth.page_timeout)),
                ) as response:
                    json.load(response)
                    return
            except Exception:
                time.sleep(0.25)
        raise LoginFlowError("launch")

    @staticmethod
    def _login_click_script() -> str:
        return (
            "(()=>{const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
            "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
            "const b=document.querySelector('button.login-button');"
            "if(b&&visible(b)){b.click();return 'clicked';}return 'notfound';})()"
        )

    def _wait_for_completion(self):
        while not self._cancel.is_set():
            self._process_action()
            with self._lock:
                deadline = self._deadline
            if deadline and time.time() >= deadline:
                raise LoginFlowError("timeout")
            try:
                token = self._auth._js(self._ws, "sessionStorage.getItem('accessToken')")
            except Exception:
                if self._proc is not None and self._proc.poll() is not None:
                    raise LoginFlowError("closed")
                token = None
            if token:
                self._finish(token)
                return
            self._update_page_state()
            self._wake.wait(1)
            self._wake.clear()

    def submit_sms(self, code: str) -> dict:
        code = str(code or "").strip()
        if not re.fullmatch(r"\d{6}", code):
            raise LoginFlowError("sms_invalid")
        with self._lock:
            if self._state != "NEED_SMS":
                raise LoginFlowError("sms_unavailable")
        if not self._enqueue_action("sms", code):
            raise LoginFlowError("sms_busy")
        return self.snapshot()

    def submit_trust(self, choice: str) -> dict:
        choice = str(choice or "").strip().lower()
        if choice not in ("true", "false", "later"):
            raise LoginFlowError("trust_invalid")
        with self._lock:
            if self._state != "NEED_TRUST":
                raise LoginFlowError("trust_unavailable")
        if not self._enqueue_action("trust", choice):
            raise LoginFlowError("trust_busy")
        return self.snapshot()

    def _enqueue_action(self, kind: str, payload: str) -> bool:
        with self._lock:
            if self._pending_action:
                return False
            self._pending_action = kind
            self._actions.put((kind, payload))
            self._wake.set()
            return True

    def _process_action(self):
        try:
            kind, payload = self._actions.get_nowait()
        except queue.Empty:
            return
        with self._lock:
            self._pending_action = ""
        try:
            if kind == "sms":
                result = self._auth._js(self._ws, self._sms_submit_script(payload))
            elif kind == "trust":
                result = self._auth._js(self._ws, self._trust_submit_script(payload))
            else:
                return
        except Exception:
            result = "error"
        if kind == "sms":
            if result not in ("submitted", "filled"):
                self._sms_action_sent = False
                with self._lock:
                    self._set_state("NEED_SMS", "验证码输入框尚未准备好，请稍后重试")
            else:
                self._sms_action_sent = True
                with self._lock:
                    self._set_state("SUBMITTING")
        elif kind == "trust":
            if result != "clicked":
                self._trust_action_sent = False
                with self._lock:
                    self._set_state("NEED_TRUST", "信任选择窗口已变化，请重新选择")
            else:
                self._trust_action_sent = True
                with self._lock:
                    self._set_state("SUBMITTING")

    def _update_page_state(self):
        try:
            raw = self._auth._js(self._ws, self._page_state_script())
            info = json.loads(raw) if isinstance(raw, str) else {}
        except Exception:
            info = {}
        with self._lock:
            current = self._state
            if info.get("sms"):
                if info.get("sms_error"):
                    self._sms_action_sent = False
                    self._set_state("NEED_SMS", "验证码校验失败，请重新输入")
                elif current != "NEED_SMS" and not self._sms_action_sent:
                    self._set_state("NEED_SMS")
            elif info.get("trust"):
                if current == "NEED_TRUST":
                    return
                if self.auto_trust and not self._pending_action and not self._trust_action_sent:
                    self._pending_action = "trust"
                    self._actions.put(("trust", "true"))
                    self._set_state("SUBMITTING")
                    self._wake.set()
                elif not self.auto_trust and not self._trust_action_sent:
                    self._set_state("NEED_TRUST")
            elif current in ("NEED_SMS", "NEED_TRUST") and not info.get("sms") and not info.get("trust"):
                self._set_state("SUBMITTING")

    @staticmethod
    def _page_state_script() -> str:
        return (
            "(()=>{const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
            "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
            "const sms=[...document.querySelectorAll('input[type=tel]')].filter(visible).length>=6;"
            "const text=[...document.querySelectorAll('span.hwid-vertical-align,button')].filter(visible)"
            ".map(e=>(e.innerText||e.textContent||'').trim());"
            "const trust=text.some(t=>/信任此浏览器|信任该浏览器/.test(t));"
            "const body=(document.body&&document.body.innerText)||'';"
            "const sms_error=sms&&/验证码.{0,6}(错误|不正确|失败)|校验失败/.test(body);"
            "return JSON.stringify({sms,trust,sms_error});})()"
        )

    @staticmethod
    def _sms_submit_script(code: str) -> str:
        code_json = json.dumps(code, ensure_ascii=False)
        return (
            "(()=>{const code=%s;const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
            "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
            "const els=[...document.querySelectorAll('input[type=tel]')].filter(visible).slice(0,6);"
            "if(els.length<6)return 'missing';"
            "for(let i=0;i<6;i++){const e=els[i],d=Object.getOwnPropertyDescriptor(e.constructor.prototype,'value');"
            "if(!d||!d.set)return 'setter';d.set.call(e,code[i]);e.dispatchEvent(new Event('input',{bubbles:true}));}"
            "const btn=[...document.querySelectorAll('span.hwid-vertical-align,button')].filter(visible)"
            ".find(e=>/^(确定|确认|登录)$/.test((e.innerText||e.textContent||'').trim()));"
            "if(btn){btn.click();return 'submitted';}return 'filled';})()"
        ) % code_json

    @staticmethod
    def _trust_submit_script(choice: str) -> str:
        pattern = {
            "true": "^(?:信任此浏览器|信任该浏览器|信任)$",
            "false": "^(?:不信任)$",
            "later": "^(?:稍后再说)$",
        }[choice]
        return (
            "(()=>{const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
            "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
            "const els=[...document.querySelectorAll('span.hwid-vertical-align,button')].filter(visible);"
            "const btn=els.find(e=>/(%s)/.test((e.innerText||e.textContent||'').trim()));"
            "if(btn){btn.click();return 'clicked';}return 'missing';})()"
        ) % pattern

    def _finish(self, token: str):
        with self._lock:
            self._set_state("FINALIZING")
        try:
            result = self._auth._call(self._ws, "Network.getAllCookies")
            cookies = result.get("result", {}).get("cookies", [])
            cookies = [normalize_cookie(c) for c in cookies if isinstance(c, dict) and c.get("name")]
            if not cookies:
                raise LoginFlowError("cookie")
            if not self._auth.save_cookies(cookies):
                raise LoginFlowError("cookie")
            expire = self._auth._js(self._ws, "sessionStorage.getItem('expireTime')")
            try:
                self._auth.token_expire_at = float(expire) / (1000 if float(expire) > 10**11 else 1)
            except (TypeError, ValueError):
                self._auth.token_expire_at = time.time() + 3000
            self.plugin._clear_health_cache()
            now = time.time()
            ttl = int(self.plugin.config.get("token_ttl", 3000))
            expire_at = self._auth.token_expire_at - 30
            if expire_at <= now:
                expire_at = now + ttl
            elif ttl > 0:
                expire_at = min(expire_at, now + ttl)
            self.plugin.store.set("token", {
                "token": token,
                "expire_at": expire_at,
                "obtained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
        except LoginFlowError:
            raise
        except Exception as exc:
            raise LoginFlowError("cookie") from exc
        with self._lock:
            self._set_state("DONE")

    def _cleanup(self):
        # 取消或结束时丢弃尚未发送的验证码/信任选项，避免会话对象继续持有敏感输入。
        try:
            while True:
                self._actions.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            self._pending_action = ""
        try:
            if self._ws is not None:
                try:
                    self._auth._call(self._ws, "Browser.close", timeout=5)
                except Exception:
                    pass
                try:
                    self._ws.close()
                except Exception:
                    pass
        finally:
            if self._auth is not None:
                try:
                    self._auth._stop_process(self._proc)
                except Exception:
                    try:
                        self._auth._cleanup_orphan_browsers()
                    except Exception:
                        pass


class HuaweiLoginManager:
    """插件级单会话管理器，重复 start 不会另开浏览器。"""

    def __init__(self, plugin):
        self.plugin = plugin
        self._lock = threading.RLock()
        self._session = None
        self.login_config_path = os.path.join(plugin.data_dir, "login_config.json")
        self.login_mode = "cookie"
        self.auto_trust = True
        self._load_login_config()

    def _load_login_config(self):
        try:
            with open(self.login_config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                if data.get("mode") in ("cookie", "password"):
                    self.login_mode = data["mode"]
                if isinstance(data.get("auto_trust"), bool):
                    self.auto_trust = data["auto_trust"]
        except (OSError, ValueError, TypeError):
            pass

    def _save_login_config(self):
        data = {"mode": self.login_mode, "auto_trust": bool(self.auto_trust),
                "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        parent = os.path.dirname(self.login_config_path) or "."
        os.makedirs(parent, exist_ok=True)
        tmp = self.login_config_path + ".tmp.%d.%d" % (os.getpid(), threading.get_ident())
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.login_config_path)
        finally:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except OSError:
                pass

    def set_login_mode(self, mode: str):
        mode = str(mode or "").strip().lower()
        if mode not in ("cookie", "password"):
            raise LoginFlowError("mode_invalid")
        with self._lock:
            self.login_mode = mode
            self._save_login_config()

    def status(self) -> dict:
        with self._lock:
            if self._session is None:
                return {
                    "state": "IDLE",
                    "mode": "manual",
                    "auto_trust": self.auto_trust,
                    "message": STATE_MESSAGES["IDLE"],
                    "deadline_left": 0,
                    "need": {"account": False, "sms": False, "trust": False},
                    "updated_at": "-",
                }
            return self._session.snapshot()

    def start(self, mode: str = "manual", auto_trust=None) -> dict:
        mode = str(mode or "manual").strip().lower()
        if mode not in ("manual", "auto"):
            raise LoginFlowError("unsupported")
        if mode == "auto":
            raise LoginFlowError("unsupported")
        if auto_trust is not None:
            if not isinstance(auto_trust, bool):
                raise LoginFlowError("trust_invalid")
            self.auto_trust = auto_trust
            self._save_login_config()
        with self._lock:
            if self._session is not None:
                current = self._session.snapshot()
                if current["state"] not in ("DONE", "FAILED"):
                    return current
            session = HuaweiLoginSession(self, mode=mode)
            self._session = session
            session.start()
            return session.snapshot()

    def submit_sms(self, code: str) -> dict:
        with self._lock:
            session = self._session
        if session is None:
            raise LoginFlowError("sms_unavailable")
        return session.submit_sms(code)

    def submit_trust(self, choice: str) -> dict:
        with self._lock:
            session = self._session
        if session is None:
            raise LoginFlowError("trust_unavailable")
        return session.submit_trust(choice)

    def cancel(self) -> dict:
        with self._lock:
            session = self._session
        if session is not None:
            session.cancel()
            session.join(2)
        return self.status()

    def stop(self):
        with self._lock:
            session = self._session
        if session is not None:
            session.cancel()
            session.join(5)
