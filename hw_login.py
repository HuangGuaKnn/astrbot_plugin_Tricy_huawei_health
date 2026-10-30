# -*- coding: utf-8 -*-
"""华为运动健康 WebUI 登录会话（v0.4.1）。

默认仍使用 Cookie 模式；账号密码模式使用 DPAPI 凭据启动无头路线 B，遇到
验证码时复用 WebUI 半自动流程。自动登录失败且显式开启兜底时才打开可见窗口。
账号密码和验证码不会进入日志或状态响应。

v0.4.1 修复（对应检测报告 P0-1 / P0-2 / P1-2 / P1-3 / P1-4 / P1-5 / P1-6 / P1-7 /
P1-10 / P2-8 / P2-9 / P2-10 / P2-16）：
    - ``_set_state`` 不再为「只换文案」重置 deadline（v0.4.0 会让 NEED_SMS 永不超时）；
    - 验证码：``filled``（只填框没点提交）不再当成已提交；宽限期 8s → 30s；
      支持 4~8 位与单输入框；
    - 新增密码错误分支（``bad_credentials``）与「页面脚本读不到不改状态」；
    - 信任页要求「对话框特征」（同时出现 信任 + 不信任/稍后再说），误判后自动重试一次；
    - ``Thread.start()`` 失败不再留下永久 LAUNCHING；
    - 会话清理不再无条件按 profile 路径清扫（v0.4.0 会杀掉下一个会话刚起的浏览器）；
    - 降级链排除列表补 ``browser``/``cookie``/``bad_credentials`` 等，且保留真实错误码；
    - ``manual=True`` 不再写失败冷却；
    - 额度语义改为「每天允许的失败次数」，成功会归还名额；
    - ``login_config.json`` 加钳制、坏文件备份、未来时间戳清理；
    - 调试端口由浏览器自己挑（``--remote-debugging-port=0``）。
"""

import json
import math
import os
import queue
import re
import subprocess
import threading
import time

try:
    from .hw_auth import (
        HuaweiAuth,
        HuaweiAuthError,
        TRAINING_CAMP_URL,
        browser_launch_args,
        clear_devtools_port_file,
        compute_expire_at,
        find_browser,
        normalize_cookie,
        read_devtools_port,
    )
    from .hw_credentials import (
        CredentialsError,
        CredentialsCorruptError,
        CredentialsLockedError,
        DPAPIUnavailableError,
        harden_file_permissions,
    )
    from .hw_privacy import redact_error
except ImportError:
    from hw_auth import (
        HuaweiAuth,
        HuaweiAuthError,
        TRAINING_CAMP_URL,
        browser_launch_args,
        clear_devtools_port_file,
        compute_expire_at,
        find_browser,
        normalize_cookie,
        read_devtools_port,
    )
    from hw_credentials import (
        CredentialsError,
        CredentialsCorruptError,
        CredentialsLockedError,
        DPAPIUnavailableError,
        harden_file_permissions,
    )
    from hw_privacy import redact_error


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

LOGIN_DEFAULTS = {
    # 语义（v0.4.1 起）：每天允许的**失败**次数。成功登录会归还名额。
    "daily_limit": 3,
    "session_timeout": 300,
    "allow_visible_fallback": False,
}
FAILURE_COOLDOWN = 6 * 60 * 60
#: 提交验证码后，若验证码页仍在超过该秒数，视为华为已重发新码，重新开放输入。
#: v0.4.0 是 8 秒，比华为正常校验耗时（10~20 秒）还短，正常提交会被误判成「码失效」。
SMS_RETRY_GRACE = 30.0
#: 点过「信任」但信任页仍在：超过该秒数重试一次，再失败就让用户手动选。
TRUST_RETRY_GRACE = 12.0
#: 会话总时长硬上限 = max(300, session_timeout * 该系数)。
#: 各状态的 deadline 会被重试续期，这个上限兜底，防止会话无限期挂着。
SESSION_HARD_CAP_FACTOR = 3

#: 走可见浏览器兜底没有意义的错误码（重开浏览器不可能解决）。
_FALLBACK_SKIP = (
    "credentials_missing", "credentials_unavailable", "credentials_corrupt",
    "credentials_locked", "cancelled", "unsupported", "browser", "cookie",
    "bad_credentials", "wronghost",
)

#: 不该写 6 小时失败冷却的错误码：这些都是「用户马上能自己修好」或「风控无关」的失败。
#: 写冷却会让提示自相矛盾（「请重新保存账号密码」→ 保存完 → 「冷却中，请稍后再试」）。
_COOLDOWN_SKIP = (
    "browser", "cookie", "bad_credentials", "wronghost", "cancelled", "unsupported",
    "credentials_missing", "credentials_unavailable", "credentials_corrupt",
    "credentials_locked", "credentials_page",
)

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
    """单个浏览器登录会话；自动模式与人工模式共用验证码/信任状态机。"""

    def __init__(self, manager, mode: str = "manual", manual: bool = False):
        self.manager = manager
        self.plugin = manager.plugin
        self.mode = mode
        self.manual = bool(manual)
        self.auto_trust = bool(manager.auto_trust)
        self._auto_attempted = mode == "auto"
        self._fallback_used = False
        self._headless = mode == "auto"
        self._session_timeout = max(60, int(getattr(manager, "session_timeout", 300)))
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._wake = threading.Event()
        self._actions = queue.Queue()
        self._pending_action = ""
        self._sms_action_sent = False
        self._sms_action_at = 0.0
        self._trust_action_sent = False
        self._trust_action_at = 0.0
        self._trust_retries = 0
        self._trust_last_choice = ""
        self._credentials_submitted = False
        #: 本次会话是否真的在闸门里记过一笔（manual=True 不记账，成功时也就不能归还）。
        self._attempt_recorded = False
        self._state = "IDLE"
        self._message = STATE_MESSAGES["IDLE"]
        self._deadline = 0.0
        self._started_at = time.time()
        self._updated_at = time.time()
        self._thread = None
        self._proc = None
        self._ws = None
        self._auth = None
        self._profile_dir = os.path.join(self.plugin.data_dir, "login_browser_profile")

    # ---------- 生命周期 ----------

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._set_state(
                "LAUNCHING",
                "正在启动无头自动登录浏览器…" if self.mode == "auto" else STATE_MESSAGES["LAUNCHING"],
                refresh=True,
            )
            self._started_at = time.time()
            self._thread = threading.Thread(
                target=self._run,
                name="huawei-health-login",
                daemon=True,
            )
        # 线程资源耗尽 / 解释器正在退出时 start() 会抛异常。v0.4.0 没有 try，
        # 状态会永久停在 LAUNCHING，且没有 finally 去执行 _cleanup()。
        try:
            self._thread.start()
        except Exception as exc:
            with self._lock:
                self._thread = None
                self._fail("launch")
            if self._auto_attempted and not self.manual:
                self._record_auto_failure()
            raise LoginFlowError("launch") from exc

    def cancel(self):
        self._cancel.set()
        self._wake.set()
        with self._lock:
            if self._state not in ("DONE", "FAILED"):
                self._set_state("FAILED", "登录已取消", refresh=True)

    def is_running(self) -> bool:
        thread = self._thread
        return bool(thread and thread.is_alive())

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

    def _set_state(self, state: str, message: str = "", refresh: bool = None):
        """切换状态。

        **只在状态真的变化（或显式 refresh）时重置 deadline。**
        v0.4.0 无条件重置，于是「每秒轮询里反复调 _set_state」的分支会让
        ``_deadline`` 永远停在「现在 + 时长」，超时判定永远差 1 秒 ——
        NEED_SMS 可以无限期挂着，session_timeout 形同虚设。
        """
        if state not in LOGIN_STATES:
            state = "FAILED"
        previous = self._state
        changed = state != self._state
        self._state = state
        self._message = message or STATE_MESSAGES.get(state, STATE_MESSAGES["FAILED"])
        if changed or refresh:
            deadline = self._session_timeout if state == "NEED_SMS" else STATE_DEADLINES.get(state, 0)
            self._deadline = time.time() + deadline
        self._updated_at = time.time()
        if changed:
            # 成功路径也必须留痕：在此之前这里完全静默，登录成功后日志里看不出
            # 走过哪几步，排查只能靠文件时间戳猜。只在状态真变化时打，避免轮询刷屏。
            self._log("info", "状态 %s → %s：%s" % (previous, state, self._message))

    def _fail(self, code: str = "failed"):
        messages = {
            "browser": "找不到可用浏览器，请检查浏览器路径",
            "launch": "浏览器启动失败，请稍后重试",
            "timeout": "登录等待超时，请重新开始",
            "closed": "浏览器已关闭，登录未完成",
            "cdp_lost": "与浏览器的调试连接已断开，请重新开始登录",
            "cookie": "登录完成但未拿到有效会话，请重试",
            "unsupported": "登录模式不受支持",
            "credentials_page": "自动登录页未准备好，请稍后重试",
            "credentials_missing": "账号密码凭据不存在，请先在 WebUI 保存",
            "credentials_unavailable": "当前系统不支持安全凭据登录，请使用 Cookie 模式",
            "credentials_corrupt": "凭据文件损坏或无法解密，请在 WebUI 重新保存账号密码",
            "credentials_locked": "凭据文件被占用或无权读取，请关闭占用程序后重试",
            "bad_credentials": "账号或密码不正确，请在 WebUI 重新保存账号密码",
            "wronghost": "页面跳转到了非华为域名，已中止自动填表",
            "fallback": "自动登录失败，可见浏览器也未能启动，请改用 Cookie 导入",
            "cooldown": "自动登录失败冷却中，请稍后再试",
            "daily_limit": "今日自动登录失败次数已达上限，请稍后再试",
            "failed": STATE_MESSAGES["FAILED"],
        }
        message = messages.get(code, messages["failed"])
        with self._lock:
            self._set_state("FAILED", message, refresh=True)
        try:
            self.plugin.logger.warning("[华为健康登录] " + message)
        except Exception:
            pass

    def _record_auto_failure(self, code: str = ""):
        if code in _COOLDOWN_SKIP:
            # 配置类/可自愈类失败不写冷却，否则用户改对了也还要等 6 小时。
            self._log("info", "失败码 %s 不写冷却（用户可自行修复）" % code)
            return
        try:
            self.manager.record_auto_failure()
        except Exception:
            # A failed config write must not hide the safe FAILED state or
            # leave the login worker with an uncaught exception.
            pass

    def _run(self):
        try:
            self._launch()
            if self._cancel.is_set():
                return
            if self.mode == "auto":
                token = self._auth._js(self._ws, "sessionStorage.getItem('accessToken')")
                if token:
                    self._finish(token)
                    return
                self._auto_submit_credentials()
                with self._lock:
                    self._set_state("SUBMITTING", refresh=True)
            else:
                with self._lock:
                    self._set_state("NEED_CRED", refresh=True)
            self._wait_for_completion()
        except LoginFlowError as exc:
            if not self._cancel.is_set():
                if not self._try_visible_fallback(exc.code):
                    self._fail(exc.code)
                    if self._auto_attempted and not self.manual:
                        self._record_auto_failure(exc.code)
        except Exception:
            if not self._cancel.is_set():
                if not self._try_visible_fallback("failed"):
                    self._fail("failed")
                    if self._auto_attempted and not self.manual:
                        self._record_auto_failure("failed")
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
            headless=self._headless,
            page_timeout=self.plugin.config.get("page_timeout", 90),
            logger=self.plugin.logger,
        )
        # 启动前清掉上一轮遗留的浏览器：此刻任何占用该 profile 的进程都是孤儿
        # （manager 保证同一时刻只有一个会话）。
        self._auth._cleanup_orphan_browsers()
        clear_devtools_port_file(self._profile_dir)
        args = browser_launch_args(browser_path, self._profile_dir, self._headless, port=0)
        kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        }
        if os.name != "nt":
            kwargs["start_new_session"] = True
        try:
            self._proc = subprocess.Popen(args, **kwargs)
            port = read_devtools_port(
                self._profile_dir,
                timeout=min(90, max(1, self._auth.page_timeout)),
                cancel=self._cancel,
            )
            if self._cancel.is_set():
                raise LoginFlowError("cancelled")
            if not port:
                raise LoginFlowError("launch")
            self._ws = self._auth._attach(port)
            self._auth._call(self._ws, "Network.enable")
            self._auth._call(self._ws, "Page.enable")
            self._auth._call(self._ws, "Runtime.enable")
            self._auth._call(self._ws, "Page.navigate", {"url": TRAINING_CAMP_URL})
            if self._headless:
                if not self._wait_login_button():
                    raise LoginFlowError("credentials_page")
            else:
                try:
                    self._auth._js(self._ws, self._login_click_script())
                except HuaweiAuthError:
                    raise
                except Exception:
                    pass
        except Exception as exc:
            self._close_browser()
            if isinstance(exc, LoginFlowError):
                raise
            raise LoginFlowError("launch") from exc

    def _wait_login_button(self):
        deadline = time.monotonic() + min(40, max(1, self._auth.page_timeout))
        while time.monotonic() < deadline and not self._cancel.is_set():
            try:
                if self._auth._js(self._ws, "sessionStorage.getItem('accessToken')"):
                    return True
                result = self._auth._js(self._ws, self._login_click_script())
                if result == "clicked":
                    return True
            except HuaweiAuthError:
                raise
            except Exception:
                pass
            time.sleep(0.5)
        return False

    # ---------- 页面脚本 ----------

    @staticmethod
    def _credential_fill_script(account: str, password: str) -> str:
        account_json = json.dumps(account, ensure_ascii=False)
        password_json = json.dumps(password, ensure_ascii=False)
        return (
            "(()=>{"
            # 只把密码交给 huawei.com：v0.4.0 没有任何域名校验，页面被替换时会照填。
            "const host=location.hostname;"
            "if(!/(^|\\.)huawei\\.com$/i.test(host))return 'wronghost';"
            "const user=%s,pwd=%s;"
            "const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
            "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
            "const set=(sel,val)=>{const e=document.querySelector(sel);if(!e||!visible(e))return false;"
            "const d=Object.getOwnPropertyDescriptor(e.constructor.prototype,'value');"
            "if(!d||!d.set)return false;d.set.call(e,val);e.dispatchEvent(new Event('input',{bubbles:true}));"
            "e.dispatchEvent(new Event('change',{bubbles:true}));return true;};"
            "const u=set('input.userAccount',user),p=set('input.hwid-input-pwd',pwd);"
            "if(!u||!p)return 'missing';"
            "const b=document.querySelector('div.hwid-login-btn,button.hwid-login-btn');"
            "if(!b||!visible(b))return 'waiting';"
            "if(/\\bhwid-disabled\\b/.test(String(b.className||'')))return 'disabled';"
            "b.click();return 'submitted';})()"
        ) % (account_json, password_json)

    def _auto_submit_credentials(self):
        store = getattr(self.plugin, "credentials", None)
        if store is None or not store.available:
            raise LoginFlowError("credentials_unavailable")
        try:
            values = store.load()
        except DPAPIUnavailableError:
            raise LoginFlowError("credentials_unavailable")
        except CredentialsLockedError:
            raise LoginFlowError("credentials_locked")
        except CredentialsCorruptError:
            raise LoginFlowError("credentials_corrupt")
        except CredentialsError:
            raise LoginFlowError("credentials_missing")
        account = values.get("account", "")
        password = values.get("password", "")
        deadline = time.monotonic() + min(45, max(1, self._auth.page_timeout))
        try:
            while time.monotonic() < deadline and not self._cancel.is_set():
                result = self._auth._js(self._ws, self._credential_fill_script(account, password))
                if result == "submitted":
                    self._credentials_submitted = True
                    return
                if result == "wronghost":
                    raise LoginFlowError("wronghost")
                time.sleep(0.5)
        except LoginFlowError:
            raise
        except Exception as exc:
            raise LoginFlowError("credentials_page") from exc
        finally:
            account = None
            password = None
            values = None
        raise LoginFlowError("credentials_page")

    def _try_visible_fallback(self, code: str) -> bool:
        if (not self._auto_attempted or self._fallback_used or
                not self.manager.allow_visible_fallback or
                code in _FALLBACK_SKIP):
            return False
        self._fallback_used = True
        original = code
        try:
            self._close_browser(sweep_profile=self._sweep_allowed())
            self.mode = "manual"
            self._headless = False
            # 兜底是「重新开始一次登录」，别让自动阶段耗掉的时间吃掉可见窗口的预算。
            self._started_at = time.time()
            with self._lock:
                self._set_state("LAUNCHING", "自动登录未完成，正在打开可见浏览器…", refresh=True)
            self._launch()
            if self._cancel.is_set():
                return True
            with self._lock:
                self._set_state("NEED_CRED", refresh=True)
            self._wait_for_completion()
        except LoginFlowError as exc:
            if not self._cancel.is_set():
                # 保留真实错误码（v0.4.0 一律覆盖成 fallback，把「没装浏览器」说成
                # 「可见浏览器也未能启动」）。
                self._fail(exc.code if exc.code != "cancelled" else original)
                if self._auto_attempted and not self.manual:
                    self._record_auto_failure(exc.code)
        except Exception:
            if not self._cancel.is_set():
                self._fail(original)
                if self._auto_attempted and not self.manual:
                    self._record_auto_failure(original)
        return True

    @staticmethod
    def _login_click_script() -> str:
        return (
            "(()=>{const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
            "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
            "const b=document.querySelector('button.login-button');"
            "if(b&&visible(b)){b.click();return 'clicked';}return 'notfound';})()"
        )

    def _wait_for_completion(self):
        hard_deadline = self._started_at + max(300, self._session_timeout * SESSION_HARD_CAP_FACTOR)
        while not self._cancel.is_set():
            self._process_action()
            with self._lock:
                deadline = self._deadline
            now = time.time()
            if (deadline and now >= deadline) or now >= hard_deadline:
                raise LoginFlowError("timeout")
            try:
                token = self._auth._js(self._ws, "sessionStorage.getItem('accessToken')")
            except HuaweiAuthError:
                # CDP 已断：立刻退出，别空等（v0.4.0 会在这里空转 90 秒）。
                if self._proc is not None and self._proc.poll() is not None:
                    raise LoginFlowError("closed")
                raise LoginFlowError("cdp_lost")
            except Exception:
                token = None
            if token:
                self._finish(token)
                return
            self._update_page_state()
            self._wake.wait(1)
            self._wake.clear()

    # ---------- 交互 ----------

    def submit_sms(self, code: str) -> dict:
        code = re.sub(r"\s+", "", str(code or ""))
        # 华为目前是 6 位，但改成 4/8 位时不该整个流程都进不去。
        if not re.fullmatch(r"\d{4,8}", code):
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
            if result == "submitted":
                self._sms_action_sent = True
                self._sms_action_at = time.time()
                with self._lock:
                    self._set_state("SUBMITTING")
            elif result == "length_mismatch":
                self._sms_action_sent = False
                self._sms_action_at = 0.0
                with self._lock:
                    self._set_state(
                        "NEED_SMS",
                        "验证码输入框的数量和码长对不上，请在浏览器窗口中手动输入",
                    )
            else:
                # v0.4.0 把 'filled'（只把框填满、没找到提交按钮）也当成已提交，
                # 于是码一次都没发出去，8 秒后还告诉用户「可能已失效」。
                self._sms_action_sent = False
                self._sms_action_at = 0.0
                with self._lock:
                    self._set_state(
                        "NEED_SMS",
                        "验证码已填入，但没有找到提交按钮，请在浏览器窗口中手动确认",
                    )
        elif kind == "trust":
            if result != "clicked":
                self._trust_action_sent = False
                with self._lock:
                    self._set_state("NEED_TRUST", "信任选择窗口已变化，请重新选择")
            else:
                self._trust_action_sent = True
                self._trust_action_at = time.time()
                self._trust_last_choice = payload
                # 用户手动选过一次之后，重置重试计数，别再直接打回 NEED_TRUST。
                self._trust_retries = 0
                with self._lock:
                    self._set_state("SUBMITTING")

    def _update_page_state(self):
        try:
            raw = self._auth._js(self._ws, self._page_state_script())
            info = json.loads(raw) if isinstance(raw, str) else {}
            if not isinstance(info, dict):
                info = {}
        except HuaweiAuthError:
            raise
        except Exception:
            info = {}
        if not info:
            # 页面脚本读不到（正在跳转 / 已改版）：**不要改状态**。
            # v0.4.0 会把它当成「页面没有验证码框」，把 NEED_SMS 翻成 SUBMITTING，
            # 前端于是把验证码输入框置灰，90 秒后报「登录等待超时」。
            self._log("warning", "页面状态脚本无返回（可能正在跳转或页面已改版），保留状态 %s" % self._state)
            return
        with self._lock:
            current = self._state
            if (info.get("pwd_error") and self._credentials_submitted
                    and not info.get("sms") and not info.get("trust")):
                # v0.4.0 完全没有这个分支：密码错误只能空等 90 秒报「登录等待超时」。
                raise LoginFlowError("bad_credentials")
            if info.get("sms"):
                if info.get("sms_error"):
                    self._sms_action_sent = False
                    self._sms_action_at = 0.0
                    self._set_state("NEED_SMS", "验证码校验失败，请重新输入")
                elif current != "NEED_SMS" and not self._sms_action_sent:
                    self._set_state("NEED_SMS")
                elif (self._sms_action_sent and self._sms_action_at
                      and time.time() - self._sms_action_at >= SMS_RETRY_GRACE):
                    # 提交后验证码页仍在：华为多半已重发新码，重新开放输入。
                    self._sms_action_sent = False
                    self._sms_action_at = 0.0
                    self._set_state("NEED_SMS", "验证码可能已失效，请重新输入")
            elif info.get("trust"):
                if current == "NEED_TRUST":
                    return
                if self._trust_action_sent:
                    # 点过「信任」但信任页还在：重试一次，再不行就让用户手动选。
                    if time.time() - self._trust_action_at >= TRUST_RETRY_GRACE:
                        self._trust_action_sent = False
                        self._trust_retries += 1
                        if self._trust_retries > 1:
                            self._set_state(
                                "NEED_TRUST", "信任选择未生效，请在浏览器窗口中手动选择")
                        elif not self._pending_action:
                            self._pending_action = "trust"
                            # 重试沿用用户上一次的选择（没有就按 auto_trust）
                            self._actions.put(("trust", self._trust_last_choice or (
                                "true" if self.auto_trust else "false")))
                            self._wake.set()
                    return
                if self.auto_trust:
                    if not self._pending_action:
                        self._pending_action = "trust"
                        self._actions.put(("trust", "true"))
                        self._set_state("SUBMITTING")
                        self._wake.set()
                else:
                    self._set_state("NEED_TRUST")
            elif current in ("NEED_SMS", "NEED_TRUST"):
                self._set_state("SUBMITTING")

    # ---------- 页面脚本（选择器集中在这里，改版时只需改这一段） ----------

    @staticmethod
    def _page_state_script() -> str:
        return (
            "(()=>{const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
            "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
            "const tels=[...document.querySelectorAll('input[type=tel],input[inputmode=numeric]')]"
            ".filter(visible);"
            # v0.4.0 硬编码「>=6 个 input[type=tel]」；改成单输入框/4~8 位就永远识别不到。
            "const sms=tels.length>=6||(tels.length>=1&&tels.some(e=>{"
            "const m=parseInt(e.getAttribute('maxlength')||'0',10);return m>=4&&m<=8;}));"
            "const btns=[...document.querySelectorAll("
            "'span.hwid-vertical-align,button,[role=button],a')]"
            ".filter(visible).map(e=>(e.innerText||e.textContent||'').trim()).filter(Boolean);"
            "const body=(document.body&&document.body.innerText)||'';"
            "const trustText=btns.some(t=>/^(信任|信任此浏览器|信任该浏览器|信任此设备)$/.test(t));"
            "const trustOther=btns.some(t=>/^(不信任|稍后再说|以后再说)$/.test(t));"
            "const trustDialog=/是否信任此浏览器|是否信任此设备/.test(body);"
            # 要求「对话框特征」：只有 信任 文案、没有 不信任/稍后再说 的，是登录页上的
            # 复选框标签，不是信任对话框（v0.4.0 会误点，然后本会话内信任处理永久失效）。
            "const trust=trustText&&(trustOther||trustDialog);"
            "const sms_error=sms&&/(验证码|校验码).{0,10}(错误|不正确|失败|失效|过期|无效)/.test(body);"
            "const pwd_error=/(帐号或密码错误|账号或密码错误|密码不正确|帐号不存在|账号不存在|"
            "帐号或密码有误|账号或密码有误)/.test(body);"
            "return JSON.stringify({sms,trust,sms_error,pwd_error});})()"
        )

    @staticmethod
    def _sms_submit_script(code: str) -> str:
        code_json = json.dumps(code, ensure_ascii=False)
        return (
            "(()=>{const code=%s;const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
            "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
            "const els=[...document.querySelectorAll('input[type=tel],input[inputmode=numeric]')]"
            ".filter(visible);"
            "if(!els.length)return 'missing';"
            "const put=(e,v)=>{const d=Object.getOwnPropertyDescriptor(e.constructor.prototype,'value');"
            "if(!d||!d.set)return false;d.set.call(e,v);"
            "e.dispatchEvent(new Event('input',{bubbles:true}));"
            "e.dispatchEvent(new Event('change',{bubbles:true}));return true;};"
            "const n=els.length;"
            "if(n===1){if(!put(els[0],code))return 'setter';}"
            # 逐框填必须「框数 == 码长」：v0.4.1 第一版写死 6 个框，8 位码会被截成 6 位。
            "else if(n>=2){if(n!==code.length)return 'length_mismatch';"
            "for(let i=0;i<n;i++){if(!put(els[i],code[i]))return 'setter';}}"
            "else{return 'missing';}"
            "const btns=[...document.querySelectorAll("
            "'span.hwid-vertical-align,button,[role=button],div.hwid-login-btn,a')].filter(visible);"
            "const btn=btns.find(e=>/^(确定|确认|提交|下一步|验证|登录)$/.test("
            "(e.innerText||e.textContent||'').trim()));"
            "if(btn){btn.click();return 'submitted';}"
            "const form=els[0].closest('form');"
            "if(form){if(form.requestSubmit){form.requestSubmit();}else{form.submit();}return 'submitted';}"
            "return 'filled';})()"
        ) % code_json

    @staticmethod
    def _trust_submit_script(choice: str) -> str:
        pattern = {
            "true": "^(?:信任此浏览器|信任该浏览器|信任此设备|信任)$",
            "false": "^(?:不信任)$",
            "later": "^(?:稍后再说|以后再说)$",
        }[choice]
        return (
            "(()=>{const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);"
            "return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden';};"
            "const els=[...document.querySelectorAll("
            "'span.hwid-vertical-align,button,[role=button],div.hwid-login-btn,a')].filter(visible);"
            "const btn=els.find(e=>/(%s)/.test((e.innerText||e.textContent||'').trim()));"
            "if(btn){btn.click();return 'clicked';}return 'missing';})()"
        ) % pattern

    # ---------- 收尾 ----------

    def _finish(self, token: str):
        with self._lock:
            self._set_state("FINALIZING", refresh=True)
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
            ttl = self.plugin.config.get("token_ttl", 3000)
            expire_at = compute_expire_at(self._auth.token_expire_at, ttl)
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
            self._set_state("DONE", refresh=True)
        if self._auto_attempted:
            try:
                # 只归还自己那一格：manual=True 的会话不记账，成功后也不该 pop 别人的。
                self.manager.record_auto_success(return_quota=self._attempt_recorded)
            except Exception:
                pass

    def _sweep_allowed(self) -> bool:
        """本会话是否还「有资格」按 profile 路径清扫浏览器。

        ``_cleanup_orphan_browsers()`` 按命令行里的 profile 路径 taskkill，而所有
        登录会话共用同一个 ``login_browser_profile``。所以**只有自己仍是当前会话**
        时才允许清扫——否则「取消 → 立刻重开」时，老会话的收尾会把新会话刚起的
        浏览器一起杀掉（v0.4.0 的原始症状，v0.4.1 第一版只在 `_cleanup()` 里修了）。
        """
        try:
            return self.manager.current_session() is self
        except Exception:
            return False

    def _close_browser(self, sweep_profile: bool = None):
        auth, ws, proc = self._auth, self._ws, self._proc
        if sweep_profile is None:
            sweep_profile = self._sweep_allowed()
        self._auth = None
        self._ws = None
        self._proc = None
        try:
            if ws is not None and auth is not None:
                try:
                    auth._call(ws, "Browser.close", timeout=5)
                except Exception:
                    pass
                try:
                    ws.close()
                except Exception:
                    pass
        finally:
            if auth is not None:
                try:
                    auth._stop_process(proc, sweep_profile=sweep_profile)
                except TypeError:
                    # 兼容旧签名（没有 sweep_profile 参数）
                    try:
                        auth._stop_process(proc)
                    except Exception:
                        pass
                except Exception:
                    try:
                        auth._cleanup_orphan_browsers()
                    except Exception:
                        pass

    def _cleanup(self):
        # 取消或结束时丢弃尚未发送的验证码/信任选项，避免会话对象继续持有敏感输入。
        try:
            while True:
                self._actions.get_nowait()
        except queue.Empty:
            pass
        with self._lock:
            self._pending_action = ""
        # 只有当自己仍是 manager 的当前会话时才做 profile 级清扫：
        # v0.4.0 无条件清扫，会把「取消后立刻重开」的新会话浏览器一起杀掉。
        self._close_browser(sweep_profile=self._sweep_allowed())

    def _log(self, level: str, msg: str):
        try:
            getattr(self.plugin.logger, level, self.plugin.logger.info)("[华为健康登录] " + msg)
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
        self.prefer_auto = True
        self.daily_limit = LOGIN_DEFAULTS["daily_limit"]
        self.session_timeout = LOGIN_DEFAULTS["session_timeout"]
        self.allow_visible_fallback = LOGIN_DEFAULTS["allow_visible_fallback"]
        self._attempts = []
        self.failure_cooldown_until = 0.0
        self._load_login_config()

    # ---------- 持久化 ----------

    def _backup_bad_config(self, reason: str):
        if not os.path.isfile(self.login_config_path):
            return
        try:
            bad = "%s.bad.%d" % (self.login_config_path, int(time.time()))
            os.replace(self.login_config_path, bad)
            self._log_warning("login_config.json 无效（%s），已备份为 %s 并重置为默认值"
                              % (reason, os.path.basename(bad)))
        except OSError:
            self._log_warning("login_config.json 无效（%s），已重置为默认值" % reason)

    def _load_login_config(self):
        problems = []
        try:
            with open(self.login_config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            self._prune_attempts()
            return
        except (OSError, ValueError, TypeError) as exc:
            # v0.4.0 静默吞掉：文件被截断 → 额度/冷却静默清零，下一次写回把「干净」状态固化。
            self._backup_bad_config("%s: %s" % (type(exc).__name__, redact_error(exc)))
            self._prune_attempts()
            return
        if not isinstance(data, dict):
            # 能解析但形状不对（顶层是数组/字符串/null）——v0.4.1 第一版这里仍然静默清零。
            self._backup_bad_config("顶层不是对象（%s）" % type(data).__name__)
            self._prune_attempts()
            return

        if data.get("mode") in ("cookie", "password"):
            self.login_mode = data["mode"]
        elif "mode" in data:
            problems.append("mode=%r" % (data.get("mode"),))
        if isinstance(data.get("auto_trust"), bool):
            self.auto_trust = data["auto_trust"]
        elif "auto_trust" in data:
            problems.append("auto_trust 不是 bool")
        try:
            self.daily_limit = max(1, min(10, int(data.get("daily_limit", self.daily_limit))))
        except (TypeError, ValueError):
            problems.append("daily_limit=%r" % (data.get("daily_limit"),))
        try:
            self.session_timeout = max(60, min(1800, int(data.get("session_timeout", self.session_timeout))))
        except (TypeError, ValueError):
            problems.append("session_timeout=%r" % (data.get("session_timeout"),))
        if isinstance(data.get("allow_visible_fallback"), bool):
            self.allow_visible_fallback = data["allow_visible_fallback"]
        if isinstance(data.get("prefer_auto"), bool):
            self.prefer_auto = data["prefer_auto"]
        attempts = data.get("attempts")
        if isinstance(attempts, list):
            self._attempts = [
                float(v) for v in attempts
                if isinstance(v, (int, float)) and math.isfinite(float(v))
            ]
        elif "attempts" in data:
            problems.append("attempts 不是数组")
        try:
            cooldown = float(data.get("failure_cooldown_until", 0) or 0)
        except (TypeError, ValueError):
            problems.append("failure_cooldown_until 不是数字")
            cooldown = 0.0
        now = time.time()
        # 只钳上界：手改成远期时间戳 / 系统时钟被向前拨过时，原来会永久锁死。
        if not math.isfinite(cooldown) or cooldown > now + FAILURE_COOLDOWN:
            problems.append("failure_cooldown_until 异常（%r）" % cooldown)
            cooldown = 0.0
        self.failure_cooldown_until = max(0.0, cooldown)
        if problems:
            self._log_warning("login_config.json 有非法字段，已按默认值处理：%s"
                              % redact_error("；".join(problems)))
        self._prune_attempts()

    def _save_login_config(self):
        data = {
            "mode": self.login_mode,
            "auto_trust": bool(self.auto_trust),
            "daily_limit": self.daily_limit,
            "session_timeout": self.session_timeout,
            "allow_visible_fallback": bool(self.allow_visible_fallback),
            "prefer_auto": bool(self.prefer_auto),
            "attempts": list(self._attempts),
            "failure_cooldown_until": self.failure_cooldown_until,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        tmp = self.login_config_path + ".tmp.%d.%d" % (os.getpid(), threading.get_ident())
        try:
            parent = os.path.dirname(self.login_config_path) or "."
            os.makedirs(parent, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.login_config_path)
            harden_file_permissions(self.login_config_path)
        except OSError as exc:
            # 只读目录 / 文件被占用：闸门状态丢了比抛裸 OSError 一路穿到 WebUI 好。
            # v0.4.1 第一版这里会把 PermissionError 抛到 manager.start() 的调用方。
            self._log_warning("写入 login_config.json 失败（%s），本次状态未持久化"
                              % redact_error(exc))
        finally:
            try:
                if os.path.exists(tmp):
                    os.unlink(tmp)
            except OSError:
                pass

    def _log_warning(self, msg: str):
        try:
            self.plugin.logger.warning("[华为健康登录] " + msg)
        except Exception:
            pass

    def _log_info(self, msg: str):
        try:
            self.plugin.logger.info("[华为健康登录] " + msg)
        except Exception:
            pass

    def set_login_mode(self, mode: str):
        mode = str(mode or "").strip().lower()
        if mode not in ("cookie", "password"):
            raise LoginFlowError("mode_invalid")
        with self._lock:
            self.login_mode = mode
            self._save_login_config()

    # ---------- 风控闸门 ----------

    def _prune_attempts(self):
        now = time.time()
        cutoff = now - 24 * 60 * 60
        # 顺手丢掉未来时间戳：v0.4.0 只裁掉「太旧」的，未来值会永久占满额度。
        self._attempts = [v for v in self._attempts if cutoff <= v <= now + 60]

    def _check_auto_gate(self):
        self._prune_attempts()
        now = time.time()
        if self.failure_cooldown_until > now:
            raise LoginFlowError("cooldown")
        if len(self._attempts) >= self.daily_limit:
            raise LoginFlowError("daily_limit")

    def _record_auto_attempt(self):
        self._prune_attempts()
        self._attempts.append(time.time())
        self._save_login_config()

    def record_auto_failure(self):
        with self._lock:
            self.failure_cooldown_until = time.time() + FAILURE_COOLDOWN
            self._save_login_config()

    def record_auto_success(self, return_quota: bool = True):
        with self._lock:
            self.failure_cooldown_until = 0.0
            # 成功登录必须归还名额：v0.4.0 只清冷却不动 _attempts，
            # 于是「一次成功」就占满了当天唯一额度，50 分钟后 token 过期即全挂。
            # return_quota=False 用于「本次会话根本没记账」（manual=True）。
            if return_quota and self._attempts:
                self._attempts.pop()
            self._save_login_config()

    def clear_cooldown(self):
        """凭据改对/用户手动登录成功后，把 6 小时冷却立刻清掉。"""
        with self._lock:
            if self.failure_cooldown_until:
                self.failure_cooldown_until = 0.0
                self._save_login_config()

    # ---------- 状态 ----------

    def current_session(self):
        with self._lock:
            return self._session

    def is_busy(self) -> bool:
        """当前会话是否还在等用户/页面（NEED_SMS / NEED_CRED / NEED_TRUST 等）。"""
        session = self.current_session()
        if session is None:
            return False
        return session.snapshot()["state"] not in ("IDLE", "DONE", "FAILED")

    def status(self) -> dict:
        with self._lock:
            if self._session is None:
                data = {
                    "state": "IDLE",
                    "mode": "manual",
                    "auto_trust": self.auto_trust,
                    "message": STATE_MESSAGES["IDLE"],
                    "deadline_left": 0,
                    "need": {"account": False, "sms": False, "trust": False},
                    "updated_at": "-",
                }
            else:
                data = self._session.snapshot()
            self._prune_attempts()
            data["prefer_auto"] = bool(self.prefer_auto)
            data["daily_used"] = len(self._attempts)
            data["daily_limit"] = int(self.daily_limit)
            data["cooldown_left"] = max(0, int(self.failure_cooldown_until - time.time()))
            data["login_mode"] = self.login_mode
            return data

    def start(self, mode: str = "manual", auto_trust=None, allow_visible_fallback=None,
              manual: bool = False, prefer_auto=None) -> dict:
        mode = str(mode or "manual").strip().lower()
        if mode not in ("manual", "auto"):
            raise LoginFlowError("unsupported")
        if prefer_auto is not None:
            if not isinstance(prefer_auto, bool):
                raise LoginFlowError("prefer_invalid")
            self.prefer_auto = prefer_auto
            self._save_login_config()
        if auto_trust is not None:
            if not isinstance(auto_trust, bool):
                raise LoginFlowError("trust_invalid")
            self.auto_trust = auto_trust
            self._save_login_config()
        if allow_visible_fallback is not None:
            if not isinstance(allow_visible_fallback, bool):
                raise LoginFlowError("fallback_invalid")
            self.allow_visible_fallback = allow_visible_fallback
            self._save_login_config()
        with self._lock:
            if self._session is not None:
                current = self._session.snapshot()
                if current["state"] not in ("DONE", "FAILED"):
                    return current
            if mode == "auto":
                store = getattr(self.plugin, "credentials", None)
                if store is None or not store.available:
                    raise LoginFlowError("credentials_unavailable")
                try:
                    store.load()
                except DPAPIUnavailableError:
                    raise LoginFlowError("credentials_unavailable")
                except CredentialsLockedError:
                    raise LoginFlowError("credentials_locked")
                except CredentialsCorruptError:
                    raise LoginFlowError("credentials_corrupt")
                except CredentialsError:
                    raise LoginFlowError("credentials_missing")
                if not manual:
                    self._check_auto_gate()
                    self._record_auto_attempt()
            self._log_info(
                "开始登录：mode=%s manual=%s auto_trust=%s prefer_auto=%s"
                % (mode, manual, self.auto_trust, self.prefer_auto))
            session = HuaweiLoginSession(self, mode=mode, manual=manual)
            session._attempt_recorded = (mode == "auto" and not manual)
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
            # v0.4.0 只等 2 秒，线程还在 CDP 调用里时就允许新会话启动，
            # 于是「取消 → 立刻重开」会两个会话抢同一个 profile。
            session.join(15)
        return self.status()

    def stop(self):
        with self._lock:
            session = self._session
        if session is not None:
            session.cancel()
            session.join(10)
