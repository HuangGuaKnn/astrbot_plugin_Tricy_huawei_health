# -*- coding: utf-8 -*-
"""华为运动健康 · 认证层（浏览器 + Cookie → accessToken）

链路（2026-10-22 实机验证通过）：
    1. 起一个 headless Edge/Chrome，独立 user-data-dir + remote-debugging-port
    2. 通过 CDP 把 cookie 文件里的 cookie 注入浏览器
    3. 导航到 health.cloud.huawei.com/TrainingCamp
    4. sessionStorage 无 accessToken → 点「登录」→ 自动走 OAuth
       （华为认「信任设备」，无二次验证，实测 2026-10-22）
    5. 读回 accessToken（180 字符，约 1 小时有效）
    6. 把服务端新下发的 cookie 回写文件（滚续：只要在 TTL 内用过一次就不会断）

关键坑（务必保留注释）：
    - 华为登录态的核心是 session cookie（CASTGC 等），**关浏览器即失效**，
      所以不能只靠持久化 profile，必须每次都注入 cookie 文件。
    - 但每次成功登录后服务端会下发新 cookie，回写即可滚动续期。
    - 本模块是**同步阻塞**代码，调用方必须放到线程里跑（asyncio.to_thread）。
"""

import json
import os
import signal
import socket
import subprocess
import threading
import time
import urllib.request

import websocket

TRAINING_CAMP_URL = "https://health.cloud.huawei.com/TrainingCamp"

DEFAULT_BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/microsoft-edge",
    "/usr/bin/google-chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
]

# Cookie-Editor / CDP 两种导出的 sameSite 写法 → CDP 规范值
_SAMESITE = {
    "no_restriction": "None",
    "unspecified": None,
    "lax": "Lax",
    "strict": "Strict",
    "none": "None",
    "None": "None",
    "Lax": "Lax",
    "Strict": "Strict",
}

# 设置页提供的最小可用 cookie 集；CASTGC 必须按两个路径各生成一条。
MIN_COOKIE_SPECS = (
    ("CASTGC", ".id1.cloud.huawei.com", ("/CAS", "/UnifiedIDMPortal")),
    ("sid", ".id1.cloud.huawei.com", ("/",)),
    ("hwid_cas_sid", ".id1.cloud.huawei.com", ("/",)),
    ("HuaweiID_CAS_ISCASLOGIN", ".huawei.com", ("/",)),
    ("CASLOGINSITE", ".huawei.com", ("/",)),
    ("LOGINACCSITE", ".huawei.com", ("/",)),
)


def _cookie_field_key(value) -> str:
    """把配置键/行首名称归一化，兼容 HuaweiID 与 HUAWEI_ID 两种写法。"""
    return "".join(ch for ch in str(value).strip().lower() if ch.isalnum())


def cookies_from_fields(fields) -> list:
    """把六条分项值转换为 CDP cookie；空值跳过，便于只补失效项。"""
    if not isinstance(fields, dict):
        return []
    values = {_cookie_field_key(k): str(v).strip() for k, v in fields.items() if v is not None}
    out = []
    for name, domain, paths in MIN_COOKIE_SPECS:
        value = values.get(_cookie_field_key(name), "")
        if not value:
            continue
        for path in paths:
            out.append(normalize_cookie({
                "name": name,
                "value": value,
                "domain": domain,
                "path": path,
                "secure": True,
            }))
    return out


def parse_cookie_fields(text: str) -> dict:
    """解析「名称=值」或按六项顺序填写的多行文本。"""
    lines = [line.strip() for line in str(text or "").splitlines()
             if line.strip() and not line.strip().startswith("#")]
    if not lines:
        return {}
    fields = {}
    named = False
    ordered = []
    for line in lines:
        if "=" in line:
            key, value = line.split("=", 1)
            if _cookie_field_key(key) in {_cookie_field_key(n) for n, _, _ in MIN_COOKIE_SPECS}:
                fields[key.strip()] = value.strip()
                named = True
                continue
        ordered.append(line)
    if not named:
        for (name, _, _), value in zip(MIN_COOKIE_SPECS, ordered):
            fields[name] = value
    return fields


def parse_cookie_input(text: str) -> list:
    """兼容旧 JSON，同时接受设置页的六行分项输入。"""
    stripped = str(text or "").strip()
    if not stripped:
        return []
    if stripped.startswith("[") or stripped.startswith("{"):
        return parse_cookie_payload(stripped)
    return cookies_from_fields(parse_cookie_fields(stripped))


def _merge_cookies(*groups) -> list:
    merged = {}
    for group in groups:
        for cookie in group or []:
            key = (cookie.get("name"), cookie.get("domain"), cookie.get("path", "/"))
            merged[key] = cookie
    return list(merged.values())


def find_browser(explicit: str = "") -> str:
    """定位本机浏览器可执行文件。"""
    if explicit and os.path.exists(explicit):
        return explicit
    for p in DEFAULT_BROWSERS:
        if os.path.exists(p):
            return p
    return ""


def free_port() -> int:
    """取一个空闲本地端口给 CDP 用。"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def normalize_cookie(raw: dict) -> dict:
    """把 Cookie-Editor / CDP 两种导出格式统一成 CDP Network.setCookies 格式。"""
    out = {
        "name": str(raw.get("name", "")),
        "value": str(raw.get("value", "")),
        "domain": str(raw.get("domain", "")),
        "path": str(raw.get("path") or "/"),
        "secure": bool(raw.get("secure", False)),
        "httpOnly": bool(raw.get("httpOnly", False)),
    }
    exp = raw.get("expires", raw.get("expirationDate", -1))
    try:
        exp = float(exp)
    except (TypeError, ValueError):
        exp = -1
    if exp > 0:
        out["expires"] = exp
    ss = _SAMESITE.get(str(raw.get("sameSite", "")), None)
    if ss:
        out["sameSite"] = ss
    return out


def parse_cookie_payload(text: str):
    """解析 cookie JSON：支持数组、{cookies:[...]}、以及 CDP 原始返回。"""
    if not text or not text.strip():
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        for key in ("cookies", "Cookies", "data"):
            if isinstance(data.get(key), list):
                data = data[key]
                break
        else:
            data = []
    if not isinstance(data, list):
        return []
    return [normalize_cookie(c) for c in data if isinstance(c, dict) and c.get("name")]


class HuaweiAuthError(Exception):
    """认证流程失败。"""


class HuaweiAuth:
    """负责「拿 token」这一件事。"""

    # 认证对象会按调用临时创建；按 cookie 文件共享锁和失败时间，才能让
    # 导入、回写、清除以及连续认证失败在不同对象之间也保持串行/冷却。
    _state_lock = threading.Lock()
    _cookie_locks = {}
    _failure_state = {}

    def __init__(
        self,
        cookie_file: str,
        profile_dir: str,
        browser_path: str = "",
        headless: bool = True,
        page_timeout: int = 90,
        logger=None,
    ):
        self.cookie_file = cookie_file
        self.profile_dir = profile_dir
        self.browser_path = browser_path
        self.headless = headless
        # 统一成正数，确保底层 urllib/websocket/CDP 都得到可用的超时值。
        try:
            self.page_timeout = max(1.0, float(page_timeout))
        except (TypeError, ValueError):
            self.page_timeout = 90.0
        self.log = logger
        # 共享文件锁避免导入、认证回写和清除同时修改 cookie 文件。
        lock_key = os.path.abspath(cookie_file)
        with self._state_lock:
            self._cookie_lock = self._cookie_locks.setdefault(lock_key, threading.RLock())
            state = self._failure_state.setdefault(lock_key, {"lock": threading.Lock(), "last": 0.0})
        self._failure_lock = state["lock"]
        self._failure_state_item = state
        self._last_failure = state["last"]
        self.failure_cooldown = 180
        self.token_expire_at = 0.0

    # ---------- cookie 读写 ----------

    def _load_cookie_snapshot(self):
        with self._cookie_lock:
            if not os.path.exists(self.cookie_file):
                return [], None
            with open(self.cookie_file, "r", encoding="utf-8") as f:
                text = f.read()
            try:
                mtime_ns = os.stat(self.cookie_file).st_mtime_ns
            except OSError:
                mtime_ns = None
            return parse_cookie_payload(text), mtime_ns

    def load_cookies(self):
        return self._load_cookie_snapshot()[0]

    def save_cookies(self, cookies, expected_mtime_ns=None):
        # 原子替换防止进程中断留下半份 JSON，且与导入/清除使用同一把锁。
        with self._cookie_lock:
            if expected_mtime_ns is not None:
                if not os.path.exists(self.cookie_file):
                    # 用户在认证期间清除了 cookie，不能用旧认证结果把它恢复。
                    self._log("warning", "检测到 cookie 文件已清除，跳过旧认证结果回写")
                    return False
                try:
                    current_mtime_ns = os.stat(self.cookie_file).st_mtime_ns
                except OSError:
                    current_mtime_ns = None
                if current_mtime_ns != expected_mtime_ns:
                    # 用户在认证期间导入了新 cookie，不能用旧认证结果覆盖它。
                    self._log("warning", "检测到 cookie 文件已变化，跳过旧认证结果回写")
                    return False
            parent = os.path.dirname(self.cookie_file) or "."
            os.makedirs(parent, exist_ok=True)
            tmp = self.cookie_file + ".tmp.%d.%d" % (os.getpid(), threading.get_ident())
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(cookies, f, ensure_ascii=False, indent=1)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.cookie_file)
            finally:
                try:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                except OSError:
                    pass
            return True

    def import_cookie_text(self, text: str) -> int:
        """导入一份 Cookie-Editor / CDP 导出的 cookie 文本，返回条数。"""
        cookies = parse_cookie_input(text)
        if not cookies:
            raise HuaweiAuthError("cookie 文本解析为空，请确认导出内容正确")
        self.save_cookies(cookies)
        return len(cookies)

    def import_cookie_sources(self, json_text: str = "", fields=None) -> int:
        """合并旧 JSON 和设置页分项 cookie，兼容两种配置入口。"""
        groups = []
        if str(json_text or "").strip():
            groups.append(parse_cookie_input(json_text))
        groups.append(cookies_from_fields(fields))
        cookies = _merge_cookies(*groups)
        if not cookies:
            raise HuaweiAuthError("cookie 内容为空，请至少填写一条有效 cookie")
        self.save_cookies(cookies)
        return len(cookies)

    def clear_cookies(self):
        """清除 cookie 文件并与导入、认证回写串行，避免并发恢复旧文件。"""
        with self._cookie_lock:
            try:
                os.unlink(self.cookie_file)
            except FileNotFoundError:
                pass

    def _mark_failure(self):
        """记录失败时间，统一让早期失败也进入冷却窗口。"""
        with self._failure_lock:
            self._last_failure = time.time()
            self._failure_state_item["last"] = self._last_failure

    def _cleanup_orphan_browsers(self):
        """清理命令行带本插件 profile 的孤儿浏览器，避免下一轮认证被 profile 锁住。"""
        if os.name != "nt":
            return
        needle = os.path.abspath(self.profile_dir).replace("'", "''")
        script = (
            "$needle='%s'; "
            "Get-CimInstance Win32_Process | "
            "Where-Object { ($_.Name -eq 'msedge.exe' -or $_.Name -eq 'chrome.exe') "
            "-and $_.CommandLine -and $_.CommandLine.Contains($needle) } | "
            "ForEach-Object { taskkill /PID $_.ProcessId /T /F 2>$null | Out-Null }"
        ) % needle
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            time.sleep(0.2)
        except Exception as exc:
            self._log("warning", "孤儿浏览器清理失败：%s" % exc)

    # ---------- 主流程 ----------

    def fetch_token(self) -> str:
        """起浏览器 → 注入 cookie → 自动登录 → 返回 accessToken。阻塞调用。"""
        with self._failure_lock:
            self._last_failure = self._failure_state_item["last"]
            remain = self.failure_cooldown - (time.time() - self._last_failure)
        if remain > 0:
            raise HuaweiAuthError("认证失败冷却中，请 %.0f 秒后重试" % remain)
        started = time.monotonic()
        self._log("info", "认证阶段开始")
        # 上一次异常退出可能留下 Edge 子进程，启动前先清理本插件自己的 profile。
        self._cleanup_orphan_browsers()
        browser = find_browser(self.browser_path)
        if not browser:
            self._mark_failure()
            raise HuaweiAuthError("找不到 Edge/Chrome，请在插件配置里填写浏览器路径")

        cookies, cookie_mtime_ns = self._load_cookie_snapshot()
        if not cookies:
            self._mark_failure()
            raise HuaweiAuthError(
                "没有 cookie。请先用 Cookie-Editor 从已登录的华为运动健康网页端导出，"
                "再把 JSON 导入插件。"
            )

        os.makedirs(self.profile_dir, exist_ok=True)
        port = free_port()
        args = [
            browser,
            "--remote-debugging-port=%d" % port,
            "--user-data-dir=" + self.profile_dir,
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-blink-features=AutomationControlled",
        ]
        if self.headless:
            args.append("--headless=new")
        args.append("about:blank")

        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        popen_kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "creationflags": creationflags,
        }
        if os.name != "nt":
            # Unix 下建立独立进程组，和 Windows taskkill /T 对称清理整个浏览器树。
            popen_kwargs["start_new_session"] = True
        try:
            proc = subprocess.Popen(args, **popen_kwargs)
        except Exception as exc:
            self._mark_failure()
            self._log("warning", "浏览器启动失败：%s" % exc)
            raise HuaweiAuthError("浏览器进程启动失败") from exc
        ws = None
        try:
            try:
                self._wait_cdp(port)
            except HuaweiAuthError as exc:
                raise HuaweiAuthError("%s；可能是上次浏览器未退出，请重试或手动结束 msedge 进程" % exc) from exc
            ws = self._attach(port)
            self._call(ws, "Network.setCookies", {"cookies": cookies})
            self._call(ws, "Page.enable")
            self._call(ws, "Runtime.enable")
            self._call(ws, "Page.navigate", {"url": TRAINING_CAMP_URL})

            token = self._wait_token(ws, timeout=min(25, self.page_timeout))
            if not token:
                self._log("info", "未持 token，点击「登录」走 OAuth 自动授权…")
                self._click_login(ws)
                token = self._wait_token(ws, timeout=min(40, self.page_timeout))

            if not token:
                raise HuaweiAuthError(
                    "自动登录失败：页面未拿到 accessToken。"
                    "多半是 cookie 已过期，请重新从浏览器导出 cookie 导入插件。"
                )

            # 回写新 cookie（滚续）
            try:
                fresh = self._call(ws, "Network.getAllCookies").get("result", {}).get("cookies", [])
                if len(fresh) >= max(5, len(cookies) // 2):
                    if self.save_cookies([normalize_cookie(c) for c in fresh], cookie_mtime_ns):
                        self._log("info", "cookie 已回写：%d → %d 条" % (len(cookies), len(fresh)))
            except Exception as exc:  # 回写失败不影响本次取数
                self._log("warning", "cookie 回写失败：%s" % exc)

            # 页面提供的过期时间优先用于后续缓存 TTL；旧页面没有该字段时保留安全默认值。
            expire = self._js(ws, "sessionStorage.getItem('expireTime')")
            try:
                self.token_expire_at = float(expire) / (1000 if float(expire) > 10**11 else 1)
            except (TypeError, ValueError):
                self.token_expire_at = time.time() + 3000
            self._log("info", "认证成功，耗时 %.1f 秒" % (time.monotonic() - started))
            return token
        except Exception as exc:
            self._mark_failure()
            self._log("warning", "认证失败，耗时 %.1f 秒：%s" % (time.monotonic() - started, exc))
            raise
        finally:
            try:
                if ws is not None:
                    self._call(ws, "Browser.close", timeout=5)
                    ws.close()
            except Exception:
                pass
            self._stop_process(proc)

    # ---------- CDP 细节 ----------

    def _wait_cdp(self, port: int, timeout: int = 40):
        # 页面超时是整个 CDP 初始化阶段的上限，避免单独的端口轮询越界。
        deadline = time.monotonic() + min(max(1, timeout), max(1, self.page_timeout))
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:%d/json/version" % port,
                    timeout=min(2, max(1, self.page_timeout)),
                ) as r:
                    json.load(r)
                    return
            except Exception:
                time.sleep(0.5)
        raise HuaweiAuthError("浏览器调试端口未就绪（%d）" % port)

    def _attach(self, port: int):
        with urllib.request.urlopen("http://127.0.0.1:%d/json" % port, timeout=min(5, self.page_timeout)) as r:
            tabs = json.load(r)
        pages = [t for t in tabs if t.get("type") == "page"]
        if not pages:
            raise HuaweiAuthError("浏览器里没有可用页面目标")
        ws = websocket.create_connection(
            pages[0]["webSocketDebuggerUrl"], timeout=self.page_timeout, suppress_origin=True
        )
        ws.settimeout(min(3, self.page_timeout))
        return ws

    def _call(self, ws, method: str, params=None, timeout: int = None):
        # 所有 CDP 请求统一受 page_timeout 约束，超时抛明确异常供上层记录。
        timeout = min(timeout or self.page_timeout, max(1, self.page_timeout))
        self._seq = getattr(self, "_seq", 0) + 1
        mid = self._seq
        ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                msg = json.loads(ws.recv())
            except Exception:
                continue
            if msg.get("id") == mid:
                if msg.get("error"):
                    raise HuaweiAuthError("CDP 调用失败：%s" % msg["error"])
                return msg
        raise HuaweiAuthError("CDP 调用超时：%s（%.1f 秒）" % (method, timeout))

    def _stop_process(self, proc):
        """先优雅退出并等待，失败时杀掉整个进程组，避免孤儿浏览器。"""
        if proc is None:
            return
        try:
            proc.terminate()
        except Exception:
            pass
        # Windows 上 Popen 常拿到 Edge 启动器，terminate 只会结束父进程；
        # 无条件 taskkill /T /F 才能同步清理真正持有 profile 锁的子进程。
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=10,
                )
            except Exception:
                pass
        else:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=10,
                    )
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                proc.wait(timeout=3)
            except Exception:
                pass

    def _js(self, ws, expr: str):
        r = self._call(ws, "Runtime.evaluate", {
            "expression": expr, "returnByValue": True, "awaitPromise": True,
        })
        return r.get("result", {}).get("result", {}).get("value")

    def _wait_token(self, ws, timeout: int = 30) -> str:
        """轮询 sessionStorage.accessToken，避免死等固定秒数。"""
        deadline = time.monotonic() + min(timeout, max(1, self.page_timeout))
        while time.monotonic() < deadline:
            try:
                tok = self._js(ws, "sessionStorage.getItem('accessToken')")
            except Exception:
                tok = None
            if tok:
                return tok
            time.sleep(2)
        return ""

    def _click_login(self, ws) -> bool:
        """点掉页面上的「登录」按钮（前端随后会跳 OAuth）。"""
        expr = (
            "(()=>{const t='登录';"
            "const els=[...document.querySelectorAll('*')]"
            ".filter(e=>e.children.length===0&&e.innerText&&e.innerText.trim()===t);"
            "if(els.length){els[0].click();return 'clicked';}return 'notfound';})()"
        )
        # 点击轮询也必须受 page_timeout 约束，避免 CDP 正常超时后仍长时间阻塞。
        deadline = time.monotonic() + max(1, self.page_timeout)
        while time.monotonic() < deadline:
            try:
                if self._js(ws, expr) == "clicked":
                    return True
            except Exception:
                pass
            time.sleep(min(3, max(0.1, deadline - time.monotonic())))
        return False

    def _log(self, level: str, msg: str):
        if self.log:
            getattr(self.log, level, self.log.info)("[华为健康] " + msg)
