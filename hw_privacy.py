# -*- coding: utf-8 -*-
"""华为运动健康 · 错误信息脱敏

异常文本、HTTP 响应片段、CDP 目标地址会一路流进日志、LLM 工具输出和 WebUI
响应，里面经常夹着 cookie、accessToken、本机绝对路径和 AstrBot 会话标识。
本模块只做一件事：把 ``redact_error()`` 洗过的文本交给外面。

设计约束：
    - **纯函数、零依赖**：只 import ``re``，``hw_credentials`` / ``hw_client``
      这种底层模块也能直接引用，不会引入循环依赖；
    - **绝不抛异常**：脱敏工具自己报错会毁掉整条错误处理路径，所以对
      ``__str__`` 坏掉的对象也退化成类名；
    - **顺序有意义**：先整行、再键值、再独立 token 格式，最后才是 URL / 路径 /
      邮箱 / 会话这种通用模式。反过来的话，键值规则会把已经替换出来的
      ``[remote URL]`` 再吃掉一次。

覆盖的 11 条规则（编号与交付说明一一对应）：
    1. ``Authorization:`` / ``Set-Cookie:`` / ``Cookie:`` / ``X-Api-Key:`` 等请求头整行
    2. ``Bearer xxx`` / ``Basic xxx``
    3. 敏感键值对（token / password / cookie / secret / uid / session / ssecurity …）
    4. 已知 token 格式（ghp_ / sk- / AIza / AKIA / xox?- / sk_live_ / JWT / PEM 私钥块 …）
    5. 任意 URL
    6. Windows 绝对路径（盘符路径 ``C:\\...`` 与 UNC 共享路径 ``\\\\<server>\\<share>\\...``）
    7. POSIX 绝对路径
    8. 邮箱
    9. AstrBot 会话标识（``xxx:FriendMessage:yyy``）
    10. 控制字符折叠
    11. 截断到 180 字符；空输入返回异常类型名
"""

from __future__ import annotations

import re

#: 脱敏后文本的最大长度。日志行/工具返回值不需要更长。
MAX_LENGTH = 180

#: 各类占位符（与 privacy_gate 脚本的白名单对齐：含 ``***`` 的值视为已脱敏）。
HEADER_MASK = "***"
AUTH_MASK = "authorization=***"
VALUE_MASK = "***"
TOKEN_MASK = "***"
URL_MASK = "[remote URL]"
PATH_MASK = "[local path]"
EMAIL_MASK = "[email]"
SESSION_MASK = "[session]"

#: 需要整行抹掉的请求头名（HTTP + CDP 常见变体）。
_HEADER_NAMES = (
    "authorization",
    "proxy-authorization",
    "set-cookie",
    "cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
)

#: 敏感键名。比较时不分大小写；``-`` / ``_`` 都算分隔符。
#: 后三个（castgc / sid / hwid_cas_sid）是华为登录态的核心 cookie，泄露等于交出账号。
_SENSITIVE_KEYS = (
    "access_token", "refresh_token", "id_token", "auth_token", "token",
    "password", "passwd", "pwd", "passphrase",
    "client_secret", "secret", "secret_key", "access_key", "ssecurity",
    "authorization", "api_key", "api-key", "apikey", "x-api-key",
    "private_key", "privatekey",
    "cookie", "cookies", "set-cookie",
    "uid", "user_id", "bot_id", "platform_id", "openid", "unionid",
    "session", "session_id", "sessionid", "jsessionid",
    "castgc", "sid", "hwid_cas_sid", "ticket", "nonce", "signature",
)

#: 已知的第三方 token 格式（GitHub / OpenAI / Anthropic / Google / AWS / Slack / Stripe）。
_TOKEN_PATTERNS = (
    r"gh[pousr]_[A-Za-z0-9]{12,}",              # ghp_ / gho_ / ghu_ / ghs_ / ghr_
    r"github_pat_[A-Za-z0-9_]{20,}",
    r"sk-ant-[A-Za-z0-9_-]{6,}",                # Anthropic
    r"sk-(?:proj-)?[A-Za-z0-9_-]{12,}",         # OpenAI（含 sk-proj-）
    r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}",  # Stripe
    r"AIza[A-Za-z0-9_-]{20,}",                  # Google API key
    r"(?:AKIA|ASIA)[A-Z0-9]{16}",               # AWS access key id
    r"xox[baprs]-[A-Za-z0-9-]{8,}",             # Slack
    r"eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+){0,2}",  # JWT（华为 accessToken 也是长 base64）
)


_HEADER_ALTERNATION = "|".join(re.escape(name) for name in _HEADER_NAMES)

#: 规则 1a：行首的整行请求头（``Authorization: xxx`` 独占一行时最常见）。
_HEADER_LINE_RE = re.compile(
    r"(?im)^[ \t]*(?P<name>" + _HEADER_ALTERNATION + r")[ \t]*:[ \t]*[^\r\n]*$"
)
#: 规则 1b：行内兜底——异常文本经常把请求头和别的信息拼在同一行。
_HEADER_INLINE_RE = re.compile(
    r"(?i)(?<![\w-])(?P<name>" + _HEADER_ALTERNATION + r")[ \t]*:[ \t]*[^\r\n]*"
)

#: 规则 2：``Bearer xxx`` / ``Basic xxx``（值里允许 base64 的 ``+/=``）。
_AUTH_SCHEME_RE = re.compile(
    r"(?i)(?<![\w-])(?:bearer|basic)[ \t]+[A-Za-z0-9._~+/=\-]+"
)

#: 规则 3：``token=xxx`` / ``"password": "xxx"`` / ``CASTGC=TGT-...``。
_KV_RE = re.compile(
    r"(?i)(?<![\w-])(?P<key>"
    + "|".join(re.escape(key) for key in sorted(_SENSITIVE_KEYS, key=len, reverse=True))
    + r")(?![\w-])[ \t]*[\"']?[ \t]*(?:=|:)[ \t]*"
    # 已经是 ``***`` 的别再洗一次：否则规则 1 输出的 ``Authorization: ***``
    # 会被这里改写成 ``Authorization=***``，丢掉「整行请求头」的形态。
    r"(?!\*\*\*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&)\]}]+)"
)

#: 规则 4：已知 token 格式。
_TOKEN_RE = re.compile(r"(?i)\b(?:" + "|".join(_TOKEN_PATTERNS) + r")")

#: 规则 4 补充：PEM 私钥块（含 BEGIN/END 与裸块两种形态，块内一律抹掉）。
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
    r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)"
)

#: 规则 5：任意 URL（http/https/ws/wss/ftp）。
_URL_RE = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\s\"'<>]*[^\s\"'<>.,;:)\]]")

#: 规则 6：Windows 绝对路径。先处理带引号（路径里可能有空格），再处理裸路径。
#: 中间段允许 ``<>``（占位符 ``C:\\Users\\<账户>\\...`` 就是这种写法），
#: 末段排除 ``<>`` 以免把 ``<C:\\path>`` 的尖括号一起吃掉。
_WIN_QUOTED_PATH_RE = re.compile(
    r"(?i)([\"'])(?:[A-Z]:[\\/]|\\\\[^\\/\r\n]+[\\/])[^\"'\r\n]*\1"
)
_WIN_PATH_RE = re.compile(
    r"(?i)(?<![\w])(?:[A-Z]:[\\/]|\\\\[^\\/\s\"']+[\\/])"
    r"(?:[^\\/\r\n:*?\"'|]+[\\/])*"
    r"[^\\/\s\r\n:*?\"'<>|,;)\]}]+"
)

#: 规则 7：POSIX 绝对路径（``/home/x/.config``）。``//`` 开头的不算（那是 URL 的一部分）。
_POSIX_QUOTED_PATH_RE = re.compile(
    r"(?i)([\"'])/(?!/)[^\"'\r\n]+/[^\"'\r\n]*\1"
)
_POSIX_PATH_RE = re.compile(
    r"(?i)(?<![\w:/])/(?:[^/\r\n:;,\)\]\"'<>]+/)+[^/\s\r\n:;,\)\]\"'<>]+"
)

#: 规则 8：邮箱。
_EMAIL_RE = re.compile(r"(?i)\b[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

#: 规则 9：AstrBot 会话标识（unified_msg_origin 形如 ``webchat:FriendMessage:xxx``）。
_SESSION_RE = re.compile(
    r"(?i)\b[\w.-]+:(?:Friend|Group|Private|Guild|Temp)\w*Message:[\w.-]+"
)

#: 规则 10：控制字符。
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


def _as_text(error) -> str:
    """把任意对象转成文本；``__str__`` 坏掉时退回类名，绝不抛。"""
    try:
        return str(error)
    except Exception:
        try:
            return type(error).__name__
        except Exception:  # pragma: no cover - 理论上到不了
            return "unknown error"


def redact_error(error) -> str:
    """把异常/文本洗成可以安全展示的样子。

    Args:
        error: 异常对象、字符串或任意可 ``str()`` 的值。

    Returns:
        已脱敏的文本：最长 ``MAX_LENGTH`` 字符；输入为空时返回异常类型名
        （``redact_error("")`` 得到 ``"str"``）。
    """
    message = _as_text(error)

    # 规则 1：请求头整行。
    message = _HEADER_LINE_RE.sub(
        lambda m: "%s: %s" % (m.group("name"), HEADER_MASK), message)
    message = _HEADER_INLINE_RE.sub(
        lambda m: "%s: %s" % (m.group("name"), HEADER_MASK), message)
    # 规则 2：Bearer / Basic。
    message = _AUTH_SCHEME_RE.sub(AUTH_MASK, message)
    # 规则 3：敏感键值对。
    message = _KV_RE.sub(lambda m: "%s=%s" % (m.group("key"), VALUE_MASK), message)
    # 规则 4：已知 token 格式（含 PEM 私钥块）。
    message = _TOKEN_RE.sub(TOKEN_MASK, message)
    message = _PEM_RE.sub(TOKEN_MASK, message)
    # 规则 5：URL。
    message = _URL_RE.sub(URL_MASK, message)
    # 规则 6：Windows 绝对路径。
    message = _WIN_QUOTED_PATH_RE.sub(PATH_MASK, message)
    message = _WIN_PATH_RE.sub(PATH_MASK, message)
    # 规则 7：POSIX 绝对路径。
    message = _POSIX_QUOTED_PATH_RE.sub(PATH_MASK, message)
    message = _POSIX_PATH_RE.sub(PATH_MASK, message)
    # 规则 8：邮箱。
    message = _EMAIL_RE.sub(EMAIL_MASK, message)
    # 规则 9：AstrBot 会话标识。
    message = _SESSION_RE.sub(SESSION_MASK, message)
    # 规则 10：控制字符 → 空格，连续空白折叠。
    message = _CONTROL_RE.sub(" ", message)
    message = " ".join(message.split())
    # 规则 11：截断；空输入返回类型名。
    return message[:MAX_LENGTH] or type(error).__name__


__all__ = [
    "MAX_LENGTH",
    "AUTH_MASK",
    "EMAIL_MASK",
    "HEADER_MASK",
    "PATH_MASK",
    "SESSION_MASK",
    "TOKEN_MASK",
    "URL_MASK",
    "VALUE_MASK",
    "redact_error",
]
