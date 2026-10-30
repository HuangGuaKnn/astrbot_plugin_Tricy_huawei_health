"""Fail closed when source files or release archives contain private material.

Two modes::

    python scripts/privacy_gate.py --repository .
    python scripts/privacy_gate.py --archive dist/astrbot_plugin_Tricy_huawei_health-v0.4.2.zip

``--archive`` accepts several paths and shell-style globs, so the CI step
``python scripts/privacy_gate.py --archive dist/*.zip`` works on every shell
(PowerShell does not expand wildcards for native commands).

Public interface reused by ``scripts/build_release.py``::

    assert_archive_clean(archive_path: Path) -> None

The gate never prints matched content: a violation is rendered as
``<scope>:<path>:<line> [<rule>]`` so the report itself stays safe to paste.

Design notes
------------
* Shipped content is checked twice: the source tree (``--repository``) and the
  built ZIP (``--archive``, also called from ``build_release.py``).
* Values carrying ``synthetic`` / ``example`` / ``dummy`` / ``fake`` /
  ``placeholder`` / ``redacted`` / ``***`` / ``示例`` are documentation
  placeholders and pass, so README examples do not break the gate.
* ``tests/`` trees hold deliberately realistic fake credentials; content rules
  would reject every test suite, and tests are never shipped (the release
  manifest is explicit). Only path/size/binary rules apply to the worktree
  there. Archive mode still enforces every content rule on what actually ships.
* OS install locations (``%ProgramFiles%``-style browser executables) are
  legitimate code constants and pass; user-profile locations are rejected.
* The documented placeholder path form (a ``<account>`` / ``*`` / ``{user}``
  segment) passes because ``<`` and ``*`` are not legal path characters, so the
  pattern stops in front of them. A concrete account segment never stops there
  and is reported. UNC examples whose host is a generic placeholder word
  (``server``, ``host``, ``nas``, ...) also pass; a real machine name does not.
"""

from __future__ import annotations

import argparse
import ast
import glob
import hashlib
import os
import re
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# Sensitive key names must have exactly one authoritative source: the plugin's
# own redaction module.  Importing them here keeps this gate and
# ``redact_error`` from drifting apart -- a drift is precisely how the gate
# stopped recognising ``CASTGC`` / ``sid`` / ``hwid_cas_sid``, which are the
# cookies that *are* the Huawei login state.
_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))
try:
    from hw_privacy import _SENSITIVE_KEYS as _SHARED_SENSITIVE_KEYS
except ImportError:  # pragma: no cover - only when hw_privacy.py is absent
    print(
        "warning: privacy_gate: 无法从 hw_privacy 导入 _SENSITIVE_KEYS，"
        "回退到内置键名副本；两份清单可能已漂移，请检查 hw_privacy.py。",
        file=sys.stderr,
    )
    _SHARED_SENSITIVE_KEYS = (
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

#: Longest keys first so ``hwid_cas_sid`` wins over ``sid`` at the same offset.
_SHARED_KEY_ALTERNATION = "|".join(
    re.escape(key) for key in sorted(_SHARED_SENSITIVE_KEYS, key=len, reverse=True)
)
_SHARED_KEY_ALTERNATION_BYTES = _SHARED_KEY_ALTERNATION.encode("utf-8")

# SHA256 of the only approved binary asset (logo.png, computed from the repo).
APPROVED_LOGO_NAME = "logo.png"
APPROVED_LOGO_SHA256 = "e6b868228b296b1b849c2d27149e342bb0196fcbd7d6928c928339fa2e3bda37"

MAX_ARCHIVE_ENTRY_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 50 * 1024 * 1024

# Directories that are generated, version-control internals, or dependency trees.
#
# ``dist`` is build output: ``build_release.py`` writes the release ZIP there and
# the archive is gated separately (``--archive``), so scanning it again in
# repository mode would only make a clean tree fail *after* it has been built
# once.  Without this entry, running the CI steps in order works exactly once and
# every subsequent run reports ``private-artifact-file`` for the ZIP it just
# produced.  Nothing ships from ``dist``: the manifest in ``build_release.py`` is
# explicit and never includes it.
_SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "dist",
        "node_modules",
        "venv",
    }
)

# Values carrying one of these markers are documentation placeholders, not secrets.
_PLACEHOLDER_MARKERS = (
    b"synthetic",
    b"example",
    b"dummy",
    b"fake",
    b"placeholder",
    b"redacted",
    b"***",
    "示例".encode(),
)
# Code fragments (not secrets): pattern sources, list/dict displays, call sites.
_CODE_FRAGMENT_BYTES = b"[](){}<>"
# Windows install locations that are OS constants rather than personal paths.
_OS_PROGRAM_DIRECTORIES = (
    b"program files (x86)",
    b"program files",
    b"programdata",
    b"windows",
)
# Generic UNC host names that appear in documentation examples, never on a
# real workstation (a real share leak names the actual machine).
_PLACEHOLDER_UNC_HOSTS = (
    b"example",
    b"fileserver",
    b"host",
    b"hostname",
    b"nas",
    b"server",
    b"servername",
    b"share",
)

_FORBIDDEN_SUFFIXES = (
    "-journal",
    "-shm",
    "-wal",
    ".7z",
    ".bak",
    ".backup",
    ".db",
    ".db-journal",
    ".db-shm",
    ".db-wal",
    ".env",
    ".key",
    ".cred",
    ".log",
    ".pyc",
    ".pyo",
    ".rar",
    ".sqlite",
    ".sqlite-journal",
    ".sqlite-shm",
    ".sqlite-wal",
    ".sqlite3",
    ".sqlite3-journal",
    ".sqlite3-shm",
    ".sqlite3-wal",
    ".zip",
)
_IMAGE_SUFFIXES = (
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".webp",
)
_PRIVATE_KEY_PATTERN = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_KNOWN_TOKEN_PATTERN = re.compile(
    rb"(?i)\b(?:"
    rb"gh[pousr]_[A-Za-z0-9]{20,}|"
    rb"sk-(?:ant-)?[A-Za-z0-9_-]{16,}|"
    rb"AIza[A-Za-z0-9_-]{24,}|"
    rb"AKIA[A-Z0-9]{16}|"
    rb"xox[baprs]-[A-Za-z0-9-]{16,}|"
    rb"(?:sk|rk)_live_[A-Za-z0-9]{16,}"
    rb")\b"
)
_SENSITIVE_NAME_PATTERN = re.compile(
    r"(?i)^(?:"
    r"[a-z0-9_-]*token|[a-z0-9_-]*(?:password|passwd|pwd)|"
    r"[a-z0-9_-]*cookie[a-z0-9_-]*|[a-z0-9_-]*secret[a-z0-9_-]*|"
    r"(?:c?user|session|owner|provider|persona)[a-z0-9_-]*id|"
    r"uid|platform_id|bot_id|ssecurity|authorization|api[_-]?key|"
    r"x-api-key|private[_-]?key|"
    + _SHARED_KEY_ALTERNATION
    + r")$"
)
_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    rb"(?i)\b(?:"
    rb"[a-z0-9_-]*token|[a-z0-9_-]*(?:password|passwd|pwd)|"
    rb"[a-z0-9_-]*cookie[a-z0-9_-]*|[a-z0-9_-]*secret[a-z0-9_-]*|"
    rb"(?:c?user|session|owner|provider|persona)[a-z0-9_-]*id|"
    rb"uid|platform_id|bot_id|ssecurity|authorization|api[_-]?key|"
    rb"x-api-key|private[_-]?key|"
    + _SHARED_KEY_ALTERNATION_BYTES
    + rb")[\"']?\s*(?:=|:)\s*(?:"
    rb'"(?P<double>[^"\r\n]*)"|\'(?P<single>[^\'\r\n]*)\'|'
    rb"(?P<unquoted>[^\s;,&\r\n]+))"
)
_BEARER_PATTERN = re.compile(
    rb"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+(?P<value>[^\s\r\n]+)"
)
# A request/response header line carrying ``name=value`` cookie pairs.
_COOKIE_HEADER_PATTERN = re.compile(
    rb"(?i)\b(?:set-)?cookie\s*:\s*(?P<value>[^\r\n]+)"
)
# Cookie-jar dumps and pasted browser cookies: ``CASTGC=TGT-...; sid=...``.
_COOKIE_PAIR_PATTERN = re.compile(
    rb"(?i)(?<![\w-])(?:"
    rb"castgc|jsessionid|hwid_cas_sid|casloginsite|loginaccsite|"
    rb"sessionid|session_id|sid|uid"
    rb")\s*=\s*(?P<value>[A-Za-z0-9][A-Za-z0-9._%~+/=-]{7,})"
)
# Huawei ``CASTGC`` values look like ``TGT-<digits>-<alnum>``.  Keying off the
# *value shape* keeps the gate working even when the key name is rewritten,
# translated, quoted as a JSON key, or dropped entirely.
_CASTGC_VALUE_PATTERN = re.compile(rb"(?i)(?<![\w-])TGT-\d+-[A-Za-z0-9]{6,}")
_URL_USERINFO_PATTERN = re.compile(rb"(?i)https?://[^\s/:]+:[^\s/@]+@")
_WINDOWS_PATH_PATTERN = re.compile(
    rb"(?ix)(?<![\w])(?:"
    rb"[A-Z]:[\\/](?![\]\\(){}*+?.^$|])"
    rb"(?:[^\\/\r\n:*?\"<>|,;\)\]]+[\\/])*"
    rb"[^\\/\s\r\n:*?\"<>|,;\)\]]+|"
    rb"\\\\[A-Z0-9._-]+[\\/][A-Z0-9 $._-]+[\\/]"
    rb"(?:[^\\/\r\n:*?\"<>|,;\)\]]+[\\/])*"
    rb"[^\\/\s\r\n:*?\"<>|,;\)\]]+"
    rb")"
)
_PERSONAL_POSIX_PATH_PATTERN = re.compile(
    rb"(?ix)(?<![\w:/])(?:"
    rb"/(?:home|Users)/[^/\s]+/(?:[^/\r\n:;,]+/)*[^/\s\r\n:;,\)\]]+|"
    rb"/root/(?:[^/\r\n:;,]+/)*[^/\s\r\n:;,\)\]]+|"
    rb"/mnt/[a-z]/Users/[^/\s]+/(?:[^/\r\n:;,]+/)*[^/\s\r\n:;,\)\]]+"
    rb")"
)
_PLATFORM_LOG_PATTERN = re.compile(
    rb"(?m)^\[(?:\d{2}:\d{2}:\d{2}(?:\.\d+)?|"
    rb"\d{4}-\d{2}-\d{2}[^\]]*)\].*"
    rb"(?:event_bus|star_manager|plugin_service)"
)


@dataclass(frozen=True, slots=True)
class Violation:
    """One safe-to-print privacy gate failure without the matched content."""

    scope: str
    path: str
    rule: str
    line: int | None = None

    def render(self) -> str:
        location = f"{self.scope}:{self.path}"
        if self.line is not None:
            location += f":{self.line}"
        return f"{location} [{self.rule}]"


def _line_number(payload: bytes, offset: int) -> int:
    return payload.count(b"\n", 0, max(offset, 0)) + 1


def _is_test_path(path: str) -> bool:
    """True for test trees, where realistic fake credentials are expected."""
    parts = PurePosixPath(path).parts
    if parts and parts[0].lower() in {"test", "tests"}:
        return True
    return PurePosixPath(path).name.lower().startswith("test_")


def _is_placeholder(value: bytes) -> bool:
    """True when a value is documentation filler or a code fragment."""
    normalized = value.strip(b"\"'").lower()
    if not normalized or normalized in {b"none", b"null", b"nil", b"true", b"false"}:
        return True
    if any(marker in normalized for marker in _PLACEHOLDER_MARKERS):
        return True
    # Regex sources and list/dict displays read like values but are code.
    if any(byte in _CODE_FRAGMENT_BYTES for byte in normalized):
        return True
    return False


def _looks_like_credential(value: bytes) -> bool:
    """True when a value has the shape of a credential rather than prose."""
    if len(value) < 8:
        return False
    if any(byte < 0x20 or byte > 0x7E for byte in value):
        return False
    return not any(byte in b" \t" for byte in value)


#: 插件自身的配置键名。前端会把这些键当字符串字面量写（例如
#: ``const COOKIE_JSON_PATH = "cookie_json";``），而 ``_SENSITIVE_ASSIGNMENT_PATTERN``
#: 里有一条 ``[a-z0-9_-]*cookie[a-z0-9_-]*`` 且带 ``(?i)``，会把
#: ``COOKIE_JSON_PATH = "x"`` 整个匹配上，右侧的键名字符串就被当成了凭据值——
#: 每次新增 cookie 字段都会误报一次。新增 cookie 配置项时请同步这里。
_CONFIG_KEY_LITERALS = frozenset(
    name.encode("utf-8")
    for name in (
        "cookie_json",
        "cookie_CASTGC",
        "cookie_sid",
        "cookie_hwid_cas_sid",
        "cookie_HuaweiID_CAS_ISCASLOGIN",
        "cookie_CASLOGINSITE",
        "cookie_LOGINACCSITE",
    )
)


def _is_secret_value(value: bytes) -> bool:
    # 值本身就是配置键名 -> 不含任何凭据，别当泄露。
    if value.strip() in _CONFIG_KEY_LITERALS:
        return False
    return _looks_like_credential(value) and not _is_placeholder(value)


def _is_os_program_path(match: bytes) -> bool:
    """True for ``C:\\Program Files\\...``-style OS install locations.

    Paths containing parentheses are truncated by the pattern (the class avoids
    brackets to stay clear of regex sources), so the first segment is matched as
    a prefix of a known install directory.
    """
    normalized = match.replace(b"/", b"\\").lower()
    _, separator, remainder = normalized.partition(b":\\")
    if not separator:
        return False
    first_segment = remainder.split(b"\\", 1)[0].strip()
    if not first_segment:
        return False
    return any(
        directory.startswith(first_segment) for directory in _OS_PROGRAM_DIRECTORIES
    )


def _is_placeholder_unc(match: bytes) -> bool:
    """True for UNC examples whose host segment is a generic placeholder."""
    normalized = match.replace(b"/", b"\\").lower()
    if not normalized.startswith(b"\\\\"):
        return False
    segments = [segment for segment in normalized[2:].split(b"\\") if segment]
    if not segments:
        return False
    return segments[0] in _PLACEHOLDER_UNC_HOSTS


def _stops_at_placeholder(payload: bytes, end: int) -> bool:
    """True when a path match ends right before a ``<placeholder>`` segment.

    ``C:\\Users\\<account>\\...`` is the documented placeholder form: ``<`` and
    ``*`` are not legal path characters, so the pattern stops in front of them.
    A concrete account segment never stops there and is still reported.
    """
    markers = (b"<", b"*", b"{")
    if payload[end : end + 1] in markers:
        return True
    return payload[end : end + 1] in (b"\\", b"/") and payload[end + 1 : end + 2] in markers


def _forbidden_path_reason(relative_path: str) -> str | None:
    """Return a rule name when the path itself is not shippable."""
    path = PurePosixPath(relative_path.replace("\\", "/"))
    lowered_parts = tuple(part.lower() for part in path.parts)
    lowered_name = path.name.lower()
    if any(
        part in {"logs", "log", "screenshots", "screenshot"} for part in lowered_parts
    ):
        return "private-artifact-path"
    if any(part == "browser_profile" or part.startswith("login_browser_") for part in lowered_parts):
        return "browser-profile-path"
    if lowered_name == ".env" or lowered_name.startswith(".env."):
        if lowered_name not in {".env.example", ".env.template"}:
            return "environment-file"
    if lowered_name.startswith(("screenshot", "截图")):
        return "screenshot-file"
    if lowered_name != APPROVED_LOGO_NAME and lowered_name.endswith(_IMAGE_SUFFIXES):
        return "unapproved-image"
    if lowered_name.endswith(_FORBIDDEN_SUFFIXES):
        return "private-artifact-file"
    return None


def _text_violations(
    payload: bytes,
    path: str,
    scope: str,
    *,
    check_assignments: bool,
    base_line: int = 1,
) -> list[Violation]:
    """Run every content rule over text payload (a whole file or one literal)."""
    violations: list[Violation] = []

    def add(rule: str, offset: int) -> None:
        line = base_line + _line_number(payload, offset) - 1
        violations.append(Violation(scope, path, rule, line))

    match = _PRIVATE_KEY_PATTERN.search(payload)
    if match:
        add("private-key-literal", match.start())
    match = _URL_USERINFO_PATTERN.search(payload)
    if match:
        add("credential-in-url", match.start())
    for match in _KNOWN_TOKEN_PATTERN.finditer(payload):
        if not _is_placeholder(match.group(0)):
            add("known-token-literal", match.start())
            break
    for match in _BEARER_PATTERN.finditer(payload):
        if _is_secret_value(match.group("value")):
            add("authorization-literal", match.start())
            break
    for match in _COOKIE_HEADER_PATTERN.finditer(payload):
        pairs = [part.partition(b"=") for part in match.group("value").split(b";")]
        if any(
            separator
            and _is_secret_value(part.strip())
            for _, separator, part in pairs
        ):
            add("cookie-header-literal", match.start())
            break
    for match in _COOKIE_PAIR_PATTERN.finditer(payload):
        if _is_secret_value(match.group("value")):
            add("session-cookie-literal", match.start())
            break
    for match in _CASTGC_VALUE_PATTERN.finditer(payload):
        if not _is_placeholder(match.group(0)):
            add("huawei-castgc-literal", match.start())
            break
    if check_assignments:
        for match in _SENSITIVE_ASSIGNMENT_PATTERN.finditer(payload):
            value = (
                match.group("double")
                or match.group("single")
                or match.group("unquoted")
                or b""
            )
            if _is_secret_value(value):
                add("sensitive-value-literal", match.start())
                break
    for match in _WINDOWS_PATH_PATTERN.finditer(payload):
        # A placeholder segment (``<account>``, ``*``, ``{user}``) is not a legal
        # path character, so the pattern stops in front of it: such a match is a
        # documentation placeholder, not a real local path.
        if _stops_at_placeholder(payload, match.end()):
            continue
        if (
            _is_os_program_path(match.group(0))
            or _is_placeholder_unc(match.group(0))
            or _is_placeholder(match.group(0))
        ):
            continue
        add("local-windows-path", match.start())
        break
    for match in _PERSONAL_POSIX_PATH_PATTERN.finditer(payload):
        if _is_placeholder(match.group(0)):
            continue
        add("local-posix-path", match.start())
        break
    match = _PLATFORM_LOG_PATTERN.search(payload)
    if match:
        add("platform-log-content", match.start())
    return violations


def _python_violations(text: str, path: str, scope: str) -> list[Violation]:
    """Check Python sources via AST so variables are not mistaken for values."""
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError:
        return [Violation(scope, path, "invalid-python-source")]

    candidates: list[tuple[str, ast.expr]] = []

    def target_name(target: ast.expr) -> str | None:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                name = target_name(target)
                if name:
                    candidates.append((name, node.value))
        elif isinstance(node, ast.AnnAssign):
            name = target_name(node.target)
            if name and node.value is not None:
                candidates.append((name, node.value))
        elif isinstance(node, ast.keyword) and node.arg:
            candidates.append((node.arg, node.value))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    candidates.append((key.value, value))

    violations: list[Violation] = []
    for name, value_node in candidates:
        if not _SENSITIVE_NAME_PATTERN.fullmatch(name) or name.isupper():
            continue
        if not isinstance(value_node, ast.Constant) or not isinstance(
            value_node.value, (str, bytes)
        ):
            continue
        value = (
            value_node.value.encode("utf-8")
            if isinstance(value_node.value, str)
            else value_node.value
        )
        if _is_secret_value(value):
            violations.append(
                Violation(
                    scope,
                    path,
                    "sensitive-value-literal",
                    getattr(value_node, "lineno", None),
                )
            )
            break

    # Secrets pasted inside string literals are still shipped bytes.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        if isinstance(node.value, str):
            literal = node.value.encode("utf-8")
        elif isinstance(node.value, bytes):
            literal = node.value
        else:
            continue
        if len(literal) < 8:
            continue
        violations.extend(
            _text_violations(
                literal,
                path,
                scope,
                check_assignments=False,
                base_line=getattr(node, "lineno", 1),
            )
        )
    return violations


def inspect_payload(relative_path: str, payload: bytes, scope: str) -> list[Violation]:
    """Inspect one repository/archive entry without ever returning matched values."""
    path = relative_path.replace("\\", "/")
    path_reason = _forbidden_path_reason(path)
    if path_reason:
        return [Violation(scope, path, path_reason)]
    if PurePosixPath(path).name.lower() == APPROVED_LOGO_NAME:
        if hashlib.sha256(payload).hexdigest() != APPROVED_LOGO_SHA256:
            return [Violation(scope, path, "unapproved-logo-content")]
        return []
    if b"\x00" in payload:
        return [Violation(scope, path, "unexpected-binary-content")]
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return [Violation(scope, path, "non-utf8-content")]
    if scope == "worktree" and _is_test_path(path):
        # Test fixtures intentionally hold realistic fake credentials; they are
        # never part of the release manifest, and archive mode still checks
        # every content rule on what actually ships.
        return []
    if path.lower().endswith(".py"):
        return _python_violations(text, path, scope)
    return _text_violations(payload, path, scope, check_assignments=True)


def scan_repository_tree(repository_root: Path) -> list[Violation]:
    """Scan every shippable file of a source tree, skipping generated internals."""
    repository_root = repository_root.resolve()
    violations: list[Violation] = []
    for current_root, directory_names, file_names in os.walk(repository_root):
        directory_names[:] = sorted(
            name for name in directory_names if name not in _SKIPPED_DIRECTORIES
        )
        for file_name in sorted(file_names):
            file_path = Path(current_root) / file_name
            relative = file_path.relative_to(repository_root).as_posix()
            if file_path.is_symlink():
                violations.append(Violation("worktree", relative, "symlink"))
                continue
            try:
                size = file_path.stat().st_size
            except OSError:
                violations.append(Violation("worktree", relative, "unreadable-file"))
                continue
            if size > MAX_ARCHIVE_ENTRY_BYTES:
                violations.append(Violation("worktree", relative, "entry-too-large"))
                continue
            violations.extend(inspect_payload(relative, file_path.read_bytes(), "worktree"))
    return violations


def scan_archive(archive_path: Path) -> list[Violation]:
    """Scan one ZIP in memory without extracting private material to disk."""
    violations: list[Violation] = []
    with zipfile.ZipFile(archive_path) as archive:
        names = [entry.filename for entry in archive.infolist()]
        for name, count in Counter(names).items():
            if count > 1:
                violations.append(Violation("archive", name, "duplicate-entry"))
        total_size = 0
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or ".." in path.parts:
                violations.append(Violation("archive", entry.filename, "unsafe-path"))
                continue
            if entry.flag_bits & 0x1:
                violations.append(Violation("archive", entry.filename, "encrypted-entry"))
                continue
            mode = (entry.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                violations.append(Violation("archive", entry.filename, "symlink"))
                continue
            total_size += entry.file_size
            if entry.file_size > MAX_ARCHIVE_ENTRY_BYTES:
                violations.append(Violation("archive", entry.filename, "entry-too-large"))
                continue
            if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                violations.append(Violation("archive", entry.filename, "archive-too-large"))
                break
            violations.extend(
                inspect_payload(entry.filename, archive.read(entry), "archive")
            )
    return violations


def assert_clean(violations: list[Violation]) -> None:
    """Raise with only safe path/rule diagnostics when any violation exists."""
    if violations:
        rendered = "\n".join(violation.render() for violation in violations)
        raise ValueError("privacy gate rejected content:\n" + rendered)


def assert_archive_clean(archive_path: Path) -> None:
    """Fail closed when a release archive carries private material."""
    assert_clean(scan_archive(Path(archive_path)))


def _expand_archives(raw_values: list[str]) -> list[Path]:
    """Expand shell-style globs that PowerShell refuses to expand itself."""
    archives: list[Path] = []
    for raw_value in raw_values:
        if any(character in raw_value for character in "*?["):
            for match in sorted(glob.glob(raw_value)):
                candidate = Path(match)
                if candidate.is_file():
                    archives.append(candidate)
            continue
        archives.append(Path(raw_value))
    return archives


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail closed when sources or a release ZIP contain private material."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--repository", type=Path, metavar="ROOT")
    group.add_argument("--archive", type=str, nargs="+", metavar="ZIP")
    arguments = parser.parse_args(argv)
    try:
        if arguments.repository is not None:
            repository_root = arguments.repository.resolve()
            if not repository_root.is_dir():
                print(
                    f"privacy gate: not a directory: {arguments.repository}",
                    file=sys.stderr,
                )
                return 2
            assert_clean(scan_repository_tree(repository_root))
            print(f"Repository privacy gate: clean ({repository_root.name})")
            return 0
        archives = _expand_archives(arguments.archive)
        if not archives:
            print(
                "privacy gate: no archive matched " + " ".join(arguments.archive),
                file=sys.stderr,
            )
            return 2
        for archive_path in archives:
            if not archive_path.is_file():
                print(f"privacy gate: not a file: {archive_path}", file=sys.stderr)
                return 2
            assert_archive_clean(archive_path)
            print(f"Release privacy gate: clean ({archive_path.name})")
        return 0
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
