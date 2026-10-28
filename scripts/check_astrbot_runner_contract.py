#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AstrBot 插件接口契约检查（纯静态 AST，不需要 import astrbot）。

本脚本只回答一个问题：**这份 AstrBot 源码，还认不认本插件的用法？**

它把 main.py / hw_webapi.py 依赖的每一个 AstrBot 接口点都变成一条断言，因此既能
在 CI 里对着「最低支持版本」的源码树跑，也能对着最新稳定版跑（不需要真的安装、
不需要起 AstrBot 进程，因此两条通道共用同一份脚本）。

用法：
    python scripts/check_astrbot_runner_contract.py
    python scripts/check_astrbot_runner_contract.py --astrbot-root <含 astrbot/ 包的目录>

AstrBot 源码根的确定顺序（脚本内不写死任何本机路径）：
    1. --astrbot-root 参数（可以是包含 astrbot/ 的目录，也可以直接是 astrbot/ 包目录）
    2. 环境变量 ASTRBOT_ROOT
    3. import astrbot 后取 astrbot.__file__ 的父目录

退出码：0 = 全部通过；1 = 有断言失败（逐条打印原因，不静默跳过）。
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
METADATA_FILE = "metadata.yaml"


class ContractViolation(AssertionError):
    """一条契约断言不成立。"""


def _violation(message: str) -> None:
    raise ContractViolation(message)


# --------------------------------------------------------------------------- #
# AST 工具
# --------------------------------------------------------------------------- #


def _parse(path: Path) -> ast.Module:
    if not path.is_file():
        _violation(f"缺少 AstrBot 源码文件：{path}")
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        _violation(f"AstrBot 源码读取/解析失败：{path}: {exc}")


def _class_node(module: ast.Module, name: str) -> ast.ClassDef:
    for node in module.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    _violation(f"找不到类 {name}")


def _method_node(
    class_node: ast.ClassDef,
    name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in class_node.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    _violation(f"找不到方法 {class_node.name}.{name}")


def _function_node(
    module: ast.Module,
    name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    _violation(f"找不到模块级函数 {name}")


def _positional_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [arg.arg for arg in (*func.args.posonlyargs, *func.args.args)]


def _required_positional_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    params = _positional_params(func)
    return params[: len(params) - len(func.args.defaults)]


def _keyword_only_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [arg.arg for arg in func.args.kwonlyargs]


def _module_level_bindings(module: ast.Module) -> dict[str, str]:
    """模块顶层名字 -> 绑定来源。

    来源形如 ``import:astrbot.core.star.register.register_llm_tool``、``assign``、
    ``def``、``class``。用来确认「插件写的那条 import 路径还在，且指向原来那个东西」。
    """
    bindings: dict[str, str] = {}
    for node in module.body:
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local = alias.asname or alias.name
                bindings[local] = f"import:{node.module or ''}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                bindings[local] = f"import:{alias.name}"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bindings[node.name] = "def"
        elif isinstance(node, ast.ClassDef):
            bindings[node.name] = "class"
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = "assign"
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            bindings[node.target.id] = "assign"
    return bindings


def _module_all(module: ast.Module) -> list[str] | None:
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    try:
                        value = ast.literal_eval(node.value)
                    except (ValueError, SyntaxError):
                        return None
                    return [str(item) for item in value] if isinstance(value, (list, tuple)) else None
    return None


def _require_export(module: ast.Module, label: str, name: str, source_suffix: str) -> None:
    """断言 ``name`` 在模块顶层绑定，且来源以 ``source_suffix`` 结尾；有 __all__ 时还要在 __all__ 里。"""
    bindings = _module_level_bindings(module)
    if name not in bindings:
        _violation(f"{label} 不再提供 {name}")
    source = bindings[name]
    if source_suffix and not source.endswith(source_suffix):
        _violation(f"{label}.{name} 的来源变了（现在是 {source}，期望以 {source_suffix} 结尾）")
    exported = _module_all(module)
    if exported is not None and name not in exported:
        _violation(f"{label} 的 __all__ 里不再有 {name}")


def _calls_with_name(module: ast.Module, func_name: str) -> list[ast.Call]:
    found: list[ast.Call] = []
    for node in ast.walk(module):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == func_name:
            found.append(node)
        elif isinstance(func, ast.Attribute) and func.attr == func_name:
            found.append(node)
    return found


def _awaited_attribute_calls(module: ast.Module, attr: str) -> list[ast.Await]:
    found: list[ast.Await] = []
    for node in ast.walk(module):
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Attribute) and func.attr == attr:
                found.append(node)
    return found


def _string_constants(node: ast.AST) -> set[str]:
    values: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            values.add(child.value)
    return values


# --------------------------------------------------------------------------- #
# 版本：源码树版本 vs metadata.yaml 声明
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Tree:
    root: Path
    version: str | None
    """源码树自报的版本；读不出来就是 None（例如 <= 4.25.x 没有 __version__ 字段）。"""

    @property
    def package(self) -> Path:
        return self.root / "astrbot"

    def source(self, relative: str) -> ast.Module:
        return _parse(self.package / relative)


def _version_from_source(root: Path) -> str | None:
    module = _parse(root / "astrbot" / "__init__.py")
    for node in module.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if value is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "__version__":
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value
    return None


def _declared_spec(repo_root: Path) -> str:
    """从 metadata.yaml 读 astrbot_version（单一事实来源，不在脚本里重复写死）。"""
    metadata_path = repo_root / METADATA_FILE
    if not metadata_path.is_file():
        _violation(f"仓库根目录缺少 {METADATA_FILE}")
    text = metadata_path.read_text(encoding="utf-8")

    value = None
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        yaml = None  # type: ignore[assignment]
    if yaml is not None:
        data = yaml.safe_load(text) or {}
        if isinstance(data, dict):
            value = data.get("astrbot_version")
    if value is None:
        # 没装 PyYAML 时的兜底：只取这一个字段，够用且不引入新依赖。
        match = re.search(r"^astrbot_version:\s*(.+?)\s*$", text, re.MULTILINE)
        if match:
            value = match.group(1).strip().strip("'\"")
    if not isinstance(value, str) or not value.strip():
        _violation(f"{METADATA_FILE} 缺少可用的 astrbot_version 字段")
    return value.strip()


def _check_declared_version_range(tree: Tree, repo_root: Path) -> None:
    spec_text = _declared_spec(repo_root)
    if tree.version is None:
        _violation(
            "这份源码树的 astrbot/__init__.py 里没有 __version__ 字段（AstrBot <= 4.25.x 的形态），"
            f"无法满足 metadata.yaml 声明的 {spec_text!r}",
        )
    try:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
        from packaging.version import InvalidVersion, Version
    except ImportError:  # pragma: no cover - AstrBot 自身依赖 packaging
        _violation(
            "校验 astrbot_version 需要 packaging（AstrBot 自身依赖它）；"
            "请先 `pip install packaging`",
        )
    try:
        specifier = SpecifierSet(spec_text)
    except InvalidSpecifier:
        _violation(f"metadata.yaml 的 astrbot_version 不是合法 PEP 440 区间：{spec_text!r}")
    try:
        version = Version(tree.version)
    except InvalidVersion:
        _violation(f"AstrBot 源码版本号不是合法 PEP 440 版本：{tree.version!r}")
    if not specifier.contains(version, prereleases=True):
        _violation(
            f"这份 AstrBot 源码版本 {tree.version} 不满足 metadata.yaml 声明的 "
            f"astrbot_version {spec_text!r}（AstrBot 加载插件时用同一套 SpecifierSet 校验）",
        )


# --------------------------------------------------------------------------- #
# 逐条契约断言
# --------------------------------------------------------------------------- #


def _check_api_package(tree: Tree) -> None:
    """main.py: `from astrbot.api import AstrBotConfig, logger`。"""
    module = tree.source("api/__init__.py")
    _require_export(module, "astrbot.api", "AstrBotConfig", "astrbot_config.AstrBotConfig")
    _require_export(module, "astrbot.api", "logger", "")


def _check_api_event_package(tree: Tree) -> None:
    """main.py: `from astrbot.api.event import AstrMessageEvent, filter`。

    ``filter`` 是子模块（`astrbot/api/event/filter/`），`from package import submodule`
    能成立的前提是该子模块文件还在，所以这里检查文件本身。
    """
    module = tree.source("api/event/__init__.py")
    _require_export(module, "astrbot.api.event", "AstrMessageEvent", "")
    filter_init = tree.package / "api" / "event" / "filter" / "__init__.py"
    if not filter_init.is_file():
        _violation("astrbot.api.event 下没有 filter 子模块，`from astrbot.api.event import filter` 会失败")


def _check_filter_llm_tool(tree: Tree) -> None:
    """main.py: 8 处 `@filter.llm_tool(name="health_xxx")`。"""
    module = tree.source("api/event/filter/__init__.py")
    _require_export(
        module,
        "astrbot.api.event.filter",
        "llm_tool",
        "astrbot.core.star.register.register_llm_tool",
    )


def _check_api_star_package(tree: Tree) -> None:
    """main.py: `from astrbot.api.star import Context, Star, register`。"""
    module = tree.source("api/star/__init__.py")
    _require_export(module, "astrbot.api.star", "Context", "")
    _require_export(module, "astrbot.api.star", "Star", "")
    _require_export(module, "astrbot.api.star", "register", "register.register_star")


def _check_api_web_module(tree: Tree) -> None:
    """hw_webapi.py: `from astrbot.api.web import json_response, request`。

    这一条是本插件版本下限的直接来源：该模块随 v4.26.0 的 Quart→FastAPI 迁移引入。
    """
    module = tree.source("api/web.py")

    json_response = _function_node(module, "json_response")
    required = _required_positional_params(json_response)
    if required:
        _violation(
            "json_response 出现必填位置参数 "
            f"{required}；插件按 json_response(data, status_code=...) 调用",
        )
    if "data" not in _positional_params(json_response):
        _violation("json_response 不再接受 data 位置参数")
    missing_kwonly = {"status_code", "headers"} - set(_keyword_only_params(json_response))
    if missing_kwonly:
        _violation(
            "json_response 不再接受关键字参数 " + ", ".join(sorted(missing_kwonly)),
        )

    bindings = _module_level_bindings(module)
    if bindings.get("request") != "assign":
        _violation("astrbot.api.web 不再在模块级导出 request（插件在 handler 里 await request.json()）")
    if "PluginRequestProxy" not in bindings:
        _violation("astrbot.api.web 不再定义 PluginRequestProxy")

    plugin_request = _class_node(module, "PluginRequest")
    json_method = _method_node(plugin_request, "json")
    if not isinstance(json_method, ast.AsyncFunctionDef):
        _violation("PluginRequest.json 不再是 async，`await request.json()` 会失效")

    proxy = _class_node(module, "PluginRequestProxy")
    proxy_members = {
        node.name
        for node in proxy.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for member in ("json", "query"):
        if member not in proxy_members:
            _violation(f"PluginRequestProxy 不再提供 {member}，插件的 request 代理用法会失效")

    bind = _function_node(module, "bind_request_context")
    decorators = {
        getattr(decorator, "id", None) or getattr(decorator, "attr", None)
        for decorator in bind.decorator_list
    }
    if "contextmanager" not in decorators:
        _violation("bind_request_context 不再以 @contextmanager 提供，`with bind_request_context(...)` 会失效")


def _check_register_star(tree: Tree) -> None:
    """main.py: `@register(PLUGIN_NAME, author, desc, "v0.4.2")` —— 4 个位置参数。"""
    module = tree.source("core/star/register/star.py")
    func = _function_node(module, "register_star")
    params = _positional_params(func)
    expected = ["name", "author", "desc", "version", "repo"]
    if params[:4] != expected[:4]:
        _violation(f"register_star 前 4 个位置参数变成 {params[:4]}，期望 {expected[:4]}")
    required = _required_positional_params(func)
    if required != expected[:4]:
        _violation(
            f"register_star 必填位置参数变成 {required}，期望 {expected[:4]}"
            "（插件用 4 个位置参数注册）",
        )


def _check_register_llm_tool(tree: Tree) -> None:
    """`@filter.llm_tool(name="health_status")`：必须接受 name 关键字。"""
    module = tree.source("core/star/register/star_handler.py")
    func = _function_node(module, "register_llm_tool")
    params = _positional_params(func)
    if not params or params[0] != "name":
        _violation(f"register_llm_tool 的第一个位置参数变成 {params[:1]}，期望 name")
    if not func.args.defaults:
        _violation("register_llm_tool 的 name 不再有默认值，`@filter.llm_tool()` 无参用法会失效")
    if not func.args.kwarg:
        _violation("register_llm_tool 不再接受 **kwargs（插件依赖它透传 name）")


def _check_star_base(tree: Tree) -> None:
    """main.py: `class HuaweiHealthPlugin(Star)` + `super().__init__(context)`。"""
    module = tree.source("core/star/base.py")
    star = _class_node(module, "Star")
    init = _method_node(star, "__init__")
    params = _positional_params(init)
    if params[:2] != ["self", "context"]:
        _violation(f"Star.__init__ 前两个参数变成 {params[:2]}，期望 ['self', 'context']")
    optional = params[len(params) - len(init.args.defaults):] if init.args.defaults else []
    if "config" in params and "config" not in optional:
        _violation("Star.__init__ 的 config 不再有默认值，`super().__init__(context)` 会 TypeError")


def _check_lifecycle_hooks(tree: Tree) -> None:
    """main.py 的 `initialize()` / `terminate()` 由加载器按名字可选调用。"""
    module = tree.source("core/star/star_manager.py")

    initialize_guarded = False
    for call in _calls_with_name(module, "hasattr"):
        if "initialize" in _string_constants(call):
            initialize_guarded = True
            break
    if not initialize_guarded:
        _violation("插件加载器不再用 hasattr(..., 'initialize') 判断，initialize() 可能不会被调用")
    if not _awaited_attribute_calls(module, "initialize"):
        _violation("插件加载器不再 await 插件的 initialize()")

    terminate_guarded = False
    for node in ast.walk(module):
        if isinstance(node, ast.Compare) and "terminate" in _string_constants(node):
            terminate_guarded = True
            break
    if not terminate_guarded:
        _violation("插件卸载逻辑不再按名字检查 terminate，terminate() 可能不会被调用")
    if not _awaited_attribute_calls(module, "terminate"):
        _violation("插件卸载逻辑不再 await 插件的 terminate()")


def _check_dashboard_dispatch(tree: Tree) -> None:
    """hw_webapi.py 的 handler 都是**零参数**方法，靠 AstrBot 的调度约定。

    AstrBot 以 `view_handler(**path_values)` 调用注册的 handler，并在
    `bind_request_context(...)` 里绑定 request 代理 —— 这两点任一改变，插件的
    WebUI 后端会整体失效（要么 TypeError，要么 request 代理拿不到请求）。
    """
    module = tree.source("dashboard/api/plugins.py")

    dispatch_found = False
    for call in _calls_with_name(module, "view_handler"):
        for keyword in call.keywords:
            if keyword.arg is None and isinstance(keyword.value, ast.Name):
                if keyword.value.id == "path_values":
                    dispatch_found = True
    if not dispatch_found:
        _violation("插件 Web API 的调度不再是 view_handler(**path_values)，零参数 handler 会失效")

    if not _calls_with_name(module, "bind_request_context"):
        _violation("插件 Web API 调度不再使用 bind_request_context，request 代理会拿不到请求")
    if not _calls_with_name(module, "PluginRequest"):
        _violation("插件 Web API 调度不再构造 PluginRequest，request 代理会拿不到请求")


def _check_config_class(tree: Tree) -> None:
    """main.py: `config.get("login_daily_limit")`，配置对象是 AstrBotConfig（dict 子类）。"""
    module = tree.source("core/config/astrbot_config.py")
    config_class = _class_node(module, "AstrBotConfig")
    base_names = {
        getattr(base, "id", None) or getattr(base, "attr", None)
        for base in config_class.bases
    }
    if "dict" not in base_names:
        _violation("AstrBotConfig 不再是 dict 子类，插件的 config.get(...) 用法会失效")
    init = _method_node(config_class, "__init__")
    params = _positional_params(init)
    for required_param in ("config_path", "schema"):
        if required_param not in params:
            _violation(f"AstrBotConfig.__init__ 不再接受 {required_param}")
        optional = params[len(params) - len(init.args.defaults):] if init.args.defaults else []
        if required_param not in optional:
            _violation(f"AstrBotConfig.__init__ 的 {required_param} 变成必填，冒烟脚本的构造方式会失效")


def _check_handler_registry(tree: Tree) -> None:
    """冒烟脚本用 star_handlers_registry 反查插件注册结果。"""
    module = tree.source("core/star/star_handler.py")
    bindings = _module_level_bindings(module)
    if bindings.get("star_handlers_registry") != "assign":
        _violation("astrbot.core.star.star_handler 不再在模块级提供 star_handlers_registry")
    registry = _class_node(module, "StarHandlerRegistry")
    _method_node(registry, "get_handlers_by_module_name")


def _check_register_web_api(tree: Tree) -> None:
    """hw_webapi.py: `reg(route, handler, ["GET"], "desc")` —— 4 个位置参数，顺序固定。"""
    module = tree.source("core/star/context.py")
    context_class = _class_node(module, "Context")
    method = _method_node(context_class, "register_web_api")
    params = _positional_params(method)
    expected = ["self", "route", "view_handler", "methods", "desc"]
    if params != expected:
        _violation(f"Context.register_web_api 的位置参数变成 {params}，期望 {expected}")
    if _required_positional_params(method) != expected:
        _violation(
            f"Context.register_web_api 的必填参数变成 {_required_positional_params(method)}，"
            f"期望全部必填 {expected}",
        )


CHECKS: tuple[tuple[str, Callable[[Tree], None]], ...] = (
    (
        "metadata.yaml 的 astrbot_version 与这份源码版本相容",
        lambda tree: _check_declared_version_range(tree, REPO_ROOT),
    ),
    ("astrbot.api 仍导出 AstrBotConfig / logger", _check_api_package),
    ("astrbot.api.event 仍导出 AstrMessageEvent / filter 子模块", _check_api_event_package),
    ("filter.llm_tool 仍指向 register_llm_tool", _check_filter_llm_tool),
    ("astrbot.api.star 仍导出 Context / Star / register", _check_api_star_package),
    ("astrbot.api.web 仍提供 json_response / request 代理", _check_api_web_module),
    ("register_star(name, author, desc, version) 签名未变", _check_register_star),
    ("register_llm_tool 仍接受 name 关键字", _check_register_llm_tool),
    ("Context.register_web_api(route, handler, methods, desc) 签名未变", _check_register_web_api),
    ("Star.__init__(context) 仍可只传 context", _check_star_base),
    ("插件 initialize() / terminate() 生命周期钩子仍会被调用", _check_lifecycle_hooks),
    (
        "插件 Web API 调度仍是 view_handler(**path_values) + 请求上下文绑定",
        _check_dashboard_dispatch,
    ),
    ("AstrBotConfig 仍是 dict 子类且 config_path/schema 可只按关键字传", _check_config_class),
    ("star_handlers_registry.get_handlers_by_module_name 仍在", _check_handler_registry),
)


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #


def _resolve_astrbot_root(explicit: str | None) -> Path:
    if explicit:
        candidates: list[tuple[str, Path]] = [("--astrbot-root", Path(explicit))]
    else:
        candidates = []
    env_root = os.environ.get("ASTRBOT_ROOT")
    if env_root:
        candidates.append(("环境变量 ASTRBOT_ROOT", Path(env_root)))

    for label, raw in candidates:
        root = raw.expanduser().resolve()
        if (root / "astrbot" / "__init__.py").is_file():
            return root
        # 也允许直接指向 astrbot/ 包目录
        if root.name == "astrbot" and (root / "__init__.py").is_file():
            return root.parent
        _violation(f"{label} 指向的目录里找不到 astrbot/ 包：{root}")

    try:
        import astrbot  # noqa: PLC0415 - 只在自动发现时才需要
    except ImportError:
        _violation(
            "找不到 AstrBot 源码：请用 --astrbot-root <含 astrbot/ 的目录> 或设置环境变量 "
            "ASTRBOT_ROOT，或先安装 astrbot",
        )
    module_file = getattr(astrbot, "__file__", None)
    if not module_file:
        _violation("已导入 astrbot 但拿不到 astrbot.__file__，无法定位源码树")
    return Path(module_file).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="检查 AstrBot 源码树是否仍满足本插件依赖的接口契约（静态 AST，不 import）。",
    )
    parser.add_argument(
        "--astrbot-root",
        default=None,
        help="AstrBot 源码根目录（含 astrbot/ 包）；缺省依次取 $ASTRBOT_ROOT、已安装的 astrbot",
    )
    arguments = parser.parse_args(argv)

    root = _resolve_astrbot_root(arguments.astrbot_root)
    try:
        version = _version_from_source(root)
    except ContractViolation as exc:
        print(f"[FAIL] 无法读取 AstrBot 源码树：{exc}", file=sys.stderr)
        return 1
    tree = Tree(root=root, version=version)

    print(f"AstrBot 源码树：{root}")
    print(f"AstrBot 版本：{version if version else '未知（源码树没有 __version__）'}")
    print(f"插件声明区间：{_declared_spec(REPO_ROOT)}（来自 {METADATA_FILE}）")
    print("")

    failures: list[tuple[str, str]] = []
    for title, check in CHECKS:
        try:
            check(tree)
        except ContractViolation as exc:
            failures.append((title, str(exc)))
            print(f"[FAIL] {title}")
            print(f"       {exc}")
        else:
            print(f"[PASS] {title}")

    print("")
    if failures:
        print(f"契约检查失败：{len(failures)}/{len(CHECKS)} 条不成立。")
        return 1
    print(f"契约检查通过：{len(CHECKS)}/{len(CHECKS)} 条（AstrBot {version}）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
