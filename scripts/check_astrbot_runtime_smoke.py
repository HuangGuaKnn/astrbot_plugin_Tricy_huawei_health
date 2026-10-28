#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""插件运行时冒烟：在真实 AstrBot 上 import 插件、实例化、核对注册结果。

与 check_astrbot_runner_contract.py 的分工：
    - 契约脚本：静态看「AstrBot 的接口还在不在」（不需要装 AstrBot，可对任意源码树跑）
    - 本脚本  ：动态看「插件在这个 AstrBot 上还活不活」（必须已经装好 AstrBot）

用法：
    python scripts/check_astrbot_runtime_smoke.py
    python scripts/check_astrbot_runtime_smoke.py --plugin-root <插件目录>
    python scripts/check_astrbot_runtime_smoke.py --keep-workspace   # 保留临时目录便于排查

三条隔离措施（都是硬要求，别改成「方便点」的写法）：
    1. import astrbot 之前把 ASTRBOT_ROOT 指向临时目录并 chdir 过去，避免 AstrBot 的
       配置迁移/日志把文件写进仓库或真实 ~/.astrbot；
    2. 把 main._data_dir 换成临时目录，插件全程不碰真实的 plugin_data/；
    3. 不调用 initialize()：它会启动后台 token 预热（真的会打华为接口），
       违反「绝不跑真实登录或抓取」的红线；WebUI 注册改成直接构造 WebApi 验证。

退出码：0 = 全部通过；1 = 有断言失败（逐条打印原因）。
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import importlib
import inspect
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import types
import warnings
from pathlib import Path

METADATA_FILE = "metadata.yaml"
SHORT_DESC_LIMIT = 40


class SmokeFailure(AssertionError):
    """一条冒烟断言不成立。"""


def _fail(message: str) -> None:
    raise SmokeFailure(message)


# --------------------------------------------------------------------------- #
# metadata.yaml
# --------------------------------------------------------------------------- #


def _read_metadata(plugin_root: Path) -> dict:
    metadata_path = plugin_root / METADATA_FILE
    if not metadata_path.is_file():
        _fail(f"插件目录缺少 {METADATA_FILE}：{plugin_root}")
    text = metadata_path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        _fail("读取 metadata.yaml 需要 PyYAML（AstrBot 依赖里已经带了）")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        _fail(f"{METADATA_FILE} 不是一个 YAML 映射")
    return data


def _check_metadata_fields(metadata: dict, astrbot_version: str) -> None:
    for field in ("name", "display_name", "desc", "version", "author", "repo"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value.strip():
            _fail(f"{METADATA_FILE} 缺少非空字符串字段 {field}")

    short_desc = metadata.get("short_desc")
    if not isinstance(short_desc, str) or not short_desc.strip():
        _fail(f"{METADATA_FILE} 缺少 short_desc（市场列表页一句话）")
    if len(short_desc.strip()) > SHORT_DESC_LIMIT:
        _fail(
            f"short_desc 长度 {len(short_desc.strip())} 超过 {SHORT_DESC_LIMIT} 字符：{short_desc!r}",
        )

    spec_text = metadata.get("astrbot_version")
    if not isinstance(spec_text, str) or not spec_text.strip():
        _fail(f"{METADATA_FILE} 缺少 astrbot_version")
    try:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
        from packaging.version import InvalidVersion, Version
    except ImportError:  # pragma: no cover - AstrBot 自身依赖 packaging
        _fail("校验 astrbot_version 需要 packaging（AstrBot 依赖里已经带了）")
    try:
        specifier = SpecifierSet(spec_text.strip())
    except InvalidSpecifier:
        _fail(f"astrbot_version 不是合法 PEP 440 区间：{spec_text!r}")
    try:
        version = Version(astrbot_version)
    except InvalidVersion:
        _fail(f"当前 AstrBot 版本号不是合法 PEP 440 版本：{astrbot_version!r}")
    if not specifier.contains(version, prereleases=True):
        _fail(
            f"当前 AstrBot {astrbot_version} 不满足插件声明的 astrbot_version "
            f"{spec_text.strip()!r}（AstrBot 加载插件时用同一套校验，这里提前拦下）",
        )


# --------------------------------------------------------------------------- #
# 插件包加载
# --------------------------------------------------------------------------- #


def _register_plugin_package(plugin_root: Path, package_name: str) -> types.ModuleType:
    """把插件目录挂成名为 package_name 的包（等价于 AstrBot 的 data.plugins.<name>）。

    插件目录本身没有 __init__.py，AstrBot 靠隐式命名空间包导入；这里复刻同样的语义，
    好处是不依赖仓库目录名必须等于插件名。
    """
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", package_name):
        _fail(f"metadata.yaml 的 name 不是合法模块名：{package_name!r}")
    existing = sys.modules.get(package_name)
    if existing is not None:
        return existing
    module = types.ModuleType(package_name)
    module.__path__ = [str(plugin_root)]  # type: ignore[attr-defined]
    module.__package__ = package_name
    sys.modules[package_name] = module
    return module


class _RecordingContext:
    """只记录 register_web_api 的 Context 替身（插件其余部分不依赖 Context）。"""

    def __init__(self) -> None:
        self.registered_web_apis: list[tuple[str, object, list[str], str]] = []

    def register_web_api(self, route, view_handler, methods, desc) -> None:
        self.registered_web_apis.append((route, view_handler, list(methods), desc))


def _build_config(workspace: Path, plugin_root: Path, package_name: str):
    """用真实的 AstrBotConfig 加载 _conf_schema.json（顺手验证配置层契约）。"""
    from astrbot.core.config.astrbot_config import AstrBotConfig

    schema_path = plugin_root / "_conf_schema.json"
    if not schema_path.is_file():
        _fail("插件目录缺少 _conf_schema.json")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    config_dir = workspace / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    return AstrBotConfig(
        config_path=str(config_dir / f"{package_name}_config.json"),
        schema=schema,
    )


# --------------------------------------------------------------------------- #
# 请求代理（验证 hw_webapi 的 handler 真的能在 AstrBot 调度下跑起来）
# --------------------------------------------------------------------------- #


def _fake_plugin_request(body: bytes):
    from starlette.requests import Request

    from astrbot.api.web import PluginRequest

    scope = {
        "type": "http",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/plugins/smoke/page/cookie/import",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 54321),
        "server": ("127.0.0.1", 6185),
        "http_version": "1.1",
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return PluginRequest(Request(scope, receive), plugin_name="smoke", username="smoke")


# --------------------------------------------------------------------------- #
# 断言
# --------------------------------------------------------------------------- #


def _check_llm_tools(package_name: str, main_module) -> None:
    from astrbot.core.star.star_handler import star_handlers_registry

    handlers = star_handlers_registry.get_handlers_by_module_name(package_name + ".main")
    tool_handlers = {
        handler.handler_name: handler
        for handler in handlers
        if getattr(getattr(handler, "event_type", None), "name", "") == "OnCallingFuncToolEvent"
    }
    expected = set(main_module.TOOL_NAMES)
    missing = expected - set(tool_handlers)
    if missing:
        _fail(f"这些 LLM 工具没注册上：{', '.join(sorted(missing))}")
    unexpected = set(tool_handlers) - expected
    if unexpected:
        _fail(f"注册了 TOOL_NAMES 之外的工具：{', '.join(sorted(unexpected))}")
    for name, handler in sorted(tool_handlers.items()):
        if not inspect.iscoroutinefunction(handler.handler):
            _fail(f"LLM 工具 {name} 的处理函数不再是 async，AstrBot 调用会失败")
    if len(tool_handlers) != len(expected):
        _fail(f"LLM 工具数量 {len(tool_handlers)} != 声明的 {len(expected)}")


def _check_web_api(plugin, package_name: str, context: _RecordingContext) -> None:
    webapi_module = importlib.import_module(package_name + ".hw_webapi")
    api = webapi_module.HuaweiHealthWebApi(plugin)
    api.register()

    routes = context.registered_web_apis
    if not routes:
        _fail("HuaweiHealthWebApi.register() 没有注册任何路由")
    prefix = webapi_module.PAGE_PREFIX + "/"
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for route, handler, methods, desc in routes:
        if not route.startswith(prefix):
            _fail(f"路由 {route!r} 不在页面前缀 {prefix!r} 下")
        if not methods or any(method not in {"GET", "POST"} for method in methods):
            _fail(f"路由 {route!r} 的 HTTP 方法异常：{methods}")
        if not isinstance(desc, str) or not desc.strip():
            _fail(f"路由 {route!r} 没有描述")
        if not inspect.iscoroutinefunction(handler):
            _fail(f"路由 {route!r} 的 handler 不是 async 函数")
        # AstrBot 以 view_handler(**path_values) 调用：插件的 handler 必须零参数
        if inspect.signature(handler).parameters:
            _fail(
                f"路由 {route!r} 的 handler 声明了参数 "
                f"{list(inspect.signature(handler).parameters)}；"
                "AstrBot 只按路径参数传关键字，插件路由没有路径参数，会被 TypeError 打断",
            )
        key = (route, tuple(methods))
        if key in seen:
            _fail(f"路由 {route!r} {methods} 重复注册")
        seen.add(key)


def _check_request_proxy(plugin, package_name: str) -> None:
    from astrbot.api.web import bind_request_context, request

    try:
        request.method
    except RuntimeError:
        pass
    else:
        _fail("astrbot.api.web.request 在 handler 外也能取到值，请求隔离已失效")

    webapi_module = importlib.import_module(package_name + ".hw_webapi")
    api = webapi_module.HuaweiHealthWebApi(plugin)

    with bind_request_context(_fake_plugin_request(b"{not-json")):
        response = asyncio.run(api.import_cookie())

    if getattr(response, "status_code", None) != 400:
        _fail(f"非法 JSON 的 cookie 导入应返回 400，实际 {getattr(response, 'status_code', None)}")
    payload = json.loads(response.body)
    if payload.get("status") != "error":
        _fail(f"非法 JSON 的 cookie 导入响应体不是错误信封：{payload!r}")


def _check_plugin_object(plugin, main_module, plugin_data_dir: Path) -> None:
    from astrbot.api.star import Star

    if not isinstance(plugin, Star):
        _fail("插件实例不再是 Star 的子类")
    if Path(plugin.data_dir).resolve() != plugin_data_dir.resolve():
        _fail(
            "插件数据目录没被替换成临时目录，冒烟测试会碰到真实 plugin_data："
            f"{plugin.data_dir}",
        )
    for method in ("debug", "info", "warning", "error"):
        if not callable(getattr(plugin.logger, method, None)):
            _fail(f"插件的 logger 缺少 {method}()，日志调用会 AttributeError")
    for hook in ("initialize", "terminate"):
        if not inspect.iscoroutinefunction(getattr(main_module.HuaweiHealthPlugin, hook, None)):
            _fail(f"插件入口类的 {hook}() 不再是 async，AstrBot 生命周期钩子会失败")


def _check_metadata_consistency(metadata: dict, main_module, package_name: str) -> None:
    from astrbot.core.star.star import star_map

    if metadata["name"] != main_module.PLUGIN_NAME:
        _fail(
            f"metadata.yaml 的 name（{metadata['name']}）与 main.PLUGIN_NAME"
            f"（{main_module.PLUGIN_NAME}）不一致",
        )
    registered = star_map.get(package_name + ".main")
    if registered is None:
        _fail("@register 装饰器没有在 star_map 里登记这个插件")
    if registered.version != metadata["version"]:
        _fail(
            f"@register 的版本（{registered.version}）与 metadata.yaml 的 version"
            f"（{metadata['version']}）不一致",
        )
    if registered.name != metadata["name"]:
        _fail(f"@register 的插件名（{registered.name}）与 metadata.yaml 的 name 不一致")


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #


_ORIGINAL_CWD: Path | None = None
"""chdir 到临时目录之前的工作目录；清理时先切回来，否则 Windows 删不掉临时目录。"""


def _close_log_handlers() -> None:
    """关掉 AstrBot 在临时目录里打开的日志文件句柄，否则 Windows 上删不掉目录。"""
    loggers = [logging.getLogger()] + [
        logging.getLogger(name) for name in list(logging.Logger.manager.loggerDict)
    ]
    for logger_object in loggers:
        for handler in list(getattr(logger_object, "handlers", [])):
            try:
                handler.flush()
                handler.close()
            except Exception:  # noqa: BLE001 - 关句柄失败不该让冒烟报错
                pass
            logger_object.removeHandler(handler)


def _cleanup(workspace: Path, keep: bool, state: dict[str, object]) -> None:
    """删掉临时工作目录；实在删不掉时给出可操作提示，不静默留垃圾。"""
    if keep:
        print(f"临时工作目录保留在：{workspace}")
        return
    if _ORIGINAL_CWD is not None:
        try:
            os.chdir(_ORIGINAL_CWD)
        except OSError:
            pass
    state.clear()
    gc.collect()
    try:
        shutil.rmtree(workspace)
        return
    except OSError:
        _close_log_handlers()
    gc.collect()
    try:
        shutil.rmtree(workspace)
    except OSError as exc:
        print(f"临时工作目录未能删除（句柄未释放：{exc}），可手动清理：{workspace}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="在真实 AstrBot 上冒烟插件（不联网、不碰真实数据目录）。")
    parser.add_argument(
        "--plugin-root",
        default=None,
        help="插件根目录；缺省为脚本上一级目录（仓库根）",
    )
    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        help="保留临时工作目录（默认跑完删除）",
    )
    parser.add_argument(
        "--astrbot-path",
        default=None,
        help="额外的 AstrBot 源码目录（含 astrbot/ 包），插到 sys.path 最前面；"
        "CI 里 pip install 后不需要传",
    )
    arguments = parser.parse_args(argv)

    plugin_root = (
        Path(arguments.plugin_root).expanduser().resolve()
        if arguments.plugin_root
        else Path(__file__).resolve().parents[1]
    )
    if not (plugin_root / "main.py").is_file():
        print(f"[FAIL] {plugin_root} 下没有 main.py，--plugin-root 指错了？", file=sys.stderr)
        return 1

    # 必须在 import astrbot 之前完成隔离（AstrBot 会按 ASTRBOT_ROOT 决定数据目录）。
    if arguments.astrbot_path:
        extra_path = Path(arguments.astrbot_path).expanduser().resolve()
        if not (extra_path / "astrbot").is_dir():
            print(f"[FAIL] {extra_path} 下没有 astrbot/ 包，--astrbot-path 指错了？", file=sys.stderr)
            return 1
        sys.path.insert(0, str(extra_path))

    global _ORIGINAL_CWD
    _ORIGINAL_CWD = Path.cwd()
    workspace = Path(tempfile.mkdtemp(prefix="hw-health-smoke-"))
    os.environ["ASTRBOT_ROOT"] = str(workspace)
    os.chdir(workspace)

    print(f"插件目录：{plugin_root}")
    print(f"临时工作目录：{workspace}")

    failures: list[tuple[str, str]] = []

    def run(title: str, func) -> None:
        try:
            func()
        except SmokeFailure as exc:
            failures.append((title, str(exc)))
            print(f"[FAIL] {title}")
            print(f"       {exc}")
        except Exception as exc:  # noqa: BLE001 - 冒烟要报出真实异常类型
            failures.append((title, f"{type(exc).__name__}: {exc}"))
            print(f"[FAIL] {title}")
            print(f"       {type(exc).__name__}: {exc}")
        else:
            print(f"[PASS] {title}")

    try:
        import astrbot  # noqa: PLC0415 - 隔离目录准备好之后再导入
    except ImportError as exc:
        print(f"[FAIL] 导入 astrbot 失败（需要先安装 AstrBot）：{exc}", file=sys.stderr)
        _cleanup(workspace, arguments.keep_workspace, {})
        return 1
    astrbot_version = getattr(astrbot, "__version__", "unknown")
    print(f"AstrBot 版本：{astrbot_version}")
    print("")

    metadata = _read_metadata(plugin_root)
    package_name = str(metadata.get("name") or "")
    run(
        "metadata.yaml 字段齐全且 astrbot_version 与当前 AstrBot 相容",
        lambda: _check_metadata_fields(metadata, astrbot_version),
    )
    if failures:
        print("")
        print("metadata.yaml 不合法，后续冒烟无法进行。")
        _cleanup(workspace, arguments.keep_workspace, {})
        return 1

    _register_plugin_package(plugin_root, package_name)
    state: dict[str, object] = {}

    def import_plugin() -> None:
        # @register 是已废弃装饰器，导入时会发 DeprecationWarning；这里只静音这一条噪音。
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            main_module = importlib.import_module(package_name + ".main")
        state["main"] = main_module
        state["webapi"] = importlib.import_module(package_name + ".hw_webapi")

    run("插件能 import（main / hw_webapi，含 astrbot.api.web 依赖）", import_plugin)
    if failures:
        print("")
        print("插件导入失败，后续冒烟无法进行。")
        _cleanup(workspace, arguments.keep_workspace, state)
        return 1

    main_module = state["main"]
    plugin_data_dir = workspace / "plugin_data" / package_name
    plugin_data_dir.mkdir(parents=True, exist_ok=True)
    # 关键：把数据目录钉在临时目录，绝不碰真实 plugin_data/。
    main_module._data_dir = lambda: str(plugin_data_dir)

    context = _RecordingContext()

    def instantiate() -> None:
        config = _build_config(workspace, plugin_root, package_name)
        state["plugin"] = main_module.HuaweiHealthPlugin(context, config)

    run("插件能实例化（Star.__init__ + AstrBotConfig + 8 个工具装饰器）", instantiate)
    if failures:
        print("")
        print("插件实例化失败，后续冒烟无法进行。")
        _cleanup(workspace, arguments.keep_workspace, state)
        return 1

    plugin = state["plugin"]
    run(
        "插件实例状态正确（Star 子类 / 数据目录已隔离 / logger 可用 / 生命周期钩子是 async）",
        lambda: _check_plugin_object(plugin, main_module, plugin_data_dir),
    )
    run(
        "8 个 LLM 工具全部注册且都是 async",
        lambda: _check_llm_tools(package_name, main_module),
    )
    run(
        "WebUI 后端 12 条路由可注册且 handler 签名符合调度约定",
        lambda: _check_web_api(plugin, package_name, context),
    )
    run(
        "request 代理隔离正确，handler 在 bind_request_context 下能跑",
        lambda: _check_request_proxy(plugin, package_name),
    )
    run(
        "metadata.yaml 与 @register 的 name/version 一致",
        lambda: _check_metadata_consistency(metadata, main_module, package_name),
    )

    print("")
    if failures:
        print(f"运行时冒烟失败：{len(failures)} 条不成立。")
        _cleanup(workspace, arguments.keep_workspace, state)
        return 1

    print(f"运行时冒烟通过（AstrBot {astrbot_version}，插件 {metadata['version']}）。")
    _cleanup(workspace, arguments.keep_workspace, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
