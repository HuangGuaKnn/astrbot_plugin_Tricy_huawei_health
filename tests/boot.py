# -*- coding: utf-8 -*-
"""Safe bootstrap for the huawei_health acceptance tests.

Loads the plugin with stub ``astrbot`` modules and redirects every on-disk path
into a throw-away sandbox under the system temp directory, so that the real
AstrBot data directory is never touched.

Usage::

    import boot
    main_mod = boot.load_main()            # module object, data dir sandboxed
    plugin = boot.make_plugin(main_mod)    # instance, warmup disabled

Hard rule enforced here: ``main._data_dir`` is replaced BEFORE any instance is
created, so ``HealthStore``/``HuaweiCredentialsStore`` write into the sandbox.

Path layout (derived from this file, no machine-specific absolute paths)::

    <仓库根>/                 REPO_ROOT  == PLUGIN_DIR == WORK_DIR  (被测插件源码)
    <仓库根>/tests/           TESTS_DIR  (本文件所在目录)
    <仓库根>/tests/stubs/     STUBS      (``astrbot`` 桩包)
    <系统临时目录>/...        TMP        (沙箱根目录，可随时删除)
"""

import os
import pathlib
import sys
import tempfile

# Never write .pyc next to the sources under test.
sys.dont_write_bytecode = True

#: 本文件所在目录（``<仓库根>/tests``）。
TESTS_DIR = pathlib.Path(__file__).resolve().parent
#: 仓库根目录（``tests`` 的上溯一层），也是默认的被测插件目录。
REPO_ROOT = TESTS_DIR.parent
#: 被测插件目录：默认就是仓库根目录（平铺结构，无子包）。
PLUGIN_DIR = REPO_ROOT
#: 历史名字，保留作为 ``PLUGIN_DIR`` 的兼容别名。
WORK_DIR = PLUGIN_DIR
#: ``astrbot`` 桩包目录。
STUBS = TESTS_DIR / "stubs"
#: 沙箱根目录：放在系统临时目录下，仓库里不留任何临时产物。
TMP = pathlib.Path(tempfile.gettempdir()) / "hw_health_plugin_tests"

#: 用 ``HW_AUDIT_PLUGIN_DIR`` 指向别的副本（例如从 dist/*.zip 解压出来的那份），
#: 就能拿同一批探针去测发布物本身。
_DEFAULT_PLUGIN_DIR = os.environ.get("HW_AUDIT_PLUGIN_DIR") or str(PLUGIN_DIR)

#: 真实 AstrBot 数据目录，由 ``Path.home()`` 动态推导，不写死任何用户路径。
#: 测试进程绝不允许写进这两个前缀（fail-closed）。
_ASTRBOT_DATA_DIR = pathlib.Path.home() / ".astrbot" / "data"

FORBIDDEN_PREFIXES = (
    str(_ASTRBOT_DATA_DIR / "plugin_data"),
    str(_ASTRBOT_DATA_DIR / "plugins"),
)


_CURRENT_PLUGIN_DIR = {"dir": None}


def install_paths(plugin_dir=None):
    """Make ``astrbot`` (stub) and the plugin package importable.

    Order matters: the stub package must win over any real ``astrbot`` on
    ``sys.path``.  ``plugin_dir`` defaults to the repository root.

    只有切换到另一份插件目录时才清 ``sys.modules``，否则 ``make_plugin`` 之类的
    后续调用会把已经导入好的模块扔掉、再重新导入一份。
    """
    pdir = str(plugin_dir) if plugin_dir else (_CURRENT_PLUGIN_DIR["dir"] or _DEFAULT_PLUGIN_DIR)
    if _CURRENT_PLUGIN_DIR["dir"] != pdir:
        # 清掉旧的插件模块，避免两份代码互相污染
        for mod in ("main", "hw_auth", "hw_client", "hw_store", "hw_login",
                    "hw_credentials", "hw_webapi"):
            sys.modules.pop(mod, None)
        _CURRENT_PLUGIN_DIR["dir"] = pdir
    # STUBS 放最前（压过任何真实 astrbot），然后是目标插件目录
    for p in (str(STUBS), pdir):
        while p in sys.path:
            sys.path.remove(p)
        sys.path.insert(0, p)
    TMP.mkdir(parents=True, exist_ok=True)


def sandbox_dir(name="hwdata"):
    install_paths()
    return tempfile.mkdtemp(prefix=name + "_", dir=str(TMP))


def assert_sandboxed(path):
    real = os.path.abspath(str(path))
    for prefix in FORBIDDEN_PREFIXES:
        if real.lower().startswith(os.path.abspath(prefix).lower()):
            raise RuntimeError("refusing to touch the real AstrBot data dir: %s" % real)
    return real


def load_main(data_dir=None, plugin_dir=None):
    """Import ``main.py`` with ``_data_dir`` pinned to a sandbox directory."""
    install_paths(plugin_dir)
    d = assert_sandboxed(data_dir or sandbox_dir())
    os.makedirs(d, exist_ok=True)
    import main as main_mod
    main_mod._data_dir = lambda: d
    main_mod.__sandbox_dir__ = d
    return main_mod


def default_config(**overrides):
    install_paths()
    from astrbot.api import AstrBotConfig

    cfg = AstrBotConfig({
        "cookie_json": "",
        "cookie_CASTGC": "", "cookie_sid": "", "cookie_hwid_cas_sid": "",
        "cookie_HuaweiID_CAS_ISCASLOGIN": "", "cookie_CASLOGINSITE": "",
        "cookie_LOGINACCSITE": "",
        "browser_path": "", "headless": True, "page_timeout": 90,
        "token_ttl": 3000, "data_ttl": 600,
        "warmup": False,           # never auto-start a browser during tests
        "login_daily_limit": 3,
        "timezone": "+0800",
        "client_id": "106533743",
        "api_version": "HealthKitRunningGroupPortal_6.26.4.200",
    })
    cfg.update(overrides)
    return cfg


def make_plugin(main_mod=None, initialize=False, plugin_dir=None, **config_overrides):
    """Create a plugin instance whose data_dir lives in the sandbox."""
    main_mod = main_mod or load_main(plugin_dir=plugin_dir)
    install_paths(plugin_dir)
    from astrbot.api.star import Context

    plugin = main_mod.HuaweiHealthPlugin(Context(), default_config(**config_overrides))
    assert_sandboxed(plugin.data_dir)
    return plugin
