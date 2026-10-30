# -*- coding: utf-8 -*-
"""T8 契约测试：WebUI 配置同源（``GET`` / ``POST`` ``<PAGE_PREFIX>/config``）。

普通配置遵循 ``CONTRACT_webui_config.md``（下文用 §x.y 引用章节）。
敏感 Cookie 的存储契约已加固：完整集合只写安全存储，普通配置清空对应字段；
因此不再断言新 Cookie 明文出现在 AstrBot 配置中。21 项表单和掩码响应保持兼容。

覆盖范围（对应契约 §6 的必测清单）：

    - 21 个配置叶子逐项 POST 生效，且 ``reloaded`` 恒为 ``[]``；
    - 白名单 / 类型 / 钳制 / UMO 校验，任一不合法 → 整单 400；
    - 掩码：7 个敏感项永远是 ``***``，响应体里 grep 不到哨兵值；
    - revision 409 与「400/409 绝不落盘」（配置文件 sha256 比对）；
    - cookie / ``login_daily_limit`` / ``warmup`` 三组热生效；
    - 权限白名单缓存刷新；
    - 桩配置（裸 dict，没有 ``save_config_async``）的降级路径。

全部打桩：不联网、不起浏览器、不跑真实登录、不碰真实数据目录与 ``plugin_data``。
``FakeConfig`` 只在本文件内补「落盘」这一层，``tests/stubs/`` 与 ``tests/boot.py``
一个字符都没动。
"""

import asyncio
import copy
import hashlib
import json
import os
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
sys.dont_write_bytecode = True

import boot  # noqa: E402

#: 默认测仓库根目录的插件源码；``HW_AUDIT_PLUGIN_DIR`` 语义与其它测试文件一致。
PLUGIN_DIR_UNDER_TEST = os.environ.get("HW_AUDIT_PLUGIN_DIR") or str(boot.PLUGIN_DIR)
boot.install_paths(PLUGIN_DIR_UNDER_TEST)
main_mod = boot.load_main(plugin_dir=PLUGIN_DIR_UNDER_TEST)

import hw_auth  # noqa: E402
import hw_webapi  # noqa: E402
from astrbot.api import AstrBotConfig  # noqa: E402
from astrbot.api.web import request  # noqa: E402

PAGE_PREFIX = hw_webapi.PAGE_PREFIX
CONFIG_ROUTE = PAGE_PREFIX + "/config"

#: 契约 §1：掩码常量。
MASK = "***"

#: 契约 §1：7 个敏感项（``cookie_json`` + 6 个 ``cookie_*``）。
SENSITIVE_LEAVES = (
    "cookie_json",
    "cookie_CASTGC",
    "cookie_sid",
    "cookie_hwid_cas_sid",
    "cookie_HuaweiID_CAS_ISCASLOGIN",
    "cookie_CASLOGINSITE",
    "cookie_LOGINACCSITE",
)

#: 契约 §1：平铺的 17 项（含 7 个敏感项），顺序与 schema 一致。
FLAT_LEAVES = SENSITIVE_LEAVES + (
    "browser_path",
    "headless",
    "page_timeout",
    "token_ttl",
    "data_ttl",
    "warmup",
    "login_daily_limit",
    "timezone",
    "client_id",
    "api_version",
)

#: 契约 §1：分组 ``permission_settings`` 的 4 个子键。
PERMISSION_SUBKEYS = ("allow_private", "allow_group", "extra_umo_whitelist", "admin_only")

#: 契约 §1：21 个叶子，嵌套项用点号路径表示（与 ``applied`` 一致）。
PERMISSION_LEAVES = tuple("permission_settings." + sub for sub in PERMISSION_SUBKEYS)
ALL_LEAF_PATHS = FLAT_LEAVES + PERMISSION_LEAVES

#: 契约 §2 ``meta.bounds``：钳制上下限，前端据此显示范围。
BOUNDS = {
    "page_timeout": (1, 600),
    "token_ttl": (0, 86400),
    "data_ttl": (0, 86400),
    "login_daily_limit": (1, 10),
}

#: ``main._parse_umos`` 认可的三种消息类型之一，用来造一条合法 UMO。
GROUP_UMO = "aiocqhttp:GroupMessage:123456789"

#: 断言「这一层不做检查」的哨兵（只在确实无法从契约推出精确值时使用）。
_ANY = object()


def _load_schema():
    """读取 ``_conf_schema.json``（契约 §2：GET 的 ``schema`` 就是它的原样拷贝）。"""
    path = os.path.join(str(PLUGIN_DIR_UNDER_TEST), "_conf_schema.json")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


#: 配置文件里的 schema，同时也是 21 个叶子的「默认值」来源。
SCHEMA = _load_schema()


def schema_defaults():
    """按 schema 的 ``default`` 造一份完整配置（嵌套组同样展开）。

    契约 §2 要求「缺失的配置键按 schema 的 default 补齐」，所以这里直接拿
    schema 当默认值真值来源，测试里不再手抄一份常量。
    """
    out = {}
    for key, spec in SCHEMA.items():
        if spec.get("type") == "object":
            out[key] = {
                sub: copy.deepcopy(sub_spec.get("default"))
                for sub, sub_spec in spec.get("items", {}).items()
            }
        else:
            out[key] = copy.deepcopy(spec.get("default"))
    return out


def full_config(**overrides):
    """完整配置 dict；``warmup`` 强制关闭（测试绝不许自动起浏览器）。"""
    data = schema_defaults()
    data["warmup"] = False
    data.update(overrides)
    return data


class FakeConfig(AstrBotConfig):
    """测试替身：给桩 ``AstrBotConfig`` 补上真实框架的「落盘」能力。

    真实 ``save_config_async`` 的语义是「先 ``dict.update`` 浅合并，再 deepcopy
    落盘」（契约 §0.2）。这里**故意照抄浅合并**、不修正成深合并：契约正是因为
    浅合并才有「传半截 ``permission_settings`` 会整组替换、丢掉子键」的警告，
    测试替身若做深合并，就会把这个坑悄悄填平、让后端不必按契约自己合并嵌套组。
    """

    def __init__(self, data, root_dir, filename="config.json"):
        super().__init__(copy.deepcopy(data))
        #: 与真实框架同名的三个属性：契约 §3.5 的 revision 算法直接读它们。
        self.config_path = os.path.join(str(root_dir), filename)
        self._save_revision = 0
        self._save_committed_revision = 0
        #: 测试钩子：模拟「落盘失败返回 False」（契约 §3.2 第 6 步 → 500）。
        self.save_fail = False
        #: 测试钩子：模拟「落盘抛异常」（同样 → 500）。
        self.save_error = None
        #: 每次 ``save_config_async`` 收到的 ``replace_config``，留证用。
        self.save_calls = []
        self._write_file()

    # ---------- 内部 ----------

    def _write_file(self):
        """把当前内存内容写到磁盘：``utf-8-sig``，与真实框架一致（契约 §0.3）。"""
        with open(self.config_path, "w", encoding="utf-8-sig") as handle:
            json.dump(copy.deepcopy(dict(self)), handle, ensure_ascii=False, indent=2)

    # ---------- 与真实框架同名的方法 ----------

    async def save_config_async(self, replace_config=None, indent=2):
        """返回 bool；语义对齐真实框架（浅合并 + 深拷贝落盘 + 计数字段自增）。"""
        self.save_calls.append(copy.deepcopy(replace_config))
        if self.save_error is not None:
            raise self.save_error
        if self.save_fail:
            return False
        if isinstance(replace_config, dict):
            self.update(copy.deepcopy(replace_config))
        self._save_revision += 1
        self._write_file()
        self._save_committed_revision = self._save_revision
        return True


# ============================ 夹具 ============================


def make_config(data=None):
    """造一个可落盘的 ``FakeConfig``，落盘目录在系统临时目录的沙箱里。"""
    root = boot.sandbox_dir("hwcfg")
    if data is None:
        data = full_config()
    return FakeConfig(data, root)


def make_api(config=None):
    """造 ``(plugin, api, cfg)``。

    ``config`` 为 ``None`` 时保留 ``boot.make_plugin`` 造的**裸 dict** 配置，
    用来测契约 §3.6 的降级路径；否则替换成 ``FakeConfig``。
    """
    # 每个插件实例用独立沙箱目录，避免用例之间互相看到 cookie / 缓存。
    main_mod._data_dir = lambda: boot.sandbox_dir("t_webcfg")
    plugin = boot.make_plugin(main_mod, plugin_dir=PLUGIN_DIR_UNDER_TEST)
    if config is not None:
        plugin.config = config
    api = hw_webapi.HuaweiHealthWebApi(plugin)
    api.register()
    return plugin, api, plugin.config


async def _fetch_async(api):
    return await api.get_config()


async def _post_async(api, body):
    request.body = body
    return await api.post_config()


async def _revision_async(api):
    payload = (await api.get_config())["payload"]
    return payload["data"]["meta"]["revision"]


def fetch_config(api):
    """同步调用 ``GET <PAGE_PREFIX>/config``，返回 ``{payload, status_code}``。"""
    return asyncio.run(_fetch_async(api))


def post_config(api, body):
    """同步调用 ``POST <PAGE_PREFIX>/config``。"""
    return asyncio.run(_post_async(api, body))


def revision_of(api):
    """取当前 ``meta.revision``（同步版本）。"""
    return asyncio.run(_revision_async(api))


def data_of(resp):
    return resp["payload"]["data"]


def meta_of(resp):
    return resp["payload"]["data"]["meta"]


def values_of(resp):
    return resp["payload"]["data"]["values"]


def read_path(container, dotted):
    """按 ``"permission_settings.allow_group"`` 这种点号路径取值。"""
    node = container
    for part in dotted.split("."):
        node = node[part]
    return node


def read_config_file(cfg):
    """按真实框架的编码（``utf-8-sig``）把落盘文件读回来。"""
    with open(cfg.config_path, "r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        digest.update(handle.read())
    return digest.hexdigest()


def leaf_body(dotted_path, value):
    """把叶子路径拼成请求体的 ``values``（嵌套组要包一层）。"""
    if "." in dotted_path:
        group, sub = dotted_path.split(".", 1)
        return {group: {sub: value}}
    return {dotted_path: value}


class StubCookieImport:
    """把 ``hw_auth.HuaweiAuth.import_cookie_sources`` 换成记录器。

    ``plugin.auth`` 是 property，每次访问都会新建一个 ``HuaweiAuth`` 实例，
    所以必须打在类上，打实例上不会生效。记录器不落盘、不联网。
    """

    def __init__(self, result=2, error=None):
        self.result = result
        self.error = error
        self.calls = []
        self._original = None

    def __enter__(self):
        self._original = hw_auth.HuaweiAuth.import_cookie_sources
        self._original_load = hw_auth.HuaweiAuth.load_cookies
        recorder = self
        snapshots = {}

        def fake_import(auth_self, json_text="", fields=None, only_if_changed=False,
                        replace_existing=False):
            recorder.calls.append({
                "json_text": json_text,
                "fields": dict(fields or {}),
                "only_if_changed": only_if_changed,
                "replace_existing": replace_existing,
            })
            if recorder.error is not None:
                raise recorder.error
            snapshots[auth_self.cookie_file] = (hw_auth.parse_cookie_input(json_text) +
                                                 hw_auth.cookies_from_fields(fields))
            return recorder.result

        def fake_load(auth_self):
            if auth_self.cookie_file in snapshots:
                return snapshots[auth_self.cookie_file]
            return recorder._original_load(auth_self)

        hw_auth.HuaweiAuth.import_cookie_sources = fake_import
        hw_auth.HuaweiAuth.load_cookies = fake_load
        return self

    def __exit__(self, *exc_info):
        hw_auth.HuaweiAuth.import_cookie_sources = self._original
        hw_auth.HuaweiAuth.load_cookies = self._original_load
        return False


async def _noop_warmup():
    """代替真实的 ``_warmup``：不睡 8 秒、不去取 token。"""
    return None


class _ResponseAssertions(object):
    """GET/POST 响应的公共断言（``_ApiCase`` 与 ``TestDegradedConfig`` 共用）。"""

    def assert_ok(self, resp):
        """断言 200 + ``status == "ok"``，返回 payload。"""
        self.assertEqual(resp["status_code"], 200, resp["payload"])
        payload = resp["payload"]
        self.assertEqual(payload.get("status"), "ok", payload)
        return payload

    def assert_error(self, resp, status_code, field=_ANY):
        """断言失败响应：状态码 + ``status == "error"`` + 必带非空 message。

        ``field`` 传具体字符串时精确比对（契约 §3.4 要求 ``field`` 是叶子路径）；
        传 ``_ANY`` 时跳过——只有「请求体层面」的错误才允许不查 ``field``。
        """
        self.assertEqual(resp["status_code"], status_code, resp["payload"])
        payload = resp["payload"]
        self.assertEqual(payload.get("status"), "error", payload)
        message = payload.get("message")
        self.assertIsInstance(message, str, payload)
        self.assertTrue(message, payload)
        if field is not _ANY:
            self.assertEqual(payload.get("field"), field, payload)
        return payload


class _ApiCase(_ResponseAssertions, unittest.TestCase):
    """公共夹具：每个用例一套独立沙箱配置 + 插件 + WebApi。

    子类若需要不同的初始配置，自己用 ``make_api(make_config(...))`` 再造一份，
    不要改 ``self.config``（会影响「sha256 / 内存不变」类断言的前提）。
    注意：本地新造的 ``api`` 要显式调 ``post_config(api, ...)``，
    ``self.send()`` / ``self.fetch()`` 永远打 ``setUp`` 里那一份。
    """

    def setUp(self):
        request.body = {}
        self.plugin, self.api, self.config = make_api(make_config())

    # ---------- 调用 ----------

    def fetch(self):
        return fetch_config(self.api)

    def send(self, values, revision=None):
        """按契约 §3.1 的请求体形状 POST；``revision`` 缺省时现取一份最新的。"""
        body = {"values": values}
        body["revision"] = self.revision() if revision is None else revision
        return post_config(self.api, body)

    def revision(self):
        return revision_of(self.api)

    def saved(self):
        return read_config_file(self.config)


# ============================ 路由注册 ============================

class TestConfigRoutes(unittest.TestCase):
    """契约 §0 / §2 / §3：两条新路由注册好，且 12 条老路由的路径一个不丢。"""

    #: 契约 §0 的 12 条既有路由（相对 ``PAGE_PREFIX`` 的后缀）。
    LEGACY_SUFFIXES = (
        "status", "overview", "cookie/import", "cookie/clear", "refresh",
        "login/start", "login/status", "login/sms", "login/trust",
        "login/cancel", "credentials", "credentials/status",
    )

    def test_handler_method_names(self):
        """契约 §6 的调用方式固定为 ``api.get_config()`` / ``api.post_config()``。"""
        _, api, _ = make_api(make_config())
        for name in ("get_config", "post_config"):
            self.assertTrue(callable(getattr(api, name, None)),
                            "HuaweiHealthWebApi 缺少 %s 方法" % name)

    def test_config_route_registered_for_get_and_post(self):
        plugin, _, _ = make_api(make_config())
        entries = [item for item in plugin.context.web_apis if item["route"] == CONFIG_ROUTE]
        self.assertTrue(entries, "没有注册 %s" % CONFIG_ROUTE)
        methods = set()
        for item in entries:
            methods.update(str(method).upper() for method in item["methods"])
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)
        for item in entries:
            self.assertTrue(callable(item["handler"]))

    def test_legacy_routes_unchanged(self):
        plugin, _, _ = make_api(make_config())
        routes = {item["route"] for item in plugin.context.web_apis}
        for suffix in self.LEGACY_SUFFIXES:
            self.assertIn(PAGE_PREFIX + "/" + suffix, routes, suffix)

    def test_all_routes_share_page_prefix(self):
        plugin, _, _ = make_api(make_config())
        for item in plugin.context.web_apis:
            self.assertTrue(item["route"].startswith(PAGE_PREFIX + "/"), item["route"])


# ============================ GET ============================

class TestGetConfig(_ApiCase):
    """契约 §2：GET 返回完整 21 叶子 + 原样 schema + 完整 meta。"""

    def test_status_and_shape(self):
        payload = self.assert_ok(self.fetch())
        self.assertEqual(set(payload["data"]), {"values", "schema", "meta"})

    def test_values_cover_all_21_leaves(self):
        values = values_of(self.fetch())
        self.assertEqual(set(values), set(FLAT_LEAVES) | {"permission_settings"})
        self.assertIsInstance(values["permission_settings"], dict)
        self.assertEqual(set(values["permission_settings"]), set(PERMISSION_SUBKEYS))
        # 平铺 17 + 分组 4 = 21，与契约 §1 的清单逐项对齐
        leaves = list(FLAT_LEAVES) + list(PERMISSION_LEAVES)
        self.assertEqual(len(leaves), 21)
        for path in leaves:
            read_path(values, path)  # 缺任何一项都抛 KeyError

    def test_values_mirror_config(self):
        values = values_of(self.fetch())
        self.assertEqual(values["headless"], True)
        self.assertEqual(values["page_timeout"], 90)
        self.assertEqual(values["token_ttl"], 3000)
        self.assertEqual(values["data_ttl"], 600)
        self.assertEqual(values["warmup"], False)
        self.assertEqual(values["login_daily_limit"], 3)
        self.assertEqual(values["timezone"], "+0800")
        self.assertEqual(values["client_id"], "106533743")
        self.assertEqual(values["api_version"], "HealthKitRunningGroupPortal_6.26.4.200")
        self.assertEqual(values["permission_settings"], {
            "allow_private": True,
            "allow_group": False,
            "extra_umo_whitelist": [],
            "admin_only": True,
        })

    def test_schema_returned_verbatim(self):
        """契约 §2：schema 原样返回（含 description / hint），不做裁剪或改写。"""
        schema = data_of(self.fetch())["schema"]
        self.assertEqual(schema, SCHEMA)
        # 契约 §8.10：_conf_schema.json 顶层键数必须仍是 18
        self.assertEqual(len(schema), 18)

    def test_meta_bounds_match_contract(self):
        bounds = meta_of(self.fetch())["bounds"]
        self.assertEqual({key: tuple(value) for key, value in bounds.items()},
                         {key: tuple(value) for key, value in BOUNDS.items()})

    def test_meta_sensitive_is_the_seven_cookie_leaves(self):
        sensitive = meta_of(self.fetch())["sensitive"]
        self.assertEqual(sorted(sensitive), sorted(SENSITIVE_LEAVES))
        self.assertEqual(len(sensitive), 7)

    def test_meta_has_value_covers_sensitive_leaves(self):
        has_value = meta_of(self.fetch())["has_value"]
        self.assertEqual(set(has_value), set(SENSITIVE_LEAVES))
        for key in SENSITIVE_LEAVES:
            self.assertIs(has_value[key], False, key)  # 默认配置全空

    def test_meta_source_and_updated_at(self):
        meta = meta_of(self.fetch())
        self.assertEqual(meta["source"], "astrbot_config")
        self.assertIsInstance(meta["updated_at"], str)
        self.assertTrue(meta["updated_at"])

    def test_meta_revision_is_a_stable_string(self):
        first = meta_of(self.fetch())["revision"]
        second = meta_of(self.fetch())["revision"]
        self.assertIsInstance(first, str)
        self.assertTrue(first)
        self.assertEqual(first, second, "没有写操作时 revision 必须恒定")

    def test_missing_keys_filled_from_schema_default(self):
        """契约 §2：缺失的配置键按 schema 的 default 补齐（旧配置升级场景）。"""
        plugin, api, cfg = make_api(make_config({"token_ttl": 1200}))
        values = values_of(fetch_config(api))
        self.assertEqual(values["token_ttl"], 1200)          # 配置里有的
        self.assertEqual(values["page_timeout"], 90)          # 配置里没有的 → schema 默认
        self.assertEqual(values["warmup"], True)              # schema 默认 true
        self.assertEqual(values["data_ttl"], 600)
        self.assertEqual(values["client_id"], "106533743")
        self.assertEqual(values["permission_settings"], {
            "allow_private": True,
            "allow_group": False,
            "extra_umo_whitelist": [],
            "admin_only": True,
        })
        self.assertEqual(set(values), set(FLAT_LEAVES) | {"permission_settings"})


# ============================ 掩码 ============================

class TestSensitiveMasking(_ApiCase):
    """契约 §2 / §3.1：响应体永不含真实 cookie，只有 ``***`` + ``has_value``。"""

    #: 每个敏感项一个不可能与 JSON 字面量撞车的唯一哨兵。
    SENTINELS = {
        "cookie_json": "SENTINEL-JSON-9f1c",
        "cookie_CASTGC": "SENTINEL-CASTGC-2a7b",
        "cookie_sid": "SENTINEL-SID-4d3e",
        "cookie_hwid_cas_sid": "SENTINEL-HWID-5b6a",
        "cookie_HuaweiID_CAS_ISCASLOGIN": "SENTINEL-ISCAS-7c8d",
        "cookie_CASLOGINSITE": "SENTINEL-SITE-1e2f",
        "cookie_LOGINACCSITE": "SENTINEL-ACCSITE-3a4b",
    }

    def _api_with_sentinels(self):
        data = full_config()
        data.update(self.SENTINELS)
        return make_api(make_config(data))

    def test_get_masks_all_seven_and_never_leaks(self):
        _, api, _ = self._api_with_sentinels()
        resp = fetch_config(api)
        values = values_of(resp)
        for key in SENSITIVE_LEAVES:
            self.assertEqual(values[key], MASK, key)
        blob = json.dumps(resp, ensure_ascii=False)
        for key, sentinel in self.SENTINELS.items():
            self.assertNotIn(sentinel, blob, "%s 的真实值泄漏进了响应体" % key)
        self.assertNotIn("TGT-", blob)
        has_value = meta_of(resp)["has_value"]
        for key in SENSITIVE_LEAVES:
            self.assertIs(has_value[key], True, key)

    def test_get_masks_even_when_empty(self):
        values = values_of(self.fetch())
        for key in SENSITIVE_LEAVES:
            self.assertEqual(values[key], MASK, key)
        has_value = meta_of(self.fetch())["has_value"]
        for key in SENSITIVE_LEAVES:
            self.assertIs(has_value[key], False, key)

    def test_has_value_tracks_each_sensitive_key(self):
        data = full_config()
        data["cookie_CASTGC"] = self.SENTINELS["cookie_CASTGC"]
        data["cookie_sid"] = self.SENTINELS["cookie_sid"]
        _, api, _ = make_api(make_config(data))
        has_value = meta_of(fetch_config(api))["has_value"]
        for key in SENSITIVE_LEAVES:
            expected = key in ("cookie_CASTGC", "cookie_sid")
            self.assertIs(has_value[key], expected, key)

    def test_post_response_is_masked_too(self):
        """契约 §3.3：POST 成功响应里也带一份 values/meta，掩码规则同样适用。"""
        _, api, _ = self._api_with_sentinels()
        resp = post_config(api, {"values": {"token_ttl": 1200}, "revision": revision_of(api)})
        payload = self.assert_ok(resp)
        for key in SENSITIVE_LEAVES:
            self.assertEqual(payload["data"]["values"][key], MASK, key)
        blob = json.dumps(resp, ensure_ascii=False)
        for key, sentinel in self.SENTINELS.items():
            self.assertNotIn(sentinel, blob, "%s 的真实值泄漏进了保存响应" % key)


# ============================ 21 叶子逐项生效 ============================

#: 每个叶子的新值：与 schema 默认值都不同，且落在合法范围内（钳制用例另测）。
LEAF_CASES = {
    "cookie_json": '[{"name":"CASTGC","value":"CASTGC-NEW"},{"name":"sid","value":"sid-NEW"}]',
    "cookie_CASTGC": "CASTGC-NEW-9f1c",
    "cookie_sid": "sid-NEW-2a7b",
    "cookie_hwid_cas_sid": "hwid-NEW-4d3e",
    "cookie_HuaweiID_CAS_ISCASLOGIN": "iscas-NEW-5b6a",
    "cookie_CASLOGINSITE": "site-NEW-7c8d",
    "cookie_LOGINACCSITE": "accsite-NEW-1e2f",
    "browser_path": "tools/fake-browser.exe",
    "headless": False,
    "page_timeout": 45,
    "token_ttl": 1234,
    "data_ttl": 123,
    "warmup": True,
    "login_daily_limit": 7,
    "timezone": "-0500",
    "client_id": "999888777",
    "api_version": "FakePortal_1.0.0",
    "permission_settings.allow_private": False,
    "permission_settings.allow_group": True,
    "permission_settings.extra_umo_whitelist": [GROUP_UMO],
    "permission_settings.admin_only": False,
}


class TestPostEveryLeafApplies(_ApiCase):
    """契约 §6：21 个叶子逐个 POST 都必须生效。

    诚实说明：``reloaded == []`` 只是**接口形状约束**（实现里就是硬编码的空表），
    它证明不了「这 21 项真的都不用重启」。热生效的证据看真实消费者：
    ``TestHotApplyConsumers`` / ``TestLoginDailyLimitHotApply`` /
    ``TestPermissionCacheRefresh`` / ``TestWarmupHotApply``。
    """

    def test_case_table_covers_exactly_21_leaves(self):
        self.assertEqual(len(LEAF_CASES), 21)
        self.assertEqual(set(LEAF_CASES), set(ALL_LEAF_PATHS))
        self.assertEqual(len(set(ALL_LEAF_PATHS)), 21)

    def test_every_leaf_applies(self):
        with StubCookieImport():
            for path, new_value in LEAF_CASES.items():
                with self.subTest(leaf=path):
                    plugin, api, cfg = make_api(make_config())
                    # warmup false→true 会 create_task(_warmup())；换成空实现，避免真去取 token
                    plugin._warmup = _noop_warmup
                    inputs = leaf_body(path, new_value)
                    if path in SENSITIVE_LEAVES and path != "cookie_json":
                        # An identity update cannot borrow required Cookie values
                        # from an old account. Each form field still applies when
                        # the same submission supplies a complete valid set.
                        inputs.setdefault("cookie_CASTGC", "CASTGC-COMPLETE")
                        inputs.setdefault("cookie_sid", "SID-COMPLETE")
                    resp = post_config(api, {
                        "values": inputs,
                        "revision": revision_of(api),
                    })
                    payload = self.assert_ok(resp)
                    self.assertIn(path, payload["applied"], path)
                    self.assertEqual(payload["reloaded"], [], path)
                    self.assertIn(path, payload["changed"], path)
                    self.assertNotIn(path, payload.get("clamped") or {}, path)
                    if path in SENSITIVE_LEAVES:
                        self.assertTrue(all(cfg[key] == "" for key in SENSITIVE_LEAVES))
                        saved = read_config_file(cfg)
                        self.assertTrue(all(saved[key] == "" for key in SENSITIVE_LEAVES))
                    else:
                        self.assertEqual(read_path(cfg, path), new_value, path)
                        self.assertEqual(read_path(read_config_file(cfg), path), new_value, path)
                    # 保存后的 values 是**掩码视图**（契约 §3.3「与 GET 的 values 同构」）：
                    # 7 个敏感项恒为 "***"，是否有值只体现在 meta.has_value。
                    masked = read_path(payload["data"]["values"], path)
                    if path in SENSITIVE_LEAVES:
                        self.assertEqual(masked, MASK, path)
                        self.assertIs(
                            payload["data"]["meta"]["has_value"][path], True, path)
                    else:
                        self.assertEqual(masked, new_value, path)


# ============================ 部分更新 / 响应形状 ============================

class TestPartialUpdate(_ApiCase):
    """契约 §0.2 / §3.1 / §3.3：部分更新不许连带改别的键，响应形状对齐 GET。"""

    def test_flat_partial_keeps_other_leaves(self):
        before = copy.deepcopy(dict(self.config))
        payload = self.assert_ok(self.send({"token_ttl": 1111}))
        self.assertEqual(payload["applied"], ["token_ttl"])
        saved = self.saved()
        self.assertEqual(saved["token_ttl"], 1111)
        for key in FLAT_LEAVES:
            if key == "token_ttl":
                continue
            self.assertEqual(saved[key], before[key], key)

    def test_permission_partial_keeps_siblings(self):
        """契约 §0.2 的浅合并陷阱：只传子键时服务端必须自己补全整组。"""
        payload = self.assert_ok(self.send({"permission_settings": {"allow_group": True}}))
        self.assertIn("permission_settings.allow_group", payload["applied"])
        self.assertEqual(self.saved()["permission_settings"], {
            "allow_private": True,
            "allow_group": True,
            "extra_umo_whitelist": [],
            "admin_only": True,
        })

    def test_same_value_is_not_applied(self):
        payload = self.assert_ok(self.send({"token_ttl": self.config["token_ttl"]}))
        self.assertEqual(payload["applied"], [])
        self.assertEqual(payload["changed"], [])
        self.assertEqual(self.config.save_calls, [], "值没变就不该落盘")

    def test_response_mirrors_get(self):
        payload = self.assert_ok(self.send({"token_ttl": 1300}))
        # 顶层与 data 同时给同样的字段（契约 §3.3）
        for key in ("applied", "reloaded", "revision", "changed", "clamped"):
            self.assertIn(key, payload, key)
            self.assertEqual(payload[key], payload["data"][key], key)
        self.assertEqual(payload["revision"], self.revision())
        # data.values / data.meta 与 GET 同构
        got = data_of(self.fetch())
        self.assertEqual(set(payload["data"]["values"]), set(got["values"]))
        self.assertEqual(set(payload["data"]["meta"]), set(got["meta"]))
        self.assertEqual(payload["data"]["values"]["token_ttl"], 1300)

    def test_message_counts_applied_items(self):
        """契约 §3.3：``message`` 形如「已生效 N 项」，数字要和应用项数一致。"""
        payload = self.assert_ok(self.send({
            "token_ttl": 1300,
            "permission_settings": {"allow_group": True},
        }))
        self.assertEqual(len(payload["applied"]), 2)
        self.assertIn("2", payload["message"])

    def test_real_change_mixed_with_unchanged_value(self):
        """同一批提交里「真变 + 同值」必须分开算（变异 ``applied = accepted`` 的杀手）。

        契约 §3.3：传了但值相同的项不计入 ``applied``/``changed``，也不写盘。
        """
        current = self.config["data_ttl"]
        payload = self.assert_ok(self.send({"token_ttl": 1250, "data_ttl": current}))
        self.assertEqual(payload["applied"], ["token_ttl"])
        self.assertEqual(payload["changed"], ["token_ttl"])
        self.assertNotIn("data_ttl", payload["applied"])
        self.assertNotIn("data_ttl", payload["changed"])
        self.assertNotIn("data_ttl", payload.get("clamped") or {})
        self.assertIn("1 项", payload["message"])
        self.assertEqual(self.saved()["token_ttl"], 1250)
        self.assertEqual(self.saved()["data_ttl"], current)


# ============================ 类型 / 白名单校验 ============================

class TestTypeValidation(_ApiCase):
    """契约 §3.2 第 1~3 步：白名单 + 类型 + 钳制校验，任一失败 → 整单 400。"""

    def test_body_not_json(self):
        payload = self.assert_error(post_config(self.api, "{这不是 JSON"), 400)
        self.assertIn("JSON", payload["message"])

    def test_body_is_json_but_not_object(self):
        payload = self.assert_error(post_config(self.api, [1, 2, 3]), 400)
        self.assertIn("对象", payload["message"])

    def test_values_missing(self):
        payload = self.assert_error(post_config(self.api, {"revision": self.revision()}), 400)
        self.assertIn("values", payload["message"])

    def test_values_not_object(self):
        payload = self.assert_error(
            post_config(self.api, {"values": ["token_ttl"], "revision": self.revision()}), 400)
        self.assertIn("values", payload["message"])

    def test_unknown_key(self):
        payload = self.assert_error(self.send({"不存在的key": 1}), 400, "不存在的key")
        self.assertIn("未知", payload["message"])

    def test_unknown_nested_key(self):
        payload = self.assert_error(
            self.send({"permission_settings": {"不存在的子键": True}}),
            400, "permission_settings.不存在的子键")
        self.assertIn("未知", payload["message"])

    def test_bool_leaf_rejects_string(self):
        """契约 §1：bool 项是**严格** bool，字符串一律拒绝。"""
        payload = self.assert_error(self.send({"headless": "true"}), 400, "headless")
        self.assertIn("必须", payload["message"])

    def test_bool_leaf_rejects_int(self):
        payload = self.assert_error(self.send({"warmup": 1}), 400, "warmup")
        self.assertIn("必须", payload["message"])

    def test_int_leaf_rejects_text(self):
        payload = self.assert_error(self.send({"token_ttl": "abc"}), 400, "token_ttl")
        self.assertIn("必须", payload["message"])

    def test_string_leaf_rejects_int(self):
        payload = self.assert_error(self.send({"client_id": 106533743}), 400, "client_id")
        self.assertIn("必须", payload["message"])

    def test_object_leaf_rejects_non_object(self):
        payload = self.assert_error(self.send({"permission_settings": True}),
                                    400, "permission_settings")
        self.assertIn("必须", payload["message"])

    def test_list_leaf_rejects_string(self):
        payload = self.assert_error(
            self.send({"permission_settings": {"extra_umo_whitelist": GROUP_UMO}}),
            400, "permission_settings.extra_umo_whitelist")
        self.assertIn("必须", payload["message"])

    def test_one_bad_leaf_rejects_whole_request(self):
        """整单拒绝：合法项也不许被写进去。"""
        resp = self.send({"token_ttl": 1300, "headless": "true"})
        self.assert_error(resp, 400, "headless")
        self.assertEqual(self.config["token_ttl"], 3000)
        self.assertEqual(self.config.save_calls, [])


class TestUmoValidation(_ApiCase):
    """契约 §1 / §3.4：非法 UMO 整单拒绝，``field`` 指向白名单那一项。"""

    def test_illegal_umo_rejects_whole_request(self):
        resp = self.send({
            "token_ttl": 1300,
            "permission_settings": {"extra_umo_whitelist": [GROUP_UMO, "坏格式"]},
        })
        payload = self.assert_error(resp, 400, "permission_settings.extra_umo_whitelist")
        self.assertIn("不合法", payload["message"])
        self.assertEqual(self.config["permission_settings"]["extra_umo_whitelist"], [])
        self.assertEqual(self.config["token_ttl"], 3000)

    def test_unknown_message_type_is_rejected(self):
        resp = self.send({"permission_settings": {
            "extra_umo_whitelist": ["aiocqhttp:BadMessage:123"]}})
        payload = self.assert_error(resp, 400, "permission_settings.extra_umo_whitelist")
        self.assertIn("不合法", payload["message"])

    def test_non_string_entry_is_rejected(self):
        """``list[str]`` 类型层拒绝即可：契约 §3.4 的类型错误文案是「<key> 必须是 …」，
        「会话 UMO 格式不合法」只约束**字符串**形式的非法 UMO（见上面两个用例）。
        这里只锁死契约能推出的部分：400 + 精确 field + 是「类型」错误。"""
        resp = self.send({"permission_settings": {"extra_umo_whitelist": [123]}})
        payload = self.assert_error(resp, 400, "permission_settings.extra_umo_whitelist")
        self.assertIn("必须", payload["message"])

    def test_valid_umo_is_accepted(self):
        payload = self.assert_ok(self.send({"permission_settings": {
            "extra_umo_whitelist": [GROUP_UMO, "aiocqhttp:FriendMessage:998877"]}}))
        self.assertIn("permission_settings.extra_umo_whitelist", payload["applied"])
        self.assertEqual(self.saved()["permission_settings"]["extra_umo_whitelist"],
                         [GROUP_UMO, "aiocqhttp:FriendMessage:998877"])


# ============================ 点号键写法（D-1 回归） ============================

class TestDotNotationGroupKeys(_ApiCase):
    """契约 §1 / §3.2：``"permission_settings.sub"`` 点号写法必须与嵌套写法**同口径**。

    验收 Agent 发现的 D-1：点号键会精确命中摊平后的叶子表，从而绕过分组分支里的
    UMO 校验 —— ``{"values": {"permission_settings.extra_umo_whitelist": ["garbage"]}}``
    曾经 200 并把脏 UMO 落盘。下面几条钉住「先归一化成嵌套 dict，再走统一校验」。
    """

    def test_dot_key_with_illegal_umo_is_rejected(self):
        digest = sha256_file(self.config.config_path)
        memory = copy.deepcopy(dict(self.config))
        resp = self.send({"permission_settings.extra_umo_whitelist": ["garbage"]})
        payload = self.assert_error(resp, 400, "permission_settings.extra_umo_whitelist")
        self.assertIn("不合法", payload["message"])
        self.assertEqual(sha256_file(self.config.config_path), digest,
                         "点号写法绕过校验，把脏 UMO 落盘了")
        self.assertEqual(dict(self.config), memory, "点号写法失败后不许改内存配置")
        self.assertEqual(self.config.save_calls, [], "失败请求不该触发落盘")

    def test_dot_key_with_valid_umo_applies(self):
        """别把功能一起禁掉：合法 UMO 走点号写法必须正常生效。"""
        payload = self.assert_ok(self.send({
            "permission_settings.extra_umo_whitelist": [GROUP_UMO]}))
        self.assertEqual(payload["applied"],
                         ["permission_settings.extra_umo_whitelist"])
        self.assertEqual(payload["reloaded"], [])
        self.assertEqual(self.config["permission_settings"]["extra_umo_whitelist"],
                         [GROUP_UMO])
        self.assertEqual(self.saved()["permission_settings"]["extra_umo_whitelist"],
                         [GROUP_UMO])
        # 真实消费者：白名单缓存必须重建（不是靠回读配置证明热生效）
        self.assertEqual(self.plugin._whitelist(), {GROUP_UMO})

    def test_dot_key_bool_applies(self):
        payload = self.assert_ok(self.send({"permission_settings.admin_only": False}))
        self.assertEqual(payload["applied"], ["permission_settings.admin_only"])
        self.assertFalse(self.plugin._cfg_bool("admin_only", True))  # 运行时实时读取
        self.assertEqual(self.saved()["permission_settings"], {
            "allow_private": True,
            "allow_group": False,
            "extra_umo_whitelist": [],
            "admin_only": False,      # 兄弟子键一个都不能被整组替换掉
        })

    def test_dot_key_unknown_subkey_is_rejected(self):
        payload = self.assert_error(
            self.send({"permission_settings.不存在的子键": True}),
            400, "permission_settings.不存在的子键")
        self.assertIn("未知", payload["message"])

    def test_dot_key_and_nested_form_in_one_request(self):
        """同一请求里两种写法并存：都要生效（归一化时按出现顺序合并）。"""
        payload = self.assert_ok(self.send({
            "permission_settings": {"allow_group": True},
            "permission_settings.extra_umo_whitelist": [GROUP_UMO],
        }))
        self.assertEqual(sorted(payload["applied"]), [
            "permission_settings.allow_group",
            "permission_settings.extra_umo_whitelist",
        ])
        self.assertEqual(self.saved()["permission_settings"], {
            "allow_private": True,
            "allow_group": True,
            "extra_umo_whitelist": [GROUP_UMO],
            "admin_only": True,
        })
        self.assertEqual(self.plugin._whitelist(), {GROUP_UMO})


# ============================ 分组键形态冲突（D-6 回归） ============================

class TestGroupTypeConflict(_ApiCase):
    """契约 §3.4：同一分组既给非对象值、又给子键时，必须 400「必须是对象」。

    验收 Agent 发现的 D-6：``_expand_dotted()`` 早先用空 dict 顶替「已存在但不是 dict」
    的分组，于是

        ``{"permission_settings": "x", "permission_settings.allow_group": true}``
            → 200，非法值被**静默丢弃**；
        ``{"permission_settings.allow_group": true, "permission_settings": "x"}``
            → 400。

    同一逻辑请求因为 JSON 成员顺序不同给出两种结果，违反「必须是对象」。
    **本类所有用例的核心都是「结果不依赖成员顺序」**——不只是「某个顺序返回 400」。
    """

    #: 三种「非对象」形态：字符串 / null / 数组。
    NON_OBJECTS = ("x", None, ["x"])

    def assert_group_conflict(self, values):
        """POST 一组必然冲突的 values：400 + 精确 field + 不落盘 + 不动内存。"""
        plugin, api, cfg = make_api(make_config())
        digest = sha256_file(cfg.config_path)
        memory = copy.deepcopy(dict(cfg))
        resp = post_config(api, {"values": values, "revision": revision_of(api)})
        payload = self.assert_error(resp, 400, "permission_settings")
        self.assertIn("必须", payload["message"])
        self.assertEqual(sha256_file(cfg.config_path), digest, "非法输入被落盘了")
        self.assertEqual(dict(cfg), memory, "非法输入改了内存配置")
        self.assertEqual(cfg.save_calls, [], "非法输入触发了落盘")
        return payload

    def test_non_object_group_before_dot_key_rejected(self):
        """``permission_settings`` 在前（非对象），点号键随后撞上它。"""
        for bad in self.NON_OBJECTS:
            with self.subTest(bad=repr(bad), order="分组在前"):
                self.assert_group_conflict({
                    "permission_settings": bad,
                    "permission_settings.allow_group": True,
                })

    def test_non_object_group_after_dot_key_rejected(self):
        """反序：点号键先建出分组，随后又来一个非对象的 ``permission_settings``。"""
        for bad in self.NON_OBJECTS:
            with self.subTest(bad=repr(bad), order="点号键在前"):
                self.assert_group_conflict({
                    "permission_settings.allow_group": True,
                    "permission_settings": bad,
                })

    def test_dot_subkey_on_plain_leaf_is_not_silently_dropped(self):
        """**普通叶子**塞点号子键：这是 ``_expand_dotted`` 第二个 raise 唯一的防线。

        ``permission_settings`` 这类**分组**键即使漏掉那个 raise，后面 ``_validate_patch``
        的分组分支还会独立兜底抛 400；但 ``timezone`` 这种普通叶子没有分组分支兜底——
        少了 raise，``{"timezone.x": 1, "timezone": "abc"}`` 会 200：点号子键被**静默丢弃**、
        ``timezone`` 被写成 ``"abc"``，违反契约 §3.4「未知配置项必须 400」。
        """
        cases = (
            ("点号子键在前", {"timezone.x": 1, "timezone": "abc"}),
            ("合法值在前", {"timezone": "abc", "timezone.x": 1}),
            ("只给点号子键", {"timezone.x": 1}),
        )
        for label, values in cases:
            with self.subTest(order=label):
                plugin, api, cfg = make_api(make_config())
                digest = sha256_file(cfg.config_path)
                memory = copy.deepcopy(dict(cfg))
                resp = post_config(api, {"values": values, "revision": revision_of(api)})
                payload = self.assert_error(resp, 400, "timezone")
                self.assertTrue(payload["message"])
                self.assertEqual(sha256_file(cfg.config_path), digest,
                                 "%s：非法输入被落盘了" % label)
                self.assertEqual(dict(cfg), memory, "%s：非法输入改了内存配置" % label)
                self.assertEqual(cfg.save_calls, [], "%s：非法输入触发了落盘" % label)
                # "abc" 绝不许被写进配置（内存与落盘都不许）
                self.assertNotEqual(cfg["timezone"], "abc", label)
                self.assertNotEqual(read_config_file(cfg)["timezone"], "abc", label)

    def test_result_does_not_depend_on_member_order(self):
        """核心断言：同一逻辑请求，两种 JSON 成员顺序必须给出**完全相同**的响应。"""
        outcomes = []
        for label, values in (
            ("分组在前", {"permission_settings": "x",
                          "permission_settings.allow_group": True}),
            ("点号键在前", {"permission_settings.allow_group": True,
                            "permission_settings": "x"}),
        ):
            plugin, api, cfg = make_api(make_config())
            resp = post_config(api, {"values": values, "revision": revision_of(api)})
            payload = self.assert_error(resp, 400, "permission_settings")
            outcomes.append((label, resp["status_code"], payload.get("field")))
        self.assertEqual(
            [item[1:] for item in outcomes],
            [(400, "permission_settings"), (400, "permission_settings")],
            "同一逻辑请求因 JSON 成员顺序不同而结果不同：%r" % (outcomes,))

    def test_two_dict_forms_merge_and_apply(self):
        """正对照：两种写法**都是 dict** 时必须正常合并生效（别把功能一起禁掉）。"""
        payload = self.assert_ok(self.send({
            "permission_settings": {"allow_group": True},
            "permission_settings.extra_umo_whitelist": ["aiocqhttp:GroupMessage:9"],
        }))
        self.assertEqual(sorted(payload["applied"]), [
            "permission_settings.allow_group",
            "permission_settings.extra_umo_whitelist",
        ])
        self.assertEqual(self.saved()["permission_settings"], {
            "allow_private": True,
            "allow_group": True,
            "extra_umo_whitelist": ["aiocqhttp:GroupMessage:9"],
            "admin_only": True,        # 兄弟子键不许丢
        })
        self.assertEqual(self.plugin._whitelist(), {"aiocqhttp:GroupMessage:9"})


# ============================ 脏写防护 ============================

class TestDirtyWriteProtection(_ApiCase):
    """契约 §3.4 / §6：400 与 409 绝不许改动配置——文件 sha256 与内存值都不变。"""

    def snapshot(self):
        return sha256_file(self.config.config_path), copy.deepcopy(dict(self.config))

    def assert_untouched(self, snapshot):
        digest, memory = snapshot
        self.assertEqual(sha256_file(self.config.config_path), digest,
                         "失败请求改了配置文件")
        self.assertEqual(dict(self.config), memory, "失败请求改了内存配置")

    def test_invalid_type_does_not_write(self):
        snap = self.snapshot()
        self.assert_error(self.send({"token_ttl": "abc"}), 400, "token_ttl")
        self.assert_untouched(snap)

    def test_unknown_key_does_not_write(self):
        snap = self.snapshot()
        self.assert_error(self.send({"不存在的key": 1}), 400, "不存在的key")
        self.assert_untouched(snap)

    def test_illegal_umo_does_not_write(self):
        snap = self.snapshot()
        self.assert_error(
            self.send({"permission_settings": {"extra_umo_whitelist": ["坏格式"]}}),
            400, "permission_settings.extra_umo_whitelist")
        self.assert_untouched(snap)

    def test_stale_revision_does_not_write(self):
        snap = self.snapshot()
        resp = self.send({"token_ttl": 1300}, revision=str(self.revision()) + "-stale")
        payload = self.assert_error(resp, 409, "revision")
        self.assertIn("刷新", payload["message"])
        self.assert_untouched(snap)

    def test_missing_revision_is_409(self):
        snap = self.snapshot()
        resp = post_config(self.api, {"values": {"token_ttl": 1300}})
        self.assert_error(resp, 409, "revision")
        self.assert_untouched(snap)

    def test_invalid_value_wins_over_missing_revision(self):
        """契约 §3.2：第 3 步（校验）先于第 4 步（revision），非法值恒 400。"""
        snap = self.snapshot()
        resp = post_config(self.api, {"values": {"token_ttl": "abc"}})
        self.assert_error(resp, 400, "token_ttl")
        self.assert_untouched(snap)

    def test_illegal_umo_wins_over_missing_revision(self):
        snap = self.snapshot()
        resp = post_config(self.api, {"values": {"permission_settings": {
            "extra_umo_whitelist": ["坏格式"]}}})
        self.assert_error(resp, 400, "permission_settings.extra_umo_whitelist")
        self.assert_untouched(snap)

    def test_missing_values_wins_over_missing_revision(self):
        snap = self.snapshot()
        self.assert_error(post_config(self.api, {}), 400)
        self.assert_untouched(snap)


# ============================ revision ============================

class TestRevisionContract(_ApiCase):
    """契约 §3.5：revision 覆盖「落盘计数 + 文件 mtime」，落盘一次就换一个。"""

    def test_get_revision_is_stable_without_writes(self):
        self.assertEqual(self.revision(), self.revision())

    def test_revision_changes_after_save(self):
        before = self.revision()
        payload = self.assert_ok(self.send({"token_ttl": 1300}, revision=before))
        after = payload["revision"]
        self.assertNotEqual(after, before)
        self.assertEqual(after, payload["data"]["revision"])
        self.assertEqual(after, self.revision(), "保存后的 revision 必须与下一次 GET 一致")

    def test_revision_tracks_fake_config_save_counter(self):
        """FakeConfig 的计数字段真的被后端读到了（否则 revision 形同虚设）。"""
        before = self.config._save_revision
        self.assert_ok(self.send({"token_ttl": 1300}))
        self.assertEqual(self.config._save_revision, before + 1)

    def test_successive_saves_keep_bumping_revision(self):
        revisions = []
        for value in (1310, 1320, 1330):
            revisions.append(self.assert_ok(self.send({"token_ttl": value}))["revision"])
        self.assertEqual(len(set(revisions)), 3)


# ============================ "***" 回写防护 ============================

class TestMaskWriteBack(_ApiCase):
    """契约 §3.1：敏感项传回 ``***`` 视为未修改，绝不能被写进配置。"""

    #: 5 项有值、2 项留空，两种情形都要覆盖。
    ORIGINALS = {
        "cookie_json": "ORIGINAL-JSON-9f1c",
        "cookie_CASTGC": "ORIGINAL-CASTGC-2a7b",
        "cookie_sid": "ORIGINAL-SID-4d3e",
        "cookie_hwid_cas_sid": "ORIGINAL-HWID-5b6a",
        "cookie_HuaweiID_CAS_ISCASLOGIN": "ORIGINAL-ISCAS-7c8d",
        "cookie_CASLOGINSITE": "",
        "cookie_LOGINACCSITE": "",
    }

    def setUp(self):
        super().setUp()
        self.config.update(copy.deepcopy(self.ORIGINALS))
        self.config._write_file()  # 让磁盘与内存一致，sha256 断言才成立

    def test_mask_value_is_skipped(self):
        with StubCookieImport() as stub:
            payload = self.assert_ok(self.send({"cookie_CASTGC": MASK}))
            self.assertEqual(stub.calls, [], "传回 *** 不该触发 cookie 导入")
        self.assertEqual(payload["applied"], [])
        self.assertEqual(payload["changed"], [])
        self.assertEqual(self.config["cookie_CASTGC"], self.ORIGINALS["cookie_CASTGC"])
        self.assertEqual(self.saved()["cookie_CASTGC"], self.ORIGINALS["cookie_CASTGC"])
        self.assertEqual(self.config.save_calls, [], "没有任何有效变更时不该落盘")

    def test_all_seven_masks_are_skipped(self):
        with StubCookieImport() as stub:
            payload = self.assert_ok(self.send({key: MASK for key in SENSITIVE_LEAVES}))
            self.assertEqual(stub.calls, [])
        self.assertEqual(payload["applied"], [])
        saved = self.saved()
        for key in SENSITIVE_LEAVES:
            self.assertEqual(saved[key], self.ORIGINALS[key], key)

    def test_mask_does_not_flip_has_value(self):
        with StubCookieImport():
            self.assert_ok(self.send({key: MASK for key in SENSITIVE_LEAVES}))
        has_value = meta_of(self.fetch())["has_value"]
        for key in SENSITIVE_LEAVES:
            self.assertIs(has_value[key], bool(self.ORIGINALS[key]), key)

    def test_mask_mixed_with_real_change(self):
        with StubCookieImport() as stub:
            payload = self.assert_ok(self.send({"cookie_CASTGC": MASK, "token_ttl": 1300}))
            self.assertEqual(stub.calls, [])
        self.assertEqual(payload["applied"], ["token_ttl"])
        self.assertEqual(self.config["cookie_CASTGC"], self.ORIGINALS["cookie_CASTGC"])
        self.assertEqual(self.saved()["token_ttl"], 1300)

    def test_padded_mask_is_treated_as_unchanged(self):
        """带空白的掩码变体也必须当「未修改」。

        严格 ``== "***"`` 时 ``" *** "`` 会被当成真实值写进配置、覆盖真实 cookie；
        这里用**真实消费者**（cookie 文件里的 CASTGC）而不是回读配置来证明没被覆盖。
        """
        # A pre-existing legacy snapshot isolates mask/no-op behavior from the
        # host's DPAPI availability. Real secure writes are covered separately.
        cookies = hw_auth.cookies_from_fields(
            {"CASTGC": "REAL-CASTGC-9f1c", "sid": "REAL-SID-2a7b"})
        with open(self.plugin.cookie_file, "w", encoding="utf-8") as stream:
            json.dump(cookies, stream)
        self.assertEqual(self.cookie_file_value("CASTGC"), "REAL-CASTGC-9f1c")
        original = self.config["cookie_CASTGC"]

        for padded in (" *** ", "***\t", "\t***\n"):
            with self.subTest(mask=repr(padded)):
                with StubCookieImport() as stub:
                    payload = self.assert_ok(self.send({"cookie_CASTGC": padded}))
                    self.assertEqual(stub.calls, [], "掩码变体不该触发 cookie 导入")
                self.assertEqual(payload["applied"], [])
                self.assertEqual(payload["changed"], [])
                self.assertEqual(self.config["cookie_CASTGC"], original,
                                 "掩码变体被当成真实值写进了配置")
                self.assertEqual(self.saved()["cookie_CASTGC"], original)
                self.assertEqual(self.cookie_file_value("CASTGC"), "REAL-CASTGC-9f1c",
                                 "真实 cookie 被掩码变体覆盖了")

    def cookie_file_value(self, name):
        """读 cookie 文件里某个 cookie 的真实值（真实消费者，不是配置回读）。"""
        for cookie in self.plugin.auth.load_cookies():
            if cookie.get("name") == name:
                return cookie.get("value")
        return None


# ============================ cookie 热生效 ============================

class TestCookieHotApply(_ApiCase):
    """Secure Cookie updates replace the full set and remove plaintext config copies."""

    def test_cookie_field_triggers_import(self):
        with StubCookieImport(result=3) as stub:
            payload = self.assert_ok(self.send({"cookie_CASTGC": "CASTGC-NEW-9f1c",
                                                "cookie_sid": "SID-NEW-9f1c"}))
        self.assertIn("cookie_CASTGC", payload["applied"])
        self.assertEqual(payload["reloaded"], [])
        self.assertEqual(len(stub.calls), 1)
        call = stub.calls[0]
        self.assertFalse(call["only_if_changed"], "不能用指纹快路径跳过旧明文文件的安全迁移")
        self.assertTrue(call["replace_existing"], "不能继承旧账号的辅助 Cookie")
        self.assertEqual(call["fields"].get("CASTGC"), "CASTGC-NEW-9f1c")
        self.assertEqual(call["fields"].get("sid"), "SID-NEW-9f1c")
        for name in ("hwid_cas_sid", "HuaweiID_CAS_ISCASLOGIN",
                     "CASLOGINSITE", "LOGINACCSITE"):
            self.assertEqual(call["fields"].get(name), "", name)
        self.assertTrue(all(self.config[key] == "" for key in SENSITIVE_LEAVES))

    def test_cookie_json_triggers_import_with_raw_json(self):
        raw = '[{"name":"CASTGC","value":"X"},{"name":"sid","value":"Y"}]'
        with StubCookieImport(result=2) as stub:
            payload = self.assert_ok(self.send({"cookie_json": raw}))
        self.assertIn("cookie_json", payload["applied"])
        self.assertEqual(len(stub.calls), 1)
        self.assertEqual(stub.calls[0]["json_text"], raw)
        self.assertFalse(stub.calls[0]["only_if_changed"])
        self.assertTrue(stub.calls[0]["replace_existing"])

    def test_non_cookie_change_does_not_import(self):
        with StubCookieImport() as stub:
            self.assert_ok(self.send({"token_ttl": 1300}))
        self.assertEqual(stub.calls, [])

    def test_same_legacy_values_still_migrate_and_clear_plaintext(self):
        """An explicit re-submit must migrate even if its values equal old config."""
        values = {"cookie_CASTGC": "CASTGC-NEW-9f1c", "cookie_sid": "SID-NEW-9f1c"}
        self.config.update(values)
        self.config._write_file()
        with StubCookieImport() as stub:
            payload = self.assert_ok(self.send(values))
        self.assertIn("cookie_CASTGC", payload["applied"])
        self.assertEqual(len(stub.calls), 1)
        self.assertFalse(stub.calls[0]["only_if_changed"])
        self.assertTrue(all(self.saved()[key] == "" for key in SENSITIVE_LEAVES))

    def test_import_failure_is_400_and_nothing_is_saved(self):
        digest = sha256_file(self.config.config_path)
        memory = copy.deepcopy(dict(self.config))
        error = hw_auth.HuaweiAuthError("缺少必要的 cookie：sid")
        with StubCookieImport(error=error):
            resp = self.send({"cookie_CASTGC": "CASTGC-NEW-9f1c", "cookie_sid": "SID-NEW"})
        payload = self.assert_error(resp, 400, "cookie_CASTGC")
        self.assertIn("cookie", payload["message"].lower())
        self.assertEqual(sha256_file(self.config.config_path), digest,
                         "cookie 导入失败后不许落盘（契约 §3.2 第 5 步）")
        self.assertEqual(dict(self.config), memory, "cookie 导入失败后不许改内存配置")


# ============================ login_daily_limit 热生效 ============================

class TestLoginDailyLimitHotApply(_ApiCase):
    """契约 §4：登录额度热生效，并保留 1..10 的钳制。"""

    def test_sets_login_manager_limit(self):
        self.assertEqual(self.plugin.login_manager.daily_limit, 3)
        payload = self.assert_ok(self.send({"login_daily_limit": 7}))
        self.assertNotIn("login_daily_limit", payload.get("clamped") or {})
        self.assertEqual(self.plugin.login_manager.daily_limit, 7)

    def test_clamped_high_and_still_in_range(self):
        payload = self.assert_ok(self.send({"login_daily_limit": 99}))
        self.assertEqual(self.config["login_daily_limit"], 10)
        self.assertEqual(payload["clamped"].get("login_daily_limit"), 10)
        self.assertEqual(self.plugin.login_manager.daily_limit, 10)

    def test_clamped_low_and_still_in_range(self):
        payload = self.assert_ok(self.send({"login_daily_limit": 0}))
        self.assertEqual(self.config["login_daily_limit"], 1)
        self.assertEqual(payload["clamped"].get("login_daily_limit"), 1)
        self.assertEqual(self.plugin.login_manager.daily_limit, 1)

    def test_every_in_range_value_is_applied_verbatim(self):
        for value in (1, 5, 9, 10):
            with self.subTest(value=value):
                plugin, api, cfg = make_api(make_config())
                payload = self.assert_ok(post_config(api, {
                    "values": {"login_daily_limit": value},
                    "revision": revision_of(api),
                }))
                self.assertEqual(payload["applied"], ["login_daily_limit"])
                self.assertEqual(plugin.login_manager.daily_limit, value)
                self.assertGreaterEqual(plugin.login_manager.daily_limit, 1)
                self.assertLessEqual(plugin.login_manager.daily_limit, 10)
                self.assertEqual(cfg["login_daily_limit"], value)


# ============================ warmup 热生效 ============================

class TestWarmupHotApply(_ApiCase):
    """契约 §4：``warmup`` 热生效——false→true 新建任务，true→false 取消任务。"""

    def test_false_to_true_creates_and_starts_task(self):
        plugin, api, cfg = make_api(make_config())  # warmup=False
        started = {}
        self.assertIsNone(plugin._warmup_task)

        async def fake_warmup():
            started["yes"] = True

        plugin._warmup = fake_warmup

        async def run():
            revision = await _revision_async(api)
            request.body = {"values": {"warmup": True}, "revision": revision}
            resp = await api.post_config()
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            return resp, plugin._warmup_task

        resp, task = asyncio.run(run())
        payload = self.assert_ok(resp)
        self.assertIn("warmup", payload["applied"])
        self.assertEqual(payload["reloaded"], [])
        self.assertTrue(cfg["warmup"])
        self.assertIsNotNone(task, "warmup false→true 必须新建 _warmup_task")
        self.assertIsInstance(task, asyncio.Task)
        self.assertTrue(started.get("yes"), "新建的预热任务必须真的被调度起来")

    def test_true_to_false_cancels_task(self):
        """必须在**事件循环内**取值：``asyncio.run`` 退出时会替我们 cancel 所有残留任务，
        在循环外读 ``task.done()/cancelled()`` 必然是 True（哪怕实现什么都没做）——
        那是假绿。所以 done/cancelled 都在 ``run()`` 里、``post_config`` 返回后立刻取。"""
        plugin, api, cfg = make_api(make_config(full_config(warmup=True)))

        async def run():
            async def forever():
                await asyncio.sleep(3600)

            task = asyncio.create_task(forever())
            plugin._warmup_task = task
            revision = await _revision_async(api)
            request.body = {"values": {"warmup": False}, "revision": revision}
            resp = await api.post_config()
            for _ in range(3):
                await asyncio.sleep(0)
            # 关键：退出循环前把状态取成布尔，交给循环外的断言
            return resp, task.done(), task.cancelled()

        resp, done, cancelled = asyncio.run(run())
        payload = self.assert_ok(resp)
        self.assertIn("warmup", payload["applied"])
        self.assertEqual(payload["reloaded"], [])
        self.assertFalse(cfg["warmup"])
        self.assertTrue(done, "warmup true→false 必须结束预热任务（循环内取值）")
        self.assertTrue(cancelled, "预热任务必须是被 cancel 掉的（循环内取值）")

    def test_true_to_false_without_task_is_not_an_error(self):
        # 本地新建了一套夹具，必须打到本地 api；self.send() 打的是 setUp 那一份。
        plugin, api, cfg = make_api(make_config(full_config(warmup=True)))
        self.assertIsNone(plugin._warmup_task)
        payload = self.assert_ok(post_config(api, {
            "values": {"warmup": False}, "revision": revision_of(api)}))
        self.assertIn("warmup", payload["applied"])
        self.assertFalse(cfg["warmup"])

    def test_unchanged_value_does_not_start_task(self):
        plugin, api, cfg = make_api(make_config())  # warmup=False
        payload = self.assert_ok(post_config(api, {
            "values": {"warmup": False}, "revision": revision_of(api)}))
        self.assertEqual(payload["applied"], [])
        self.assertIsNone(plugin._warmup_task)


# ============================ 热生效：真实消费者 ============================

class TestHotApplyConsumers(_ApiCase):
    """契约 §4：18 项「运行时实时读取」的项，用**真实消费者**证明不用重启。

    诚实说明：``reloaded == []`` 是接口形状约束（实现里就是硬编码的空表），
    它和「配置回读」都**不能**证明某一次改动真的不用重启。真正能证明的是
    「运行时真正取值的对象/属性已经变了」——所以这个类只读消费者，不读配置。
    """

    def test_browser_settings_reach_the_auth_consumer(self):
        """``browser_path`` / ``headless`` / ``page_timeout`` 由 ``plugin.auth`` 实时读取。"""
        before = self.plugin.auth
        self.assertIs(before.headless, True)
        self.assertEqual(before.page_timeout, 90.0)

        payload = self.assert_ok(self.send({
            "headless": False,
            "page_timeout": 45,
            "browser_path": "tools/fake-browser.exe",
        }))
        self.assertEqual(sorted(payload["applied"]),
                         ["browser_path", "headless", "page_timeout"])

        # 不重建插件、不重启：下一次取 auth 就该拿到新值
        auth = self.plugin.auth
        self.assertIs(auth.headless, False)
        self.assertEqual(auth.page_timeout, 45.0)
        self.assertEqual(auth.browser_path, "tools/fake-browser.exe")


# ============================ 权限缓存刷新 ============================

class TestPermissionCacheRefresh(_ApiCase):
    """契约 §4 末条：改 ``extra_umo_whitelist`` 必须立刻刷新 ``_umo_whitelist`` 缓存。"""

    def test_whitelist_cache_is_refreshed(self):
        # 先让缓存落地（此刻是空集）；后端若不刷新，下面读到的还是这个旧对象
        self.assertEqual(self.plugin._whitelist(), set())
        payload = self.assert_ok(self.send({"permission_settings": {
            "extra_umo_whitelist": [GROUP_UMO]}}))
        self.assertIn("permission_settings.extra_umo_whitelist", payload["applied"])
        self.assertEqual(self.plugin._whitelist(), {GROUP_UMO})
        self.assertEqual(self.plugin._invalid_umos, [])

    def test_whitelist_cache_can_shrink(self):
        data = full_config()
        data["permission_settings"]["extra_umo_whitelist"] = [GROUP_UMO]
        plugin, api, cfg = make_api(make_config(data))
        self.assertEqual(plugin._whitelist(), {GROUP_UMO})  # 缓存住旧值
        payload = self.assert_ok(post_config(api, {
            "values": {"permission_settings": {"extra_umo_whitelist": []}},
            "revision": revision_of(api),
        }))
        self.assertIn("permission_settings.extra_umo_whitelist", payload["applied"])
        self.assertEqual(plugin._whitelist(), set(), "清空白名单后缓存必须跟着变空")

    def test_other_permission_flags_are_read_live(self):
        payload = self.assert_ok(self.send({"permission_settings": {"allow_group": True}}))
        self.assertIn("permission_settings.allow_group", payload["applied"])
        self.assertTrue(self.plugin._cfg_bool("allow_group", False))
        self.assertEqual(self.saved()["permission_settings"]["allow_group"], True)


# ============================ 钳制 ============================

class TestClamp(_ApiCase):
    """契约 §1 / §3.3：越界值按上下限钳制，``clamped`` 回传最终值。"""

    def test_bounds_match_contract(self):
        bounds = meta_of(self.fetch())["bounds"]
        self.assertEqual(set(bounds), set(BOUNDS))
        self.assertEqual({key: tuple(value) for key, value in bounds.items()},
                         {key: tuple(value) for key, value in BOUNDS.items()})

    def test_each_boundary_is_clamped(self):
        for leaf, (low, high) in BOUNDS.items():
            for raw, expected in ((low - 1, low), (high + 1, high)):
                with self.subTest(leaf=leaf, raw=raw):
                    plugin, api, cfg = make_api(make_config())
                    payload = self.assert_ok(post_config(api, {
                        "values": {leaf: raw},
                        "revision": revision_of(api),
                    }))
                    self.assertEqual(payload["applied"], [leaf])
                    self.assertEqual(payload["reloaded"], [])
                    self.assertEqual(payload["clamped"].get(leaf), expected, leaf)
                    self.assertEqual(cfg[leaf], expected, leaf)
                    self.assertEqual(payload["data"]["values"][leaf], expected, leaf)
                    self.assertEqual(read_config_file(cfg)[leaf], expected, leaf)

    def test_clamped_omitted_for_in_range_values(self):
        payload = self.assert_ok(self.send({"page_timeout": 30, "token_ttl": 100}))
        self.assertEqual(payload["clamped"], {})


# ============================ 落盘失败 ============================

class TestSaveFailure(_ApiCase):
    """契约 §3.2 第 6 步 / §3.4：落盘失败必须 500，不许谎报成功。"""

    def test_save_returning_false_is_500(self):
        self.config.save_fail = True
        payload = self.assert_error(self.send({"token_ttl": 1300}), 500)
        self.assertIn("保存", payload["message"])

    def test_save_raising_is_500(self):
        self.config.save_error = OSError("disk is full")
        payload = self.assert_error(self.send({"token_ttl": 1300}), 500)
        self.assertIn("保存", payload["message"])
        # 错误文本必须脱敏：不回显本机绝对路径
        self.assertNotIn(self.config.config_path, payload["message"])


# ============================ 降级路径（裸 dict 配置） ============================

class TestDegradedConfig(_ResponseAssertions, unittest.TestCase):
    """契约 §3.6：桩 / 极简 dict 配置没有 ``save_config_async`` 时必须优雅降级。"""

    def test_bare_dict_config_has_no_framework_hooks(self):
        _, _, cfg = make_api(None)
        self.assertFalse(hasattr(cfg, "save_config_async"))
        self.assertFalse(hasattr(cfg, "config_path"))

    def test_bare_dict_get_still_returns_full_values(self):
        _, api, _ = make_api(None)
        values = values_of(fetch_config(api))
        self.assertEqual(set(values), set(FLAT_LEAVES) | {"permission_settings"})
        self.assertEqual(values["permission_settings"], {
            "allow_private": True,
            "allow_group": False,
            "extra_umo_whitelist": [],
            "admin_only": True,
        })

    def test_bare_dict_post_updates_memory_only(self):
        plugin, api, cfg = make_api(None)
        self.assertFalse(hasattr(cfg, "save_config_async"))
        revision = revision_of(api)
        self.assertIsInstance(revision, str)
        payload = self.assert_ok(post_config(api, {
            "values": {"token_ttl": 4321}, "revision": revision}))
        self.assertEqual(payload["applied"], ["token_ttl"])
        self.assertEqual(payload["reloaded"], [])
        self.assertEqual(cfg["token_ttl"], 4321)  # 只改内存，不落盘

    def test_bare_dict_revision_is_constant(self):
        """桩对象没有 revision 三元组 → 退化成常量，409 不会误触发。"""
        _, api, _ = make_api(None)
        first = revision_of(api)
        payload = self.assert_ok(post_config(api, {
            "values": {"token_ttl": 4321}, "revision": first}))
        self.assertEqual(payload["revision"], revision_of(api))

    def test_bare_dict_permission_group_is_completed(self):
        """配置里没有 permission_settings 时，POST 子键仍要补齐整组。"""
        plugin, api, cfg = make_api(None)
        self.assertNotIn("permission_settings", dict(cfg))
        self.assert_ok(post_config(api, {
            "values": {"permission_settings": {"allow_group": True}},
            "revision": revision_of(api),
        }))
        self.assertEqual(cfg["permission_settings"], {
            "allow_private": True,
            "allow_group": True,
            "extra_umo_whitelist": [],
            "admin_only": True,
        })


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
