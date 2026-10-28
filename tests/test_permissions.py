# -*- coding: utf-8 -*-
"""T7 权限边界测试：会话准入 + 成员准入（两层正交）。

核心约束：白名单 UMO **只覆盖会话维度，永远不能覆盖成员维度**。

全部打桩：不联网、不起浏览器、不碰真实数据目录、不写真实凭据。
"""

import asyncio
import json
import os
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
sys.dont_write_bytecode = True

import boot  # noqa: E402

PLUGIN_DIR_UNDER_TEST = os.environ.get("HW_AUDIT_PLUGIN_DIR") or str(boot.PLUGIN_DIR)
boot.install_paths(PLUGIN_DIR_UNDER_TEST)
main_mod = boot.load_main(plugin_dir=PLUGIN_DIR_UNDER_TEST)

from astrbot.api.event import AstrMessageEvent, filter  # noqa: E402
import hw_webapi  # noqa: E402

TOOL_NAMES = main_mod.TOOL_NAMES
PERMISSION_SECTION = main_mod.PERMISSION_SECTION
SENTINEL = "SENTINEL-HEALTH-DATA-9f1c"

#: 一个格式完全合法的群聊 UMO，用作白名单项。
GROUP_UMO = "aiocqhttp:GroupMessage:123456789"


def make_event(*, admin=True, private=True, umo="", sender="user-1"):
    """构造带权限语义的假事件（与真实 AstrMessageEvent 的方法面一致）。"""
    ev = AstrMessageEvent(message="", sender=sender)
    ev._admin = admin
    ev._private = private
    ev.unified_msg_origin = umo
    return ev


def make_plugin(*, allow_private=True, allow_group=False, admin_only=True, whitelist=None):
    """构造插件实例，权限分组显式注入，并构建白名单。"""
    plugin = boot.make_plugin(
        main_mod,
        plugin_dir=PLUGIN_DIR_UNDER_TEST,
        permission_settings={
            "allow_private": allow_private,
            "allow_group": allow_group,
            "admin_only": admin_only,
            "extra_umo_whitelist": list(whitelist or []),
        },
    )
    plugin._build_umo_whitelist()
    return plugin


def make_plugin_without_section():
    """构造插件实例，配置里**没有** permission_settings（旧配置升级场景）。"""
    plugin = boot.make_plugin(main_mod, plugin_dir=PLUGIN_DIR_UNDER_TEST)
    plugin._build_umo_whitelist()
    return plugin


class _FakeToolSet:
    """假的 ToolSet：只实现插件用到的 remove_tool / 名字列表。"""

    def __init__(self, names):
        self.names = list(names)

    def remove_tool(self, name):
        self.names = [n for n in self.names if n != name]


class _FakeRequest:
    def __init__(self, names=None):
        self.func_tool = None if names is None else _FakeToolSet(names)


class _BoomEvent:
    """所有权限方法都抛异常的事件：验证 fail-closed。"""

    unified_msg_origin = GROUP_UMO

    def is_admin(self):
        raise RuntimeError("boom")

    def is_private_chat(self):
        raise RuntimeError("boom")

    def get_sender_id(self):
        raise RuntimeError("boom")


# ==================== 4.1 行为矩阵（十行逐条） ====================

class TestIsAllowedMatrix(unittest.TestCase):
    """派活单 §4.1 的十行矩阵，一行一个测试。"""

    def test_row01_private_admin_allowed(self):
        plugin = make_plugin(allow_private=True, admin_only=True)
        ev = make_event(admin=True, private=True)
        self.assertTrue(plugin._is_allowed(ev))

    def test_row02_private_non_admin_denied_not_admin(self):
        plugin = make_plugin(allow_private=True, admin_only=True)
        ev = make_event(admin=False, private=True)
        self.assertFalse(plugin._is_allowed(ev))
        self.assertEqual(plugin._deny_reason(ev), "not_admin")

    def test_row03_private_non_admin_allowed_when_admin_only_off(self):
        plugin = make_plugin(allow_private=True, admin_only=False)
        ev = make_event(admin=False, private=True)
        self.assertTrue(plugin._is_allowed(ev))

    def test_row04_group_admin_denied_when_allow_group_off(self):
        plugin = make_plugin(allow_group=False, admin_only=True)
        ev = make_event(admin=True, private=False, umo=GROUP_UMO)
        self.assertFalse(plugin._is_allowed(ev))
        self.assertEqual(plugin._deny_reason(ev), "session_not_allowed")

    def test_row05_group_admin_allowed_when_allow_group_on(self):
        plugin = make_plugin(allow_group=True, admin_only=True)
        ev = make_event(admin=True, private=False, umo=GROUP_UMO)
        self.assertTrue(plugin._is_allowed(ev))

    def test_row06_group_non_admin_denied_not_admin(self):
        plugin = make_plugin(allow_group=True, admin_only=True)
        ev = make_event(admin=False, private=False, umo=GROUP_UMO)
        self.assertFalse(plugin._is_allowed(ev))
        self.assertEqual(plugin._deny_reason(ev), "not_admin")

    def test_row07_group_admin_allowed_by_whitelist(self):
        """白名单可以覆盖 allow_group 开关（会话维度）。"""
        plugin = make_plugin(allow_group=False, admin_only=True, whitelist=[GROUP_UMO])
        ev = make_event(admin=True, private=False, umo=GROUP_UMO)
        self.assertTrue(plugin._is_allowed(ev))

    def test_row08_group_non_admin_denied_even_with_whitelist(self):
        """本单核心：白名单**不许**覆盖成员维度。"""
        plugin = make_plugin(allow_group=False, admin_only=True, whitelist=[GROUP_UMO])
        ev = make_event(admin=False, private=False, umo=GROUP_UMO)
        self.assertFalse(plugin._is_allowed(ev))
        self.assertEqual(plugin._deny_reason(ev), "not_admin")

    def test_row09_group_non_admin_allowed_when_admin_only_off(self):
        plugin = make_plugin(allow_group=False, admin_only=False, whitelist=[GROUP_UMO])
        ev = make_event(admin=False, private=False, umo=GROUP_UMO)
        self.assertTrue(plugin._is_allowed(ev))

    def test_row10_private_admin_denied_when_allow_private_off(self):
        plugin = make_plugin(allow_private=False, admin_only=True)
        ev = make_event(admin=True, private=True)
        self.assertFalse(plugin._is_allowed(ev))
        self.assertEqual(plugin._deny_reason(ev), "session_not_allowed")


class TestMemberDimensionIsHardGate(unittest.TestCase):
    """把「白名单不能覆盖成员维度」单独再钉一遍（防止将来被重构成会话优先）。"""

    def test_whitelisted_group_still_denies_non_admin(self):
        plugin = make_plugin(allow_group=False, admin_only=True, whitelist=[GROUP_UMO])
        self.assertFalse(plugin._is_allowed(make_event(admin=False, private=False, umo=GROUP_UMO)))

    def test_whitelisted_private_still_denies_non_admin(self):
        plugin = make_plugin(admin_only=True, whitelist=["aiocqhttp:FriendMessage:42"])
        self.assertFalse(
            plugin._is_allowed(make_event(admin=False, private=True,
                                          umo="aiocqhttp:FriendMessage:42")))


# ==================== 4.2 第一层：on_llm_request ====================

class TestOnLLMRequestLayer(unittest.TestCase):
    def _gate(self, plugin, event, names=None):
        req = _FakeRequest(list(TOOL_NAMES) if names is None else names)
        asyncio.run(plugin._gate_health_tools(event, req))
        return req

    def test_handler_is_registered_as_on_llm_request(self):
        handler = main_mod.HuaweiHealthPlugin._gate_health_tools
        self.assertTrue(getattr(handler, "__on_llm_request__", False))
        self.assertIn(handler, filter.on_llm_request_handlers)

    def test_denied_request_has_all_eight_tools_removed(self):
        plugin = make_plugin(admin_only=True)
        req = self._gate(plugin, make_event(admin=False, private=True))
        self.assertEqual(req.func_tool.names, [])
        for name in TOOL_NAMES:
            self.assertNotIn(name, req.func_tool.names)

    def test_allowed_request_keeps_all_eight_tools(self):
        plugin = make_plugin(admin_only=True)
        req = self._gate(plugin, make_event(admin=True, private=True))
        self.assertEqual(sorted(req.func_tool.names), sorted(TOOL_NAMES))

    def test_session_denied_also_removes_tools(self):
        plugin = make_plugin(allow_group=False, admin_only=True)
        req = self._gate(plugin, make_event(admin=True, private=False, umo=GROUP_UMO))
        self.assertEqual(req.func_tool.names, [])

    def test_whitelisted_admin_group_keeps_tools(self):
        plugin = make_plugin(allow_group=False, admin_only=True, whitelist=[GROUP_UMO])
        req = self._gate(plugin, make_event(admin=True, private=False, umo=GROUP_UMO))
        self.assertEqual(sorted(req.func_tool.names), sorted(TOOL_NAMES))

    def test_func_tool_none_does_not_crash(self):
        """cron / 后台任务路径下 req.func_tool 可能是 None。"""
        plugin = make_plugin(admin_only=True)
        req = _FakeRequest(None)
        asyncio.run(plugin._gate_health_tools(make_event(admin=False, private=True), req))
        self.assertIsNone(req.func_tool)

    def test_internal_exception_is_treated_as_denied(self):
        plugin = make_plugin(admin_only=True)
        req = self._gate(plugin, _BoomEvent())
        self.assertEqual(req.func_tool.names, [])


# ==================== 4.2 第二层：工具内兜底 ====================

class TestToolGuardLayer(unittest.TestCase):
    """绕过 on_llm_request 直接调用工具（模拟 cron / 后台任务 / MCP）。"""

    def _install_spies(self, plugin):
        touched = []

        async def spy_cached(*args, **kwargs):
            touched.append("cached")
            raise main_mod.HuaweiHealthError(SENTINEL)

        async def spy_token(*args, **kwargs):
            touched.append("token")
            raise main_mod.HuaweiHealthError(SENTINEL)

        async def spy_overview(*args, **kwargs):
            touched.append("overview")
            return [{"title": "总览", "text": SENTINEL}]

        plugin._cached = spy_cached
        plugin._token = spy_token
        plugin._overview_items = spy_overview
        return touched

    def test_all_eight_tools_deny_and_leak_nothing(self):
        plugin = make_plugin(admin_only=True)
        event = make_event(admin=False, private=True)  # not_admin
        touched = self._install_spies(plugin)

        for name in TOOL_NAMES:
            result = asyncio.run(getattr(plugin, name)(event))
            self.assertIn("请勿再次调用", result, "%s 未返回终局拒绝文案" % name)
            self.assertNotIn(SENTINEL, result, "%s 泄漏了健康数据" % name)
        self.assertEqual(touched, [], "拒绝路径不应触达任何取数/认证代码")

    def test_all_eight_tools_deny_on_session_denial(self):
        plugin = make_plugin(allow_group=False, admin_only=True)
        event = make_event(admin=True, private=False, umo=GROUP_UMO)
        touched = self._install_spies(plugin)

        for name in TOOL_NAMES:
            result = asyncio.run(getattr(plugin, name)(event))
            self.assertIn("请勿再次调用", result, name)
            self.assertNotIn(SENTINEL, result, name)
        self.assertEqual(touched, [])

    def test_all_eight_tools_proceed_when_allowed(self):
        plugin = make_plugin(admin_only=True)
        event = make_event(admin=True, private=True)
        self._install_spies(plugin)

        for name in TOOL_NAMES:
            result = asyncio.run(getattr(plugin, name)(event))
            self.assertNotIn("请勿再次调用", result,
                             "%s 被误拒（应已通过权限检查）" % name)

    def test_deny_text_differs_by_reason(self):
        plugin = make_plugin(allow_group=False, admin_only=True)
        not_admin = plugin._deny_text(make_event(admin=False, private=True))
        session = plugin._deny_text(make_event(admin=True, private=False, umo=GROUP_UMO))
        self.assertIn("管理员", not_admin)
        self.assertIn("未获授权", session)
        self.assertNotEqual(not_admin, session)
        # 两种文案都必须是「终局」的
        for text in (not_admin, session):
            self.assertIn("请勿再次调用", text)


# ==================== 4.3 边界与异常 ====================

class TestUmoValidation(unittest.TestCase):
    def test_parse_umos_splits_valid_and_invalid(self):
        plugin = make_plugin()
        valid, invalid = plugin._parse_umos([
            "aiocqhttp:GroupMessage:123",
            "abc",
            "a:b",
            "x:FriendMessage:",
            "x:Bogus:y",
            "   ",
        ])
        self.assertEqual(valid, ["aiocqhttp:GroupMessage:123"])
        self.assertEqual(set(invalid), {"abc", "a:b", "x:FriendMessage:", "x:Bogus:y"})

    def test_session_id_may_contain_colons(self):
        plugin = make_plugin()
        valid, invalid = plugin._parse_umos(["webchat:FriendMessage:abc:def"])
        self.assertEqual(valid, ["webchat:FriendMessage:abc:def"])
        self.assertEqual(invalid, [])

    def test_all_three_message_types_accepted(self):
        plugin = make_plugin()
        items = ["p:FriendMessage:1", "p:GroupMessage:2", "p:OtherMessage:3"]
        valid, invalid = plugin._parse_umos(items)
        self.assertEqual(sorted(valid), sorted(items))
        self.assertEqual(invalid, [])

    def test_invalid_entry_ignored_but_valid_still_works(self):
        plugin = make_plugin(allow_group=False, admin_only=False,
                             whitelist=["bogus-entry", GROUP_UMO])
        self.assertEqual(plugin._invalid_umos, ["bogus-entry"])
        self.assertEqual(plugin._whitelist(), {GROUP_UMO})
        ev = make_event(admin=False, private=False, umo=GROUP_UMO)
        self.assertTrue(plugin._is_allowed(ev))

    def test_invalid_entry_never_grants_access(self):
        plugin = make_plugin(allow_group=False, admin_only=False, whitelist=["bogus-entry"])
        ev = make_event(admin=False, private=False, umo="bogus-entry")
        self.assertFalse(plugin._is_allowed(ev))


class TestEdgeCases(unittest.TestCase):
    def test_empty_umo_falls_back_to_switches(self):
        plugin = make_plugin(allow_group=False, admin_only=False)
        ev = make_event(admin=False, private=False, umo="")
        self.assertFalse(plugin._is_allowed(ev))          # 群聊开关关闭
        ev_private = make_event(admin=False, private=True, umo="")
        self.assertTrue(plugin._is_allowed(ev_private))   # 私聊开关打开

    def test_empty_whitelist_group_still_denied(self):
        plugin = make_plugin(allow_group=False, admin_only=False, whitelist=[])
        ev = make_event(admin=False, private=False, umo=GROUP_UMO)
        self.assertFalse(plugin._is_allowed(ev))

    def test_internal_exception_is_fail_closed(self):
        plugin = make_plugin(admin_only=False)
        self.assertFalse(plugin._is_allowed(_BoomEvent()))

    def test_deny_reason_does_not_raise_on_broken_event(self):
        plugin = make_plugin(admin_only=True)
        self.assertEqual(plugin._deny_reason(_BoomEvent()), "not_admin")

    def test_config_bool_accepts_strings_and_numbers(self):
        plugin = make_plugin()
        plugin.config[PERMISSION_SECTION] = {
            "allow_private": "false",
            "allow_group": 1,
            "admin_only": "yes",
        }
        self.assertFalse(plugin._cfg_bool("allow_private", True))
        self.assertTrue(plugin._cfg_bool("allow_group", False))
        self.assertTrue(plugin._cfg_bool("admin_only", True))
        # 缺失键退回默认
        self.assertTrue(plugin._cfg_bool("nonexistent", True))

    def test_none_event_is_denied_fail_closed(self):
        """None event 必须拒绝（fail-closed）。

        与 AstrBot 自身取向一致：框架的 admin 工具守卫在 ``event is None`` 时
        同样直接判「无权限」（core/provider/func_tool_manager.py）。拿不到事件
        上下文就无法证明调用方有权，一律拒绝。

        注意：验收套件里直接调用工具函数体的用例，请改用
        ``boot.allowed_event()`` 传一个显式放行的事件，而不是 None。
        """
        plugin = make_plugin(admin_only=True, allow_group=False)
        self.assertFalse(plugin._is_allowed(None))

    def test_none_event_deny_text_is_terminal_and_clean(self):
        """None event 的拒绝文案必须是终局，且不夹带任何真实数据。"""
        plugin = make_plugin(admin_only=True, allow_group=False)
        text = plugin._deny_text(None)
        self.assertIn("请勿再次调用", text)
        self.assertNotIn("登录方式", text)
        self.assertNotIn(SENTINEL, text)


class TestConfigCompatibility(unittest.TestCase):
    def test_existing_flat_keys_still_readable(self):
        plugin = make_plugin()
        for key in ("headless", "page_timeout", "token_ttl", "data_ttl", "warmup",
                    "login_daily_limit", "timezone", "client_id", "api_version"):
            self.assertIsNotNone(plugin.config.get(key), key)

    def test_schema_keeps_seventeen_flat_keys_and_adds_one_group(self):
        path = os.path.join(str(PLUGIN_DIR_UNDER_TEST), "_conf_schema.json")
        with open(path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        self.assertIn(PERMISSION_SECTION, schema)
        self.assertEqual(len(schema), 18, "应恰好是原 17 项 + permission_settings")
        for key in ("cookie_json", "cookie_CASTGC", "cookie_sid", "cookie_hwid_cas_sid",
                    "cookie_HuaweiID_CAS_ISCASLOGIN", "cookie_CASLOGINSITE",
                    "cookie_LOGINACCSITE", "browser_path", "headless", "page_timeout",
                    "token_ttl", "data_ttl", "warmup", "login_daily_limit",
                    "timezone", "client_id", "api_version"):
            self.assertIn(key, schema, "原有配置项被删了：%s" % key)
        group = schema[PERMISSION_SECTION]
        self.assertEqual(group["type"], "object")
        self.assertEqual(sorted(group["items"]),
                         ["admin_only", "allow_group", "allow_private", "extra_umo_whitelist"])

    def test_defaults_when_section_absent(self):
        """旧配置升级：没有 permission_settings 时按设计默认值工作。"""
        plugin = make_plugin_without_section()
        self.assertTrue(plugin._cfg_bool("allow_private", True))
        self.assertFalse(plugin._cfg_bool("allow_group", False))
        self.assertTrue(plugin._cfg_bool("admin_only", True))
        self.assertEqual(plugin._whitelist(), set())

    def test_default_policy_denies_non_admin_in_group(self):
        plugin = make_plugin_without_section()
        ev = make_event(admin=False, private=False, umo=GROUP_UMO)
        self.assertFalse(plugin._is_allowed(ev))
        self.assertEqual(plugin._deny_reason(ev), "not_admin")

    def test_default_policy_allows_admin_private(self):
        plugin = make_plugin_without_section()
        self.assertTrue(plugin._is_allowed(make_event(admin=True, private=True)))


class TestStatusPermissionBlock(unittest.TestCase):
    def test_status_reports_permission_snapshot(self):
        plugin = make_plugin(allow_group=False, admin_only=True,
                             whitelist=[GROUP_UMO, "bad-format-entry"])
        api = hw_webapi.HuaweiHealthWebApi(plugin)
        data = asyncio.run(api.get_status())["payload"]["data"]
        self.assertIn("permission", data)
        perm = data["permission"]
        self.assertTrue(perm["allow_private"])
        self.assertFalse(perm["allow_group"])
        self.assertTrue(perm["admin_only"])
        self.assertEqual(perm["extra_umo_count"], 1)
        self.assertEqual(perm["invalid_umos"], ["bad-format-entry"])

    def test_status_keeps_existing_fields(self):
        plugin = make_plugin()
        api = hw_webapi.HuaweiHealthWebApi(plugin)
        data = asyncio.run(api.get_status())["payload"]["data"]
        for key in ("version", "data_dir", "cookie_file", "login_mode", "browser", "config"):
            self.assertIn(key, data)
        # 版本号一旦升级，硬编码字面值会误报；比对 metadata.yaml 声明的值。
        self.assertEqual(data["version"], boot.metadata_version(PLUGIN_DIR_UNDER_TEST))


if __name__ == "__main__":
    unittest.main(verbosity=2)
