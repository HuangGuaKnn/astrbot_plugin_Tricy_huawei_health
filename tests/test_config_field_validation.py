# -*- coding: utf-8 -*-
"""配置字段的内容级校验（``hw_webapi._check_leaf``）。

背景（2026-10-30）：设置页的若干字段是自由文本，``_conf_schema.json`` 只声明
``type`` 没有正则。当天接连发现两处「填错就崩」：

1. ``timezone`` 写成 ``+8:00`` → 每次取数 ``parse_timezone`` 抛 ValueError；
2. ``client_id`` / ``api_version`` 含换行或制表符 → ``requests`` 抛 InvalidHeader。
   ``main.py`` 只做了 ``.strip()``，中间的控制字符挡不住。

这里锁定修复后的行为：能归一化的归一化，归一化不了的当场拒绝，
绝不留到取数阶段才炸。
"""

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

import hw_webapi  # noqa: E402


def make_api():
    main_mod._data_dir = lambda: boot.sandbox_dir("t_cfgfield")
    plugin = boot.make_plugin(main_mod, plugin_dir=PLUGIN_DIR_UNDER_TEST)
    api = hw_webapi.HuaweiHealthWebApi(plugin)
    leaves = hw_webapi._schema_leaves(hw_webapi._load_schema())
    return api, leaves


class HeaderFieldValidationTests(unittest.TestCase):
    """client_id / api_version 会拼进 HTTP header，必须挡住控制字符。"""

    def setUp(self):
        self.api, self.leaves = make_api()

    def _check(self, name, value):
        return self.api._check_leaf(name, value, self.leaves[name])

    def test_control_characters_rejected(self):
        """含换行/回车/制表符会被 requests 判为 InvalidHeader，必须提前拒绝。"""
        for name in ("client_id", "api_version"):
            for bad in ("abc\ndef", "abc\rdef", "abc\tdef", "abc\x00def"):
                with self.subTest(name=name, value=repr(bad)):
                    with self.assertRaises(hw_webapi.ConfigValueError):
                        self._check(name, bad)

    def test_surrounding_whitespace_is_trimmed(self):
        """首尾空白自动去掉，不要等 main.py 的 strip 兜底（中间字符它挡不住）。"""
        for name in ("client_id", "api_version"):
            for raw, expect in (("  abc  ", "abc"), ("\tabc\t", "abc"), ("abc ", "abc")):
                with self.subTest(name=name, value=repr(raw)):
                    value, clamped = self._check(name, raw)
                    self.assertEqual(value, expect)
                    self.assertFalse(clamped)

    def test_blank_becomes_empty_string(self):
        """纯空白归一化成空串，交给 hw_client 的 `or DEFAULT_...` 兜底。"""
        for name in ("client_id", "api_version"):
            with self.subTest(name=name):
                value, _ = self._check(name, "   ")
                self.assertEqual(value, "")

    def test_normal_values_pass_through(self):
        cases = {
            "client_id": "106533743",
            "api_version": "HealthKitRunningGroupPortal_6.26.4.200",
        }
        for name, good in cases.items():
            with self.subTest(name=name):
                value, _ = self._check(name, good)
                self.assertEqual(value, good)

    def test_spaces_in_middle_still_allowed(self):
        """中间空格 requests 是接受的，不要过度收紧误伤用户。"""
        value, _ = self._check("client_id", "abc def")
        self.assertEqual(value, "abc def")


class TimezoneFieldValidationTests(unittest.TestCase):
    """timezone 在保存时归一化，非法值当场拒绝。"""

    def setUp(self):
        self.api, self.leaves = make_api()

    def test_normalized_on_save(self):
        for raw, expect in (("+8:00", "+0800"), ("+8", "+0800"), ("UTC", "+0000"),
                            ("+830", "+0830"), ("-8:00", "-0800")):
            with self.subTest(raw=raw):
                value, _ = self.api._check_leaf("timezone", raw, self.leaves["timezone"])
                self.assertEqual(value, expect)

    def test_invalid_rejected_at_save_not_at_query(self):
        """关键：错值必须在保存这一刻就报错，而不是留到取数时抛 ValueError。"""
        for bad in ("abc", "+2500", "+0870", "8:00", "+"):
            with self.subTest(bad=bad):
                with self.assertRaises(hw_webapi.ConfigValueError):
                    self.api._check_leaf("timezone", bad, self.leaves["timezone"])

    def test_blank_falls_back_to_default(self):
        value, _ = self.api._check_leaf("timezone", "   ", self.leaves["timezone"])
        self.assertEqual(value, "+0800")


if __name__ == "__main__":
    unittest.main()
