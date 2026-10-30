# -*- coding: utf-8 -*-
"""时区解析与归一化守卫。

背景（2026-10-30）：设置页的 ``timezone`` 是自由文本输入，``_conf_schema.json``
里没有正则校验。原 ``parse_timezone`` 只认 ``+HH:MM`` / ``+HHMM``，用户填 ``+8:00``
会在每次取数时抛 ``ValueError``，把整个工具调用打崩。

现在改为「宽进窄出」：接受常见写法，偏移范围仍严格校验，并在保存时归一化成
``±HHMM`` 写回配置，这样运行期不会再遇到没见过的写法。
"""

import unittest

import boot

boot.install_paths()
from hw_client import format_timezone, parse_timezone


class ParseTimezoneTests(unittest.TestCase):
    def test_accepts_common_spellings(self):
        """用户会怎么写就都得认——这些写法在真实配置页都见过。"""
        for text in ("+0800", "+08:00", "+8:00", "+8", "+830", "-1200", "-8:00"):
            with self.subTest(text=text):
                self.assertIsNotNone(parse_timezone(text))

    def test_utc_aliases(self):
        for text in ("UTC", "utc", "Z", "z", "  UTC  "):
            with self.subTest(text=text):
                self.assertEqual(parse_timezone(text).utcoffset(None).total_seconds(), 0)

    def test_empty_falls_back_to_default(self):
        """配置缺省或留空时按默认 +0800 处理，不能抛异常。"""
        for text in ("", None, "   "):
            with self.subTest(text=repr(text)):
                self.assertEqual(parse_timezone(text).utcoffset(None).total_seconds(), 8 * 3600)

    def test_rejects_invalid(self):
        """放宽解析不等于放弃校验：越界与垃圾值仍然必须拒绝。"""
        for text in ("abc", "+2500", "+0870", "++08", "+", "8:00", "+08:000"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    parse_timezone(text)

    def test_offset_values_are_correct(self):
        self.assertEqual(parse_timezone("+8").utcoffset(None).total_seconds(), 8 * 3600)
        self.assertEqual(parse_timezone("+830").utcoffset(None).total_seconds(), 8.5 * 3600)
        self.assertEqual(parse_timezone("-1200").utcoffset(None).total_seconds(), -12 * 3600)
        self.assertEqual(parse_timezone("+08:00").utcoffset(None).total_seconds(), 8 * 3600)

    def test_normalizes_to_hhmm(self):
        """归一化后的字符串必须是稳定形式，否则每次保存都会改写配置。"""
        cases = {
            "+8:00": "+0800",
            "+8": "+0800",
            "+0800": "+0800",
            "+08:00": "+0800",
            "+830": "+0830",
            "UTC": "+0000",
            "Z": "+0000",
            "-1200": "-1200",
            "-8:00": "-0800",
            "": "+0800",
        }
        for text, expect in cases.items():
            with self.subTest(text=text):
                self.assertEqual(format_timezone(text), expect)

    def test_normalization_is_idempotent(self):
        """归一化结果再归一化一次必须不变，否则保存会被反复改写。"""
        for text in ("+8:00", "+830", "UTC", "-8", "+0800"):
            with self.subTest(text=text):
                once = format_timezone(text)
                self.assertEqual(format_timezone(once), once)

    def test_format_propagates_invalid(self):
        with self.assertRaises(ValueError):
            format_timezone("abc")


if __name__ == "__main__":
    unittest.main()
