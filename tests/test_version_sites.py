# -*- coding: utf-8 -*-
"""版本号「多处硬编码」的一致性守卫。

版本号在 5 个地方各写了一份（历史原因，见 CHANGELOG 的 T0 记录）：

| 位置 | 形态 |
|---|---|
| ``metadata.yaml`` | ``version: v0.5.0-rc.2`` —— 约定为唯一真值 |
| ``main.py`` | 插件注册时用的版本字符串 |
| ``hw_webapi.py`` | ``/status`` 回给页面的 ``"version"`` |
| ``README.md`` | 顶部「版本：」 |
| ``CHANGELOG_v0.5.0.md`` | 顶部「当前版本：」 |

``test_v041.py`` 的 ``TestVersionConsistency`` 已经守着前三处。这里补上后两处
文档位置——它们恰恰是转正时最容易漏的（代码改完忘了改文档），
而漏了不会让任何测试变红，只会在发布页面上留下一个错的版本号。
"""

import os
import re
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
sys.dont_write_bytecode = True

import boot  # noqa: E402

PLUGIN_DIR_UNDER_TEST = os.environ.get("HW_AUDIT_PLUGIN_DIR") or str(boot.PLUGIN_DIR)


def _metadata_version(root):
    """metadata.yaml 里的 version 字段，作为唯一真值来源。"""
    with open(os.path.join(root, "metadata.yaml"), encoding="utf-8") as handle:
        matched = re.search(r"^version:\s*(\S+)\s*$", handle.read(), re.M | re.U)
    if not matched:
        raise AssertionError("metadata.yaml 缺少 version 字段")
    return matched.group(1)


class VersionSiteTests(unittest.TestCase):
    def setUp(self):
        self.root = PLUGIN_DIR_UNDER_TEST
        self.version = _metadata_version(self.root)

    def _read(self, name):
        with open(os.path.join(self.root, name), encoding="utf-8") as handle:
            return handle.read()

    def test_code_sites_match_metadata(self):
        """main.py / hw_webapi.py 里必须出现 metadata 声明的版本字符串。"""
        for name in ("main.py", "hw_webapi.py"):
            with self.subTest(file=name):
                self.assertIn('"%s"' % self.version, self._read(name),
                              "%s 里的版本号与 metadata.yaml 不一致" % name)

    def test_readme_declares_metadata_version(self):
        """README 顶部的「版本：」不能落后于 metadata。"""
        text = self._read("README.md")
        self.assertIn(self.version, text,
                      "README.md 里找不到当前版本号 %s" % self.version)

    def test_changelog_declares_metadata_version(self):
        """CHANGELOG 顶部的「当前版本：」不能落后于 metadata。"""
        text = self._read("CHANGELOG_v0.5.0.md")
        matched = re.search(r"当前版本：\*\*(\S+?)\*\*", text)
        self.assertIsNotNone(matched, "CHANGELOG 顶部缺少「当前版本：**x**」")
        self.assertEqual(matched.group(1), self.version,
                         "CHANGELOG 的当前版本与 metadata.yaml 不一致")

    def test_version_shape_is_consistent(self):
        """版本号要么带 -rc.N（预览），要么是纯 x.y.z（正式）；不混用。"""
        self.assertRegex(self.version, r"^v\d+\.\d+\.\d+(?:-rc\.\d+)?$")


if __name__ == "__main__":
    unittest.main()
