# -*- coding: utf-8 -*-
"""心率区间阈值阶梯守卫（Issue #2）。

背景：华为 ``/sampleConfigs`` 返回的字段名与语义顺序不一致——
``mAnaerobicThreshold``(166) 低于 ``mAnaerobicBaseThreshold``(170)，
所以前者是「无氧基础」、后者是「无氧耐力」。本文件把这条事实固化下来，
防止将来字段名漂移后再次装反而无人发现。

全部打桩：不联网、不碰真实数据目录。
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
boot.install_paths(PLUGIN_DIR_UNDER_TEST)
main_mod = boot.load_main(plugin_dir=PLUGIN_DIR_UNDER_TEST)
import hw_client  # noqa: E402

#: 华为 /sampleConfigs 的真实响应值（2026-10-29 抓取，Issue #2）。
RAW_HR = {
    "mWarmUpThreshold": 110,
    "mFatBurnThreshold": 129,
    "mAerobicBaseThreshold": 135,
    "mAerobicThreshold": 147,
    "mAerobicAdvanceThreshold": 153,
    "mLacticAcidThreshold": 165,
    # 注意这两个：字段名与语义顺序相反
    "mAnaerobicThreshold": 166,
    "mAnaerobicBaseThreshold": 170,
    "mAnaerobicAdvanceThreshold": 178,
    "mRestHeartRate": 65,
    "mMaxThreshold": 184,
}

#: 九档按语义从低到高。
TIER_ORDER = (
    "warm_up",
    "fat_burn",
    "aerobic_base",
    "aerobic",
    "aerobic_advance",
    "lactic_acid",
    "anaerobic_base",
    "anaerobic",
    "anaerobic_advance",
)


class _FakeClient(hw_client.HuaweiHealthClient):
    """只实现 heart_rate_zones 需要的那一个方法。"""

    def __init__(self):  # noqa: D107 - 故意不调父类，避免需要 token
        pass

    def _get(self, path, params=None, **kwargs):  # noqa: D102
        return {"sampleConfigs": [{"configData": {"mOtherHeartRateData": dict(RAW_HR)}}]}


class TestHeartRateZoneOrder(unittest.TestCase):
    """九档阈值必须严格单调递增。"""

    def setUp(self):
        self.client = _FakeClient()

    def test_nine_tiers_are_strictly_increasing(self):
        """核心守卫：阶梯必须单调递增且不重复。"""
        zones = self.client.heart_rate_zones()
        values = [zones[k] for k in TIER_ORDER]
        self.assertEqual(values, sorted(values), "阈值阶梯必须单调递增：%s" % values)
        self.assertEqual(len(set(values)), len(values), "阈值不应出现重复：%s" % values)
        self.assertEqual(len(values), 9, "九档应全部解析出来：%s" % values)

    def test_anaerobic_base_is_lower_than_anaerobic(self):
        """华为 mAnaerobicThreshold(166) < mAnaerobicBaseThreshold(170)，标签不能装反。"""
        zones = self.client.heart_rate_zones()
        self.assertEqual(zones["anaerobic_base"], 166)
        self.assertEqual(zones["anaerobic"], 170)
        self.assertLess(zones["anaerobic_base"], zones["anaerobic"])

    def test_lactic_acid_below_anaerobic_base(self):
        """乳酸阈值应低于无氧基础。"""
        zones = self.client.heart_rate_zones()
        self.assertLess(zones["lactic_acid"], zones["anaerobic_base"])

    def test_rest_and_max_bracket_the_ladder(self):
        """静息应低于最低档，最大心率应高于最高档。"""
        zones = self.client.heart_rate_zones()
        self.assertEqual(zones["rest"], 65)
        self.assertEqual(zones["max"], 184)
        self.assertLess(zones["rest"], zones["warm_up"])
        self.assertGreater(zones["max"], zones["anaerobic_advance"])

    def test_display_order_is_monotonic(self):
        """渲染出来的行必须单调**递减**（从无氧进阶到热身），防止展示层排错。"""
        zones = self.client.heart_rate_zones()
        text = main_mod.HuaweiHealthPlugin._fmt_zones(zones)
        nums = [int(x) for x in re.findall(r"≥ (\d+) bpm", text)]
        self.assertEqual(len(nums), 9, "渲染应输出九档：%r" % text)
        self.assertEqual(nums, sorted(nums, reverse=True),
                         "渲染顺序必须从高到低单调递减：%s" % nums)
        # 逐档核对：第一行是无氧进阶，最后一行是热身
        self.assertEqual(nums[0], 178)
        self.assertEqual(nums[-1], 110)

    def test_missing_fields_do_not_crash(self):
        """只回部分字段时不应抛异常，且仍保持相对顺序。"""

        class _Partial(_FakeClient):
            def _get(self, path, params=None, **kwargs):
                return {"sampleConfigs": [{"configData": {"mOtherHeartRateData": {
                    "mWarmUpThreshold": 110,
                    "mAnaerobicThreshold": 166,
                    "mAnaerobicBaseThreshold": 170,
                }}}]}

        zones = _Partial().heart_rate_zones()
        self.assertEqual(zones["warm_up"], 110)
        self.assertLess(zones["anaerobic_base"], zones["anaerobic"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
