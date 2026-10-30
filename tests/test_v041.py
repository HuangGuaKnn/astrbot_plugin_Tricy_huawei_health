# -*- coding: utf-8 -*-
"""v0.4.1 验收测试：每条修复一个回归断言，外加「不要改坏」的守卫。

跑法（在仓库根目录下）：
    python -B -X utf8 -m unittest discover -s tests -v
    python -B -X utf8 -m pytest tests -q

全部使用打桩：不起浏览器、不联网、不碰真实数据目录。
"""

import asyncio
import datetime
import json
import os
import sys
import tempfile
import threading
import time
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
sys.dont_write_bytecode = True

import boot  # noqa: E402

#: 默认测仓库根目录下的插件源码；设 HW_AUDIT_PLUGIN_DIR 就能改测
#: 任意副本（例如从 dist/*.zip 解压出来的那份），用于验证发布物本身。
PLUGIN_DIR_UNDER_TEST = os.environ.get("HW_AUDIT_PLUGIN_DIR") or str(boot.PLUGIN_DIR)
boot.install_paths(PLUGIN_DIR_UNDER_TEST)
main_mod = boot.load_main(plugin_dir=PLUGIN_DIR_UNDER_TEST)

import hw_auth  # noqa: E402
import hw_client  # noqa: E402
import hw_credentials  # noqa: E402
import hw_login  # noqa: E402
import hw_store  # noqa: E402
import hw_webapi  # noqa: E402


def _metadata_version(root):
    """从 metadata.yaml 读取版本号，作为唯一真值来源。"""
    import re
    with open(os.path.join(root, "metadata.yaml"), encoding="utf-8") as f:
        m = re.search(r"^version:\s*(\S+)\s*$", f.read(), re.M)
    if not m:
        raise AssertionError("metadata.yaml 缺少 version 字段")
    return m.group(1)


SIX = {
    "CASTGC": "castgc-value",
    "sid": "sid-value",
    "hwid_cas_sid": "hwid-value",
    "HuaweiID_CAS_ISCASLOGIN": "true",
    "CASLOGINSITE": "1",
    "LOGINACCSITE": "1",
}


def make_auth(**kwargs):
    d = boot.sandbox_dir("t_auth")
    return hw_auth.HuaweiAuth(
        cookie_file=os.path.join(d, "hw_cookies.json"),
        profile_dir=os.path.join(d, "profile"),
        logger=_Logger(),
        **kwargs
    )


class _Logger:
    def __init__(self):
        self.records = []

    def _add(self, level, msg):
        self.records.append((level, msg))

    def debug(self, msg, *a, **k):
        self._add("debug", msg)

    def info(self, msg, *a, **k):
        self._add("info", msg)

    def warning(self, msg, *a, **k):
        self._add("warning", msg)

    def error(self, msg, *a, **k):
        self._add("error", msg)


# ============================ hw_auth ============================

class TestCookieParsing(unittest.TestCase):
    """P1-9：模糊输入必须报错，不能静默错位/丢弃。"""

    def test_six_ordered_values_ok(self):
        got = hw_auth.parse_cookie_fields("\n".join("v%d" % i for i in range(1, 7)))
        self.assertEqual(got["CASTGC"], "v1")
        self.assertEqual(got["LOGINACCSITE"], "v6")

    def test_five_ordered_values_rejected(self):
        with self.assertRaises(hw_auth.HuaweiAuthError):
            hw_auth.parse_cookie_fields("\n".join("v%d" % i for i in range(1, 6)))

    def test_seven_ordered_values_rejected(self):
        with self.assertRaises(hw_auth.HuaweiAuthError):
            hw_auth.parse_cookie_fields("\n".join("v%d" % i for i in range(1, 8)))

    def test_mixed_named_and_ordered_rejected(self):
        with self.assertRaises(hw_auth.HuaweiAuthError):
            hw_auth.parse_cookie_fields("CASTGC=a\nsid=b\nc\nd")

    def test_named_only_ok(self):
        got = hw_auth.parse_cookie_fields("CASTGC=a\nsid=b")
        self.assertEqual(got, {"CASTGC": "a", "sid": "b"})

    def test_base64_padding_kept(self):
        got = hw_auth.parse_cookie_fields("CASTGC=YWJjZA==\nsid=YWJjZGU=")
        self.assertEqual(got["CASTGC"], "YWJjZA==")

    def test_fullwidth_colon(self):
        got = hw_auth.parse_cookie_fields("CASTGC：abc\nsid：def")
        self.assertEqual(got, {"CASTGC": "abc", "sid": "def"})

    def test_lowercase_keys(self):
        got = hw_auth.parse_cookie_fields("castgc=abc\nSID=def")
        self.assertEqual(got, {"castgc": "abc", "SID": "def"})
        # 归一化后仍能映射到规范名
        cookies = hw_auth.cookies_from_fields(got)
        self.assertEqual({c["name"] for c in cookies}, {"CASTGC", "sid"})


class TestCookieImport(unittest.TestCase):
    """P1-1 / P1-9 / P2-15：合并、补齐、校验、配置指纹。"""

    def test_castgc_two_paths(self):
        cookies = hw_auth.cookies_from_fields({"CASTGC": "x"})
        self.assertEqual(sorted(c["path"] for c in cookies), ["/CAS", "/UnifiedIDMPortal"])

    def test_import_requires_castgc_and_sid(self):
        a = make_auth()
        with self.assertRaises(hw_auth.HuaweiAuthError):
            a.import_cookie_sources("", {"CASTGC": "x"})

    def test_import_merges_and_keeps_extra_cookies(self):
        a = make_auth()
        a.import_cookie_sources("", SIX)
        rolled = a.load_cookies() + [{
            "name": "__uni__uid", "value": "ROLLED",
            "domain": ".huawei.com", "path": "/",
        }]
        a.save_cookies(rolled)
        self.assertTrue(any(c["name"] == "__uni__uid" for c in a.load_cookies()))
        # 再导入一次（模拟用户只补一条），额外 cookie 不能丢
        a.import_cookie_sources("", {"CASTGC": "new-castgc"})
        names = {c["name"] for c in a.load_cookies()}
        self.assertIn("__uni__uid", names)
        self.assertIn("sid", names)
        self.assertEqual([c["value"] for c in a.load_cookies() if c["name"] == "CASTGC"],
                         ["new-castgc", "new-castgc"])

    def test_json_channel_gets_second_castgc_path(self):
        """P2-15：JSON 通道也要补 /UnifiedIDMPortal。"""
        a = make_auth()
        payload = json.dumps([
            {"name": "CASTGC", "value": "t", "domain": ".id1.cloud.huawei.com", "path": "/CAS"},
            {"name": "sid", "value": "s", "domain": ".id1.cloud.huawei.com", "path": "/"},
        ])
        a.import_cookie_sources(payload, {})
        paths = sorted(c["path"] for c in a.load_cookies() if c["name"] == "CASTGC")
        self.assertEqual(paths, ["/CAS", "/UnifiedIDMPortal"])

    def test_config_fingerprint_skips_unchanged(self):
        """P1-1：配置没变时不能覆盖滚续结果。"""
        a = make_auth()
        self.assertEqual(a.import_cookie_sources("", SIX, only_if_changed=True), 7)
        a.save_cookies(a.load_cookies() + [{
            "name": "__uni__uid", "value": "ROLLED", "domain": ".huawei.com", "path": "/"}])
        self.assertEqual(a.import_cookie_sources("", SIX, only_if_changed=True), 0)
        self.assertTrue(any(c["name"] == "__uni__uid" for c in a.load_cookies()))

    def test_config_fingerprint_applies_when_changed(self):
        a = make_auth()
        a.import_cookie_sources("", SIX, only_if_changed=True)
        changed = dict(SIX, CASTGC="user-edited")
        self.assertEqual(a.import_cookie_sources("", changed, only_if_changed=True), 7)
        self.assertEqual([c["value"] for c in a.load_cookies() if c["name"] == "CASTGC"],
                         ["user-edited", "user-edited"])

    def test_cookie_file_is_encrypted(self):
        """P1-12：Windows 上磁盘不得出现明文 cookie；其它平台按设计降级为 0600 明文。

        DPAPI 是 Windows API，Linux/macOS 上 ``_serialize_cookies`` 会退回明文
        （见 hw_auth 的分支），因此这里断言的是「当前平台的正确行为」：
        Windows 必须加密且无明文值，其它平台必须明文 + 0600（不可被其他用户读取）。
        """
        a = make_auth()
        a.import_cookie_sources("", SIX)
        with open(a.cookie_file, "rb") as f:
            raw = f.read()
        if sys.platform == "win32":
            self.assertTrue(raw.startswith(hw_auth.COOKIE_MAGIC))
            self.assertNotIn(b"castgc-value", raw)
        else:
            self.assertFalse(raw.startswith(hw_auth.COOKIE_MAGIC))
            mode = os.stat(a.cookie_file).st_mode & 0o777
            self.assertEqual(mode, 0o600, "非 Windows 平台必须收紧到 0600")
        self.assertEqual(len(a.load_cookies()), 7)

    def test_plaintext_legacy_file_still_readable(self):
        a = make_auth()
        with open(a.cookie_file, "w", encoding="utf-8") as f:
            json.dump([{"name": "sid", "value": "legacy", "domain": ".huawei.com", "path": "/"}], f)
        self.assertEqual(a.load_cookies()[0]["value"], "legacy")

    def test_import_clears_failure_cooldown(self):
        """P2-9：导入 cookie 后不该还被 180 秒冷却拦住。"""
        a = make_auth()
        a._mark_failure()
        a.import_cookie_sources("", SIX)
        with a._failure_lock:
            self.assertEqual(a._failure_state_item["last"], 0.0)

    def test_purge_stale_tmp(self):
        a = make_auth()
        a.import_cookie_sources("", SIX)
        stale = a.cookie_file + ".tmp.999.888"
        with open(stale, "w", encoding="utf-8") as f:
            f.write("{}")
        self.assertGreaterEqual(a.purge_stale_tmp(), 1)
        self.assertFalse(os.path.exists(stale))

    def test_bad_json_message_is_friendly(self):
        """P3-6：不要把 json 解析器原文回显给前端。"""
        a = make_auth()
        with self.assertRaises(hw_auth.HuaweiAuthError) as ctx:
            a.import_cookie_sources("[{bad json", {})
        self.assertNotIn("Expecting", str(ctx.exception))
        self.assertIn("格式错误", str(ctx.exception))


class TestExpireAt(unittest.TestCase):
    """P2-5：expireTime 三态统一。"""

    NOW = 1_800_000_000.0

    def test_missing_falls_back(self):
        self.assertAlmostEqual(
            hw_auth.compute_expire_at(0, 3000, self.NOW) - self.NOW, 3000, places=0)

    def test_short_remaining_does_not_go_to_past(self):
        got = hw_auth.compute_expire_at(self.NOW + 10, 3000, self.NOW)
        self.assertGreater(got, self.NOW)

    def test_already_expired_does_not_cache_full_ttl(self):
        got = hw_auth.compute_expire_at(self.NOW - 100, 3000, self.NOW)
        self.assertAlmostEqual(got - self.NOW, 3000, places=0)

    def test_normal_uses_min(self):
        self.assertAlmostEqual(
            hw_auth.compute_expire_at(self.NOW + 1800, 3000, self.NOW) - self.NOW, 1770, places=0)
        self.assertAlmostEqual(
            hw_auth.compute_expire_at(self.NOW + 4000, 3000, self.NOW) - self.NOW, 3000, places=0)

    def test_nan_and_garbage(self):
        for bad in (float("nan"), "abc", None):
            self.assertGreater(hw_auth.compute_expire_at(bad, 3000, self.NOW), self.NOW)


# ============================ hw_credentials ============================

class TestMaskAccount(unittest.TestCase):
    """P2-12：掩码不能泄露全部字符。"""

    @staticmethod
    def revealed(masked):
        return sum(1 for ch in masked if ch != "*")

    def test_never_reveals_everything(self):
        for n in range(1, 16):
            value = "".join(str(i % 10) for i in range(n))
            masked = hw_credentials.mask_account(value)
            self.assertLess(self.revealed(masked), n, "len=%d -> %r" % (n, masked))

    def test_seven_digit_is_fully_masked(self):
        self.assertEqual(hw_credentials.mask_account("1234567"), "*******")

    def test_phone_keeps_two_plus_two(self):
        self.assertEqual(hw_credentials.mask_account("13800138000"), "13****00")

    def test_email_hides_local_and_domain_body(self):
        masked = hw_credentials.mask_account("zhangsan@example.com")
        self.assertNotIn("zhangsan", masked)
        self.assertNotIn("example", masked)

    def test_empty(self):
        self.assertEqual(hw_credentials.mask_account(""), "")


class TestCredentialsStatus(unittest.TestCase):
    """P1-10：区分「没保存 / 损坏 / 被占用」。"""

    def setUp(self):
        self.store = hw_credentials.HuaweiCredentialsStore(boot.sandbox_dir("t_cred"))

    def test_absent(self):
        self.assertEqual(self.store.status()["state"], "absent")

    @unittest.skipIf(sys.platform != "win32", "Windows DPAPI only")
    def test_ok_after_save(self):
        self.store.save("13800138000", "pw")
        st = self.store.status()
        self.assertEqual(st["state"], "ok")
        self.assertTrue(st["password_set"])
        self.assertNotIn("13800138000", json.dumps(st, ensure_ascii=False))

    @unittest.skipIf(sys.platform != "win32", "Windows DPAPI only")
    def test_corrupt_is_not_reported_as_absent(self):
        with open(self.store.path, "wb") as f:
            f.write(b"HWCRED1\x00garbage")
        st = self.store.status()
        self.assertEqual(st["state"], "corrupt")
        self.assertFalse(st["password_set"])

    def test_truncated_file(self):
        with open(self.store.path, "wb") as f:
            f.write(b"HW")
        with self.assertRaises(hw_credentials.CredentialsCorruptError):
            self.store.load()

    @unittest.skipIf(sys.platform != "win32", "Windows DPAPI only")
    def test_no_plaintext_on_disk(self):
        self.store.save("acct-sentinel", "pw-sentinel")
        with open(self.store.path, "rb") as f:
            raw = f.read()
        self.assertNotIn(b"acct-sentinel", raw)
        self.assertNotIn(b"pw-sentinel", raw)


# ============================ hw_store ============================

class TestStore(unittest.TestCase):
    def setUp(self):
        self.store = hw_store.HealthStore(os.path.join(boot.sandbox_dir("t_store"), "health.db"))

    def test_clear_except_keeps_token(self):
        self.store.set("token", {"t": 1})
        self.store.set("a", 1, ttl=60)
        self.store.set("b", 2, ttl=60)
        self.store.clear_except("token")
        self.assertEqual(self.store.get("token"), {"t": 1})
        self.assertIsNone(self.store.get("a"))
        self.assertEqual(self.store.keys(), ["token"])

    def test_has_distinguishes_cached_none(self):
        self.assertFalse(self.store.has("k"))
        self.store.set("k", None, ttl=60)
        self.assertIsNone(self.store.get("k"))
        self.assertTrue(self.store.has("k"))

    def test_ttl_zero_never_expires(self):
        self.store.set("perm", {"x": 1}, ttl=0)
        self.assertEqual(self.store.get("perm"), {"x": 1})

    def test_expired_get_removes_row(self):
        self.store.set("e", 1, ttl=1)
        time.sleep(1.1)
        self.assertIsNone(self.store.get("e"))
        self.assertFalse(self.store.has("e"))


# ============================ hw_client ============================

class TestParseStats(unittest.TestCase):
    """P2-3 / P2-4：改版要报 SchemaDrift，不能静默变成「没数据」。"""

    def test_normal(self):
        got = hw_client._parse_stats({
            "results": [{"fieldName": "restBpm", "statistics": {"avg": 60}}],
            "groupResults": [{"groupStatistics": [
                {"startDay": 20261020, "fieldName": "restBpm", "statistics": {"avg": 61}}]}],
        })
        self.assertEqual(got["overall"]["restBpm"]["avg"], 60)
        self.assertEqual(got["daily"][0]["day"], "2026-10-20")

    def test_stat_keys_lowercased(self):
        got = hw_client._parse_stats({"results": [{"fieldName": "x", "statistics": {"AVG": 1}}]})
        self.assertEqual(got["overall"]["x"]["avg"], 1)

    def test_non_dict_raises_schema_drift(self):
        for bad in (None, [], "{}"):
            with self.assertRaises(hw_client.SchemaDrift):
                hw_client._parse_stats(bad)

    def test_results_element_not_dict(self):
        with self.assertRaises(hw_client.SchemaDrift):
            hw_client._parse_stats({"results": ["oops"]})

    def test_missing_keys_on_non_empty_response(self):
        with self.assertRaises(hw_client.SchemaDrift):
            hw_client._parse_stats({"totally": "different"})

    def test_empty_response_is_legit_empty(self):
        self.assertEqual(hw_client._parse_stats({}), {"overall": {}, "daily": []})

    def test_missing_startday_does_not_create_none_bucket(self):
        got = hw_client._parse_stats({"groupResults": [{"groupStatistics": [
            {"fieldName": "restBpm", "statistics": {"avg": 58}},
            {"startDay": 20261020, "fieldName": "restBpm", "statistics": {"avg": 61}}]}]})
        self.assertEqual(len(got["daily"]), 1)
        self.assertEqual(got["daily"][0]["day"], "2026-10-20")

    def test_missing_startday_everywhere_is_drift(self):
        with self.assertRaises(hw_client.SchemaDrift):
            hw_client._parse_stats({"groupResults": [{"groupStatistics": [
                {"fieldName": "restBpm", "statistics": {"avg": 58}}]}]})


class TestFmtDay(unittest.TestCase):
    def test_none_is_empty_not_string_none(self):
        self.assertEqual(hw_client._fmt_day(None), "")

    def test_eight_digits(self):
        self.assertEqual(hw_client._fmt_day(20261020), "2026-10-20")


class TestDayWindow(unittest.TestCase):
    def test_cap_is_1095(self):
        s1, e1 = hw_client._day_window(1095)
        s2, e2 = hw_client._day_window(5000)
        self.assertEqual((s1, e1), (s2, e2))

    def test_min_one(self):
        s, e = hw_client._day_window(0)
        self.assertEqual(s, e)


class TestUnits(unittest.TestCase):
    def test_distance(self):
        self.assertEqual(hw_client.format_distance_m(5000), "5.00 公里")
        self.assertEqual(hw_client.format_distance_m(500), "500 米")

    def test_duration_ms(self):
        self.assertEqual(hw_client.format_duration_ms(1800000), "30 分 00 秒")
        self.assertEqual(hw_client.format_duration_ms(3600000), "1 小时 00 分")

    def test_duration_s(self):
        self.assertEqual(hw_client.format_duration_s(1800), "30:00")


class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.headers = {}
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class TestClientParsing(unittest.TestCase):
    def _client(self, payload):
        c = hw_client.HuaweiHealthClient("tok")
        c.session = _Session(payload)
        return c

    def test_sleep_records_missing_field_is_drift(self):
        with self.assertRaises(hw_client.SchemaDrift):
            self._client({"weird": 1}).sleep_records(7)

    def test_sleep_records_empty_dict_is_empty(self):
        self.assertEqual(self._client({}).sleep_records(7), [])

    def test_sleep_records_dict_not_list(self):
        with self.assertRaises(hw_client.SchemaDrift):
            self._client({"healthRecords": {"a": 1}}).sleep_records(7)

    def test_activities_empty_total_is_empty(self):
        self.assertEqual(self._client({"total": 0}).activities(30, 5), [])

    def test_activities_renamed_is_drift(self):
        with self.assertRaises(hw_client.SchemaDrift):
            self._client({"activityList": []}).activities(30, 5)

    def test_zones_all_none_is_drift(self):
        with self.assertRaises(hw_client.SchemaDrift):
            self._client({"sampleConfigs": [{"configData": json.dumps(
                {"mOtherHeartRateData": {"renamedA": 1, "renamedB": 2}})}]}).heart_rate_zones()

    def test_zones_configdata_as_dict(self):
        got = self._client({"sampleConfigs": [{"configData": {
            "mOtherHeartRateData": {"mRestHeartRate": 55, "mMaxThreshold": 190}}}]}).heart_rate_zones()
        self.assertEqual(got["rest"], 55)
        self.assertEqual(got["max"], 190)


class _Session:
    def __init__(self, payload):
        self.payload = payload

    def get(self, *a, **k):
        return _FakeResponse(self.payload)

    def post(self, *a, **k):
        return _FakeResponse(self.payload)


class TestLegitEmptyResponses(unittest.TestCase):
    """P2-3 的反面：合法的「没有数据」不能被误报成改版。"""

    def _client(self, payload):
        c = hw_client.HuaweiHealthClient("tok")
        c.session = _Session(payload)
        return c

    def test_parse_stats_empty_variants(self):
        for payload in ({}, {"results": []}, {"groupResults": []},
                        {"results": [], "groupResults": []}):
            self.assertEqual(hw_client._parse_stats(payload),
                             {"overall": {}, "daily": []}, payload)

    def test_sleep_empty_variants(self):
        for payload in ({}, {"healthRecords": []}, {"total": 0}, {"totalCount": 0}):
            self.assertEqual(self._client(payload).sleep_records(7), [], payload)

    def test_activities_empty_variants(self):
        for payload in ({}, {"activityRecords": []}, {"records": []}, {"list": []},
                        {"total": 0}, {"count": 0}):
            self.assertEqual(self._client(payload).activities(30, 5), [], payload)

    def test_zones_empty_variants(self):
        for payload in ({}, {"sampleConfigs": []},
                        {"sampleConfigs": [{"configData": None}]},
                        {"sampleConfigs": [{"configData": ""}]}):
            self.assertEqual(self._client(payload).heart_rate_zones(), {}, payload)

    def test_real_drift_still_raises(self):
        with self.assertRaises(hw_client.SchemaDrift):
            self._client({"sleepRecords": []}).sleep_records(7)
        with self.assertRaises(hw_client.SchemaDrift):
            self._client({"activityList": []}).activities(30, 5)
        with self.assertRaises(hw_client.SchemaDrift):
            self._client({"sampleConfigs": [{"configData": json.dumps(
                {"mOtherHeartRateData": {"renamed": 1}})}]}).heart_rate_zones()


# ============================ hw_login 状态机 ============================

class _Clock:
    """假时钟：替换 hw_login.time，但保留 strftime/localtime 等真实函数。"""

    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def time(self):
        return self.t

    def monotonic(self):
        return self.t

    def advance(self, dt):
        self.t += dt

    def __getattr__(self, name):
        return getattr(time, name)


class _FakeAuth:
    page_timeout = 90
    token_expire_at = 0.0

    def __init__(self, page_state=None, sms_result="submitted"):
        self.page_state = page_state if page_state is not None else {
            "sms": False, "trust": False, "sms_error": False, "pwd_error": False}
        self.sms_result = sms_result
        self.access_token = None
        self.calls = []

    def _js(self, ws, expr):
        self.calls.append(expr)
        if "sessionStorage.getItem('accessToken')" in expr:
            return self.access_token
        if "sessionStorage.getItem('expireTime')" in expr:
            return None
        if "const code=" in expr:
            return self.sms_result
        return json.dumps(self.page_state)

    def _call(self, ws, method, params=None, timeout=None):
        if method == "Network.getAllCookies":
            return {"result": {"cookies": [{"name": "sid", "value": "v", "domain": ".huawei.com"}]}}
        return {"result": {}}

    def save_cookies(self, cookies, expected=None):
        return True

    def _stop_process(self, proc, sweep_profile=True):
        pass

    def _cleanup_orphan_browsers(self):
        pass

    def _attach(self, port):
        return object()


class _FakeStore:
    def __init__(self):
        self.d = {}

    def get(self, k, default=None):
        return self.d.get(k, default)

    def set(self, k, v, ttl=0):
        self.d[k] = v

    def delete(self, k):
        self.d.pop(k, None)

    def keys(self):
        return list(self.d)

    def has(self, k):
        return k in self.d

    def clear_except(self, keep):
        for k in list(self.d):
            if k != keep:
                self.d.pop(k)


class _FakePlugin:
    def __init__(self):
        self.data_dir = boot.sandbox_dir("t_login")
        self.cookie_file = os.path.join(self.data_dir, "hw_cookies.json")
        self.config = {"browser_path": "", "page_timeout": 90, "token_ttl": 3000}
        self.logger = _Logger()
        self.store = _FakeStore()
        self.cleared = 0
        self.credentials = None

    def _clear_health_cache(self):
        self.cleared += 1


class _FakeManager:
    def __init__(self, plugin):
        self.plugin = plugin
        self.auto_trust = True
        self.session_timeout = 300
        self.allow_visible_fallback = False
        self.failures = 0
        self.successes = 0
        self._session = None

    def record_auto_failure(self):
        self.failures += 1

    def record_auto_success(self):
        self.successes += 1

    def current_session(self):
        return self._session


def new_session(page_state=None, mode="manual", manual=False, sms_result="submitted"):
    plugin = _FakePlugin()
    manager = _FakeManager(plugin)
    s = hw_login.HuaweiLoginSession(manager, mode=mode, manual=manual)
    manager._session = s
    s._auth = _FakeAuth(page_state, sms_result)
    s._ws = object()
    s._proc = None
    return s, manager, plugin


class _NoWait:
    """_wake 替身：每次 wait 推进假时钟，超过预算就抛。"""

    def __init__(self, clock, budget=3600, ticks=None):
        self.clock = clock
        self.budget = budget
        self.n = 0
        self._ticks = ticks if ticks is not None else {"n": 0}

    def wait(self, timeout=None):
        self.n += 1
        self._ticks["n"] += 1
        self.clock.advance(1.0)
        if self.n >= self.budget:
            raise _Budget()
        return False

    def set(self):
        pass

    def clear(self):
        pass

    def is_set(self):
        return False


class _Budget(Exception):
    pass


class TestSetState(unittest.TestCase):
    """P1-2：只换文案不能重置 deadline。"""

    def setUp(self):
        self.clock = _Clock()
        self._orig_time = hw_login.time
        hw_login.time = self.clock

    def tearDown(self):
        hw_login.time = self._orig_time

    def test_same_state_does_not_extend_deadline(self):
        s, _, _ = new_session()
        s._set_state("NEED_SMS")
        first = s._deadline
        self.clock.advance(30)
        s._set_state("NEED_SMS", "换个文案")
        self.assertEqual(s._deadline, first)
        self.assertEqual(s._message, "换个文案")

    def test_state_change_resets_deadline(self):
        s, _, _ = new_session()
        s._set_state("NEED_SMS")
        self.clock.advance(30)
        s._set_state("SUBMITTING")
        self.assertAlmostEqual(s._deadline - self.clock.time(), 90, places=0)

    def test_refresh_flag_resets(self):
        s, _, _ = new_session()
        s._set_state("NEED_SMS")
        first = s._deadline
        self.clock.advance(30)
        s._set_state("NEED_SMS", refresh=True)
        self.assertGreater(s._deadline, first)


class TestNoInfiniteLoop(unittest.TestCase):
    """P1-2：sms_error 常显时也必须能超时。"""

    def setUp(self):
        self.clock = _Clock()
        self._orig_time = hw_login.time
        hw_login.time = self.clock

    def tearDown(self):
        hw_login.time = self._orig_time

    def test_sms_error_loop_still_times_out(self):
        s, _, _ = new_session({"sms": True, "trust": False, "sms_error": True,
                               "pwd_error": False})
        s._set_state("SUBMITTING")
        ticks = {"n": 0}
        s._wake = _NoWait(self.clock, budget=2000, ticks=ticks)
        with self.assertRaises(hw_login.LoginFlowError) as ctx:
            s._wait_for_completion()
        self.assertEqual(ctx.exception.code, "timeout")
        self.assertLess(ticks["n"], 2000, "不应该被预算强行打断，应该真的超时")
        self.assertGreater(ticks["n"], 250)

    def test_hard_cap_bounds_the_session(self):
        s, _, _ = new_session()
        s._session_timeout = 60
        s._started_at = self.clock.time()
        s._set_state("NEED_SMS")
        s._wake = _NoWait(self.clock, budget=5000)
        with self.assertRaises(hw_login.LoginFlowError):
            s._wait_for_completion()
        self.assertLessEqual(self.clock.time() - s._started_at, 60 * 3 + 5)


class TestSmsFlow(unittest.TestCase):
    """P0-2：filled 不能被当成已提交；4~8 位都收。"""

    def setUp(self):
        self.clock = _Clock()
        self._orig_time = hw_login.time
        hw_login.time = self.clock

    def tearDown(self):
        hw_login.time = self._orig_time

    def test_filled_is_not_treated_as_submitted(self):
        s, _, _ = new_session({"sms": True, "trust": False, "sms_error": False,
                               "pwd_error": False}, sms_result="filled")
        s._set_state("NEED_SMS")
        s._enqueue_action("sms", "123456")
        s._process_action()
        self.assertFalse(s._sms_action_sent)
        self.assertEqual(s._state, "NEED_SMS")
        self.assertIn("没有找到提交按钮", s._message)

    def test_submitted_is_treated_as_sent(self):
        s, _, _ = new_session({"sms": True, "trust": False, "sms_error": False,
                               "pwd_error": False}, sms_result="submitted")
        s._set_state("NEED_SMS")
        s._enqueue_action("sms", "123456")
        s._process_action()
        self.assertTrue(s._sms_action_sent)
        self.assertEqual(s._state, "SUBMITTING")

    def test_grace_period_is_at_least_30s(self):
        self.assertGreaterEqual(hw_login.SMS_RETRY_GRACE, 30.0)

    def test_grace_does_not_fire_before_30s(self):
        s, _, _ = new_session({"sms": True, "trust": False, "sms_error": False,
                               "pwd_error": False})
        s._set_state("NEED_SMS")
        s._enqueue_action("sms", "123456")
        s._process_action()
        self.clock.advance(15)
        s._update_page_state()
        self.assertEqual(s._state, "SUBMITTING")

    def test_grace_fires_after_30s(self):
        s, _, _ = new_session({"sms": True, "trust": False, "sms_error": False,
                               "pwd_error": False})
        s._set_state("NEED_SMS")
        s._enqueue_action("sms", "123456")
        s._process_action()
        self.clock.advance(hw_login.SMS_RETRY_GRACE + 1)
        s._update_page_state()
        self.assertEqual(s._state, "NEED_SMS")

    def test_submit_sms_accepts_4_to_8_digits(self):
        for code in ("1234", "123456", "12345678"):
            s, _, _ = new_session()
            s._set_state("NEED_SMS")
            s.submit_sms(code)          # 不抛就是通过
            s._actions.get_nowait()
            s._pending_action = ""

    def test_submit_sms_rejects_bad(self):
        for code in ("123", "123456789", "abcdef", ""):
            s, _, _ = new_session()
            s._set_state("NEED_SMS")
            with self.assertRaises(hw_login.LoginFlowError):
                s.submit_sms(code)


class TestPageStateBranches(unittest.TestCase):
    """P1-3 / P1-4：密码错误有分支；脚本读不到不改状态。"""

    def setUp(self):
        self.clock = _Clock()
        self._orig_time = hw_login.time
        hw_login.time = self.clock

    def tearDown(self):
        hw_login.time = self._orig_time

    def test_empty_info_keeps_state(self):
        s, _, _ = new_session()
        s._set_state("NEED_SMS")
        s._auth._js = lambda ws, expr: None      # 页面脚本读不到
        s._update_page_state()
        self.assertEqual(s._state, "NEED_SMS")

    def test_non_json_info_keeps_state(self):
        s, _, _ = new_session()
        s._set_state("NEED_SMS")
        s._auth._js = lambda ws, expr: "undefined"
        s._update_page_state()
        self.assertEqual(s._state, "NEED_SMS")

    def test_password_error_raises(self):
        s, _, _ = new_session({"sms": False, "trust": False, "sms_error": False,
                               "pwd_error": True})
        s._set_state("SUBMITTING")
        s._credentials_submitted = True
        with self.assertRaises(hw_login.LoginFlowError) as ctx:
            s._update_page_state()
        self.assertEqual(ctx.exception.code, "bad_credentials")

    def test_password_error_ignored_before_submit(self):
        s, _, _ = new_session({"sms": False, "trust": False, "sms_error": False,
                               "pwd_error": True})
        s._set_state("SUBMITTING")
        s._credentials_submitted = False
        s._update_page_state()                   # 不该抛
        self.assertEqual(s._state, "SUBMITTING")


class TestTrustFlow(unittest.TestCase):
    """P1-5：误判后要能重试，不能永久失效。"""

    def setUp(self):
        self.clock = _Clock()
        self._orig_time = hw_login.time
        hw_login.time = self.clock

    def tearDown(self):
        hw_login.time = self._orig_time

    def test_trust_action_sent_retries_after_grace(self):
        s, _, _ = new_session({"sms": False, "trust": True, "sms_error": False,
                               "pwd_error": False})
        s._set_state("SUBMITTING")
        s._trust_action_sent = True
        s._trust_action_at = self.clock.time()
        self.clock.advance(hw_login.TRUST_RETRY_GRACE + 1)
        s._update_page_state()
        self.assertFalse(s._trust_action_sent)
        self.assertTrue(s._actions.qsize() >= 1)

    def test_second_failure_asks_user(self):
        s, _, _ = new_session({"sms": False, "trust": True, "sms_error": False,
                               "pwd_error": False})
        s._set_state("SUBMITTING")
        s._trust_action_sent = True
        s._trust_action_at = self.clock.time()
        s._trust_retries = 1
        self.clock.advance(hw_login.TRUST_RETRY_GRACE + 1)
        s._update_page_state()
        self.assertEqual(s._state, "NEED_TRUST")

    def test_auto_trust_false_asks_user(self):
        s, _, _ = new_session({"sms": False, "trust": True, "sms_error": False,
                               "pwd_error": False})
        s.auto_trust = False
        s._set_state("SUBMITTING")
        s._update_page_state()
        self.assertEqual(s._state, "NEED_TRUST")


class TestFallback(unittest.TestCase):
    """P2-8：排除列表 + manual 不写冷却 + 保留真实错误码。"""

    def setUp(self):
        self.clock = _Clock()
        self._orig_time = hw_login.time
        hw_login.time = self.clock

    def tearDown(self):
        hw_login.time = self._orig_time

    def test_skip_list_covers_config_errors(self):
        for code in ("browser", "cookie", "credentials_missing",
                     "credentials_unavailable", "credentials_corrupt",
                     "credentials_locked", "bad_credentials", "wronghost"):
            self.assertIn(code, hw_login._FALLBACK_SKIP, code)

    def test_manual_failure_does_not_write_cooldown(self):
        s, mgr, _ = new_session(mode="auto", manual=True)
        s._auto_attempted = True
        mgr.allow_visible_fallback = True
        s._launch = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        s._close_browser = lambda *a, **k: None
        s._try_visible_fallback("failed")
        self.assertEqual(mgr.failures, 0)

    def test_auto_failure_writes_cooldown(self):
        s, mgr, _ = new_session(mode="auto", manual=False)
        s._auto_attempted = True
        mgr.allow_visible_fallback = True
        s._launch = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
        s._close_browser = lambda *a, **k: None
        s._try_visible_fallback("failed")
        self.assertEqual(mgr.failures, 1)

    def test_browser_code_does_not_fall_back(self):
        s, mgr, _ = new_session(mode="auto")
        s._auto_attempted = True
        mgr.allow_visible_fallback = True
        self.assertFalse(s._try_visible_fallback("browser"))


class TestThreadStartFailure(unittest.TestCase):
    """P1-6：线程启动失败不能留下永久 LAUNCHING。"""

    def setUp(self):
        self.clock = _Clock()
        self._orig_time = hw_login.time
        hw_login.time = self.clock

    def tearDown(self):
        hw_login.time = self._orig_time

    def test_start_failure_marks_failed(self):
        s, _, _ = new_session()
        orig = hw_login.threading.Thread

        class Boom:
            def __init__(self, *a, **k):
                pass

            def start(self):
                raise RuntimeError("can't start new thread")

            def is_alive(self):
                return False

            def join(self, timeout=None):
                pass

        hw_login.threading.Thread = Boom
        try:
            with self.assertRaises(hw_login.LoginFlowError):
                s.start()
        finally:
            hw_login.threading.Thread = orig
        self.assertEqual(s._state, "FAILED")
        self.assertIn("浏览器启动失败", s._message)


class TestCleanupSweep(unittest.TestCase):
    """P1-7：被新会话取代的旧会话不能清扫 profile。"""

    def test_superseded_session_does_not_sweep(self):
        s, mgr, _ = new_session()
        seen = {}
        s._auth._stop_process = lambda proc, sweep_profile=True: seen.setdefault("sweep", sweep_profile)
        mgr._session = object()             # 已经被新会话取代
        s._cleanup()
        self.assertFalse(seen.get("sweep"))

    def test_current_session_sweeps(self):
        s, mgr, _ = new_session()
        seen = {}
        s._auth._stop_process = lambda proc, sweep_profile=True: seen.setdefault("sweep", sweep_profile)
        mgr._session = s
        s._cleanup()
        self.assertTrue(seen.get("sweep"))


# ============================ 风控闸门 ============================

class TestGate(unittest.TestCase):
    """P0-1：额度语义改成「失败次数」，成功要归还。"""

    def setUp(self):
        self.plugin = _FakePlugin()
        self.mgr = hw_login.HuaweiLoginManager(self.plugin)

    def test_default_daily_limit(self):
        self.assertEqual(hw_login.LOGIN_DEFAULTS["daily_limit"], 3)
        self.assertEqual(self.mgr.daily_limit, 3)

    def test_success_returns_quota(self):
        self.mgr.daily_limit = 1
        self.mgr._attempts = []
        self.mgr._record_auto_attempt()
        with self.assertRaises(hw_login.LoginFlowError):
            self.mgr._check_auto_gate()
        self.mgr.record_auto_success()
        self.mgr._check_auto_gate()          # 成功归还后应放行
        self.assertEqual(len(self.mgr._attempts), 0)

    def test_success_clears_cooldown(self):
        self.mgr.record_auto_failure()
        self.assertGreater(self.mgr.failure_cooldown_until, time.time())
        self.mgr.record_auto_success()
        self.assertEqual(self.mgr.failure_cooldown_until, 0.0)

    def test_future_cooldown_is_clamped(self):
        path = self.mgr.login_config_path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"failure_cooldown_until": 1e18}, f)
        mgr = hw_login.HuaweiLoginManager(self.plugin)
        self.assertEqual(mgr.failure_cooldown_until, 0.0)

    def test_future_attempts_pruned(self):
        self.mgr._attempts = [time.time() + 10 ** 6]
        self.mgr._prune_attempts()
        self.assertEqual(self.mgr._attempts, [])

    def test_truncated_config_backed_up_and_warned(self):
        path = self.mgr.login_config_path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"mode": "passw')
        mgr = hw_login.HuaweiLoginManager(self.plugin)
        self.assertEqual(mgr.login_mode, "cookie")
        self.assertTrue(any(".bad." in name for name in os.listdir(os.path.dirname(path))))
        self.assertTrue(any(lvl == "warning" for lvl, _ in self.plugin.logger.records))

    def test_illegal_numeric_values_clamped(self):
        path = self.mgr.login_config_path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"daily_limit": 0, "session_timeout": 99999, "attempts": ["x", None]}, f)
        mgr = hw_login.HuaweiLoginManager(self.plugin)
        self.assertEqual(mgr.daily_limit, 1)
        self.assertEqual(mgr.session_timeout, 1800)
        self.assertEqual(mgr._attempts, [])

    def test_is_busy(self):
        self.assertFalse(self.mgr.is_busy())
        s, _, _ = new_session()
        s._set_state("NEED_SMS")
        self.mgr._session = s
        self.assertTrue(self.mgr.is_busy())
        s._set_state("DONE")
        self.assertFalse(self.mgr.is_busy())


# ============================ main / 插件层 ============================

def make_plugin(**overrides):
    # 每个插件实例用独立的沙箱目录，避免测试之间互相看到对方的 cookie / 缓存。
    main_mod._data_dir = lambda: boot.sandbox_dir("t_plugin")
    return boot.make_plugin(main_mod, plugin_dir=PLUGIN_DIR_UNDER_TEST, **overrides)


class TestFormatting(unittest.TestCase):
    """P2-1 / P2-2：体重取最近一天；运动记录带单位。"""

    def test_weight_uses_last_day(self):
        text = main_mod.HuaweiHealthPlugin._fmt_weight({
            "overall": {"bodyWeight": {"avg": 70.5, "count": 3}},
            "daily": [{"day": "2026-10-16", "bodyWeight": {"avg": 71.0}},
                      {"day": "2026-10-20", "bodyWeight": {"avg": 70.0}}],
        })
        self.assertIn("70.0", text)
        self.assertIn("2026-10-20", text)
        self.assertNotIn("最新 70.5", text)

    def test_activities_have_units(self):
        text = main_mod.HuaweiHealthPlugin._fmt_acts(
            [{"activityType": 3, "distance": 5000, "duration": 1800000,
              "endTime": 1761000000000}], 30, 5)
        self.assertIn("公里", text)
        self.assertIn("分", text)
        self.assertNotIn("距离5000", text)

    def test_stat_line(self):
        self.assertEqual(main_mod.HuaweiHealthPlugin._stat_line(
            {"avg": 60, "min": 50, "max": 70, "count": 3}, "天"), "均60 / 最低50 / 最高70 / 3 天")


class TestIntCfg(unittest.TestCase):
    """P2-6：非数字不能抛裸异常。"""

    def test_guards(self):
        self.assertEqual(main_mod._int_cfg(None, 7, 1, 30), 7)
        self.assertEqual(main_mod._int_cfg("abc", 7, 1, 30), 7)
        self.assertEqual(main_mod._int_cfg("", 7, 1, 30), 7)
        self.assertEqual(main_mod._int_cfg(0, 7, 1, 30), 1)
        self.assertEqual(main_mod._int_cfg(999, 7, 1, 30), 30)
        self.assertEqual(main_mod._int_cfg("7天", 7, 1, 30), 7)
        self.assertEqual(main_mod._int_cfg(7.9, 7, 1, 30), 7)


class TestErrMapping(unittest.TestCase):
    def test_schema_drift_is_actionable(self):
        msg = main_mod.HuaweiHealthPlugin._err(hw_client.SchemaDrift("缺少 healthRecords"))
        self.assertIn("改版", msg)

    def test_auth_expired(self):
        self.assertIn("重新导入", main_mod.HuaweiHealthPlugin._err(hw_client.AuthExpired("x")))


class TestCachedNone(unittest.TestCase):
    def test_none_result_is_cached(self):
        plugin = make_plugin()
        calls = {"n": 0}

        def producer(client):
            calls["n"] += 1
            return None

        async def _client(force=False, stale_token=""):
            class C:
                token = "T"
            return C()

        plugin._client = _client

        async def run():
            await plugin._cached("k", producer, ttl=60)
            await plugin._cached("k", producer, ttl=60)

        asyncio.run(run())
        self.assertEqual(calls["n"], 1)

    def test_ttl_zero_disables_cache(self):
        """P3-2：data_ttl=0 应该「不缓存」，不是「永不过期」。"""
        plugin = make_plugin(data_ttl=0)
        calls = {"n": 0}

        def producer(client):
            calls["n"] += 1
            return {"v": calls["n"]}

        async def _client(force=False, stale_token=""):
            class C:
                token = "T"
            return C()

        plugin._client = _client

        async def run():
            await plugin._cached("k", producer)
            await plugin._cached("k", producer)

        asyncio.run(run())
        self.assertEqual(calls["n"], 2)
        self.assertIsNone(plugin.store.get("k"))


class TestInitializeCookie(unittest.TestCase):
    """P1-1：启动时不能覆盖滚续出来的 cookie。"""

    def test_startup_does_not_clobber(self):
        plugin = make_plugin(**{"cookie_" + k: v for k, v in SIX.items()})
        # 先让插件按配置写入一次（等价于首次安装）
        asyncio.run(plugin.initialize())
        rolled = plugin.auth.load_cookies() + [{
            "name": "__uni__uid", "value": "ROLLED", "domain": ".huawei.com", "path": "/"}]
        plugin.auth.save_cookies(rolled)
        # 再「重启」一次（新实例，同样的配置）
        plugin2 = make_plugin(**{"cookie_" + k: v for k, v in SIX.items()})
        plugin2.data_dir = plugin.data_dir
        plugin2.cookie_file = plugin.cookie_file
        plugin2.store = plugin.store
        plugin2.credentials = plugin.credentials
        plugin2.login_manager.plugin = plugin2
        asyncio.run(plugin2.initialize())
        names = {c["name"] for c in plugin.auth.load_cookies()}
        self.assertIn("__uni__uid", names)

    def test_startup_applies_changed_config(self):
        plugin = make_plugin(**{"cookie_" + k: v for k, v in SIX.items()})
        asyncio.run(plugin.initialize())
        changed = dict(SIX, CASTGC="user-edited")
        plugin2 = make_plugin(**{"cookie_" + k: v for k, v in changed.items()})
        plugin2.data_dir = plugin.data_dir
        plugin2.cookie_file = plugin.cookie_file
        plugin2.store = plugin.store
        plugin2.credentials = plugin.credentials
        plugin2.login_manager.plugin = plugin2
        asyncio.run(plugin2.initialize())
        values = {c["value"] for c in plugin.auth.load_cookies() if c["name"] == "CASTGC"}
        self.assertEqual(values, {"user-edited"})


class _StubClient:
    """总览用的假客户端：除运动记录外全部返回「合法空」。"""

    token = "T"

    def __init__(self, acts=None):
        self._acts = acts if acts is not None else []

    def resting_heart_rate(self, days=7):
        return {"overall": {}, "daily": []}

    def sleep_records(self, days=7):
        return []

    def hrv_stats(self, days=7):
        return {"overall": {}, "daily": []}

    def stress_stats(self, days=7):
        return {"overall": {}, "daily": []}

    def body_weight(self, days=1095):
        return {"overall": {}, "daily": []}

    def heart_rate_zones(self):
        return {}

    def athletic_performance(self):
        return {}

    def personal_bests(self, kind="running"):
        return {}

    def activities(self, days=30, limit=20):
        return list(self._acts)


class TestOverviewIncludesActs(unittest.TestCase):
    """P2-14：health_overview 必须**真的**把「近期运动」取出来（不是源码里有个字样）。"""

    def _run_overview(self, acts):
        plugin = make_plugin()
        client = _StubClient(acts)

        async def _client(force=False, stale_token=""):
            return client

        plugin._client = _client
        return asyncio.run(plugin.health_overview(boot.allowed_event()))

    def test_overview_contains_activity_record(self):
        text = self._run_overview([
            {"activityType": 3, "distance": 5000, "duration": 1800000,
             "endTime": 1761000000000}])
        self.assertIn("【近期运动】", text)
        self.assertIn("5.00 公里", text)
        self.assertIn("30 分 00 秒", text)

    def test_overview_has_all_nine_sections(self):
        text = self._run_overview([])
        for title in ("静息心率", "睡眠（近 7 晚）", "睡眠 HRV", "压力", "体重",
                      "心率区间", "运动能力", "个人纪录", "近期运动"):
            self.assertIn(title, text, title)

    def test_empty_activities_is_reported_as_empty_not_missing(self):
        text = self._run_overview([])
        self.assertIn("最近 30 天没有运动记录", text)

    def test_overview_timeout_budget_is_bounded(self):
        self.assertLessEqual(main_mod.HuaweiHealthPlugin.OVERVIEW_TIMEOUT, 110)


class TestHealthStatus(unittest.TestCase):
    """P2-13：password 模式不再恒报「没有 cookie」。"""

    @unittest.skipIf(sys.platform != "win32", "Windows DPAPI only")
    def test_password_mode_reports_credentials(self):
        plugin = make_plugin()
        plugin.login_manager.login_mode = "password"
        plugin.credentials.save("13800138000", "pw")
        text = asyncio.run(plugin.health_status(boot.allowed_event()))
        self.assertIn("账号密码", text)
        self.assertIn("已保存", text)
        self.assertNotIn("需要导入", text)

    def test_cookie_mode_mentions_cookie(self):
        plugin = make_plugin()
        text = asyncio.run(plugin.health_status(boot.allowed_event()))
        self.assertIn("Cookie", text)


# ============================ webapi ============================

class TestWebApi(unittest.TestCase):
    def setUp(self):
        self.plugin = make_plugin()
        self.api = hw_webapi.HuaweiHealthWebApi(self.plugin)
        self.api.register()

    def test_no_account_route(self):
        routes = [r["route"] for r in self.plugin.context.web_apis]
        self.assertFalse(any(r.endswith("/login/account") for r in routes))
        self.assertEqual(len(routes), 14)

    def test_key_cookies_match_specs(self):
        self.assertEqual(set(hw_webapi.KEY_COOKIES),
                         {name for name, _, _ in hw_auth.MIN_COOKIE_SPECS})

    def test_login_start_returns_full_status(self):
        from astrbot.api.web import request

        async def run():
            request.body = {}
            self.plugin.login_manager.start = lambda *a, **k: self.plugin.login_manager.status()
            resp = await self.api.login_start()
            return resp["payload"]["data"]

        data = asyncio.run(run())
        for key in ("state", "daily_used", "daily_limit", "prefer_auto"):
            self.assertIn(key, data)

    def test_status_has_login_mode(self):
        """校验三处版本号互相一致，不校验具体版本值。"""
        async def run():
            return (await self.api.get_status())["payload"]["data"]

        data = asyncio.run(run())
        self.assertIn("login_mode", data)
        self.assertEqual(data["version"], _metadata_version(str(PLUGIN_DIR_UNDER_TEST)))

    def test_credentials_status_has_state(self):
        async def run():
            return (await self.api.credentials_status())["payload"]["data"]

        data = asyncio.run(run())
        self.assertIn("state", data)

    def test_no_cookie_values_in_status(self):
        # 用不可能与 JSON 字面量撞车的哨兵值
        sentinel = {
            "CASTGC": "SENTINEL-CASTGC-9f1c",
            "sid": "SENTINEL-SID-2a7b",
            "hwid_cas_sid": "SENTINEL-HWID-4d3e",
            "HuaweiID_CAS_ISCASLOGIN": "SENTINEL-ISCAS-5b6a",
            "CASLOGINSITE": "SENTINEL-SITE-7c8d",
            "LOGINACCSITE": "SENTINEL-ACCSITE-1e2f",
        }
        self.plugin.auth.import_cookie_sources("", sentinel)

        async def run():
            return (await self.api.get_status())["payload"]

        payload = asyncio.run(run())
        blob = json.dumps(payload, ensure_ascii=False)
        for value in sentinel.values():
            self.assertNotIn(value, blob)


class TestVersionConsistency(unittest.TestCase):
    def test_version_strings(self):
        """校验三处版本号互相一致，不校验具体版本值。"""
        root = str(PLUGIN_DIR_UNDER_TEST)
        version = _metadata_version(root)
        with open(os.path.join(root, "main.py"), "r", encoding="utf-8") as f:
            self.assertIn(f'"{version}"', f.read())
        with open(os.path.join(root, "hw_webapi.py"), "r", encoding="utf-8") as f:
            self.assertIn(f'"{version}"', f.read())

    def test_tool_names_match_registry(self):
        from astrbot.api.event import filter
        self.assertEqual(sorted(filter.llm_tools), sorted(main_mod.TOOL_NAMES))


if __name__ == "__main__":
    unittest.main(verbosity=2)


# ==================== 第二轮修复（对抗性复核 verify_auth 之后） ====================

class TestRound2SweepDefault(unittest.TestCase):
    """P1-A：`_close_browser()` 的默认清扫资格必须看「自己是否还是当前会话」。"""

    def _session_with_recorder(self):
        s, mgr, _ = new_session()
        seen = {}

        class Auth:
            def _call(self, *a, **k):
                return {"result": {}}

            def _stop_process(self, proc, sweep_profile=True):
                seen["sweep"] = sweep_profile

            def _cleanup_orphan_browsers(self):
                pass

        s._auth = Auth()
        s._ws = object()
        s._proc = object()
        return s, mgr, seen

    def test_superseded_session_does_not_sweep_by_default(self):
        s, mgr, seen = self._session_with_recorder()
        mgr._session = object()          # 已被新会话取代
        s._close_browser()               # 默认参数
        self.assertFalse(seen["sweep"])

    def test_current_session_sweeps_by_default(self):
        s, mgr, seen = self._session_with_recorder()
        mgr._session = s
        s._close_browser()
        self.assertTrue(seen["sweep"])

    def test_launch_failure_when_superseded_does_not_sweep(self):
        """P1-A 的真正危险路径：`_launch()` 的 except。"""
        s, mgr, _ = new_session()
        s._profile_dir = boot.sandbox_dir("t_launch")
        mgr._session = object()          # 已被新会话取代
        seen = {}
        orig_find = hw_login.find_browser
        orig_popen = hw_login.subprocess.Popen
        orig_port = hw_login.read_devtools_port
        orig_stop = hw_auth.HuaweiAuth._stop_process

        class Proc:
            pid = 4242

            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

        def fake_stop(self, proc, sweep_profile=True):
            seen["sweep"] = sweep_profile

        hw_login.find_browser = lambda p="": "/fake/browser"
        hw_login.subprocess.Popen = lambda *a, **k: Proc()
        hw_login.read_devtools_port = lambda *a, **k: 0
        hw_auth.HuaweiAuth._stop_process = fake_stop
        try:
            with self.assertRaises(hw_login.LoginFlowError):
                s._launch()
        finally:
            hw_login.find_browser = orig_find
            hw_login.subprocess.Popen = orig_popen
            hw_login.read_devtools_port = orig_port
            hw_auth.HuaweiAuth._stop_process = orig_stop
        self.assertIn("sweep", seen, "_launch 的失败收尾没有走 _stop_process")
        self.assertFalse(seen["sweep"])


class TestRound2NeedsHuman(unittest.TestCase):
    """P1-B：需要人工介入时不能被 cookie 回退盖掉。"""

    def _plugin(self, status):
        plugin = make_plugin()
        plugin.login_manager.login_mode = "password"
        plugin.auth.import_cookie_sources("", SIX)
        plugin.login_manager.start = lambda *a, **k: status
        plugin.login_manager.status = lambda: dict(status)
        return plugin

    def _run(self, status):
        plugin = self._plugin(status)
        calls = {"fetch": 0}
        real = hw_auth.HuaweiAuth.fetch_token

        def fake(self):
            calls["fetch"] += 1
            raise hw_auth.HuaweiAuthError("cookie 桩")

        hw_auth.HuaweiAuth.fetch_token = fake
        try:
            with self.assertRaises(Exception) as ctx:
                asyncio.run(plugin._token())
        finally:
            hw_auth.HuaweiAuth.fetch_token = real
        return ctx.exception, calls["fetch"]

    def test_needs_sms_does_not_fall_back(self):
        exc, fetches = self._run({"state": "NEED_SMS", "message": "请输入手机验证码"})
        self.assertIsInstance(exc, main_mod.LoginNeedsHuman)
        self.assertEqual(fetches, 0)
        self.assertIn("手机验证码", str(exc))

    def test_needs_cred_does_not_fall_back(self):
        exc, fetches = self._run({"state": "NEED_CRED", "message": "浏览器已打开"})
        self.assertIsInstance(exc, main_mod.LoginNeedsHuman)
        self.assertEqual(fetches, 0)

    def test_real_failure_does_fall_back(self):
        exc, fetches = self._run({"state": "FAILED", "message": "自动登录失败"})
        self.assertEqual(fetches, 1)
        self.assertNotIsInstance(exc, main_mod.LoginNeedsHuman)


class TestRound2Cooldown(unittest.TestCase):
    """P2-A：可自愈的失败不该写 6 小时冷却。"""

    def setUp(self):
        self.clock = _Clock()
        self._orig_time = hw_login.time
        hw_login.time = self.clock

    def tearDown(self):
        hw_login.time = self._orig_time

    def _run_failure(self, code):
        s, mgr, _ = new_session(mode="auto", manual=False)
        s._auto_attempted = True
        s._launch = lambda: (_ for _ in ()).throw(hw_login.LoginFlowError(code))
        s._close_browser = lambda *a, **k: None
        s._run()
        return mgr

    def test_bad_credentials_no_cooldown(self):
        mgr = self._run_failure("bad_credentials")
        self.assertEqual(mgr.failures, 0)
        self.assertEqual(mgr._session._message, "账号或密码不正确，请在 WebUI 重新保存账号密码")

    def test_browser_no_cooldown(self):
        self.assertEqual(self._run_failure("browser").failures, 0)

    def test_timeout_still_writes_cooldown(self):
        self.assertEqual(self._run_failure("timeout").failures, 1)

    def test_clear_cooldown(self):
        plugin = make_plugin()
        mgr = plugin.login_manager
        mgr.record_auto_failure()
        self.assertGreater(mgr.failure_cooldown_until, time.time())
        mgr.clear_cooldown()
        self.assertEqual(mgr.failure_cooldown_until, 0.0)


class TestRound2Quota(unittest.TestCase):
    """P2-B：manual=True 的会话不记账，成功后也不能 pop 别人的名额。"""

    def test_manual_success_does_not_pop(self):
        plugin = make_plugin()
        mgr = plugin.login_manager
        mgr.daily_limit = 1
        mgr._attempts = [time.time()]
        s, _, _ = new_session(mode="auto", manual=True)
        s._auto_attempted = True
        s._attempt_recorded = False
        s.manager = mgr
        s._auth = _FakeAuth()
        s._auth._call = lambda *a, **k: {"result": {"cookies": [
            {"name": "sid", "value": "v", "domain": ".huawei.com"}]}}
        s._finish("TOKEN")
        self.assertEqual(len(mgr._attempts), 1)

    def test_auto_success_pops_own(self):
        plugin = make_plugin()
        mgr = plugin.login_manager
        mgr.daily_limit = 1
        mgr._attempts = [time.time()]
        s, _, _ = new_session(mode="auto", manual=False)
        s._auto_attempted = True
        s._attempt_recorded = True
        s.manager = mgr
        s._auth = _FakeAuth()
        s._auth._call = lambda *a, **k: {"result": {"cookies": [
            {"name": "sid", "value": "v", "domain": ".huawei.com"}]}}
        s._finish("TOKEN")
        self.assertEqual(len(mgr._attempts), 0)


class TestRound2Cdp(unittest.TestCase):
    """P2-C：`ws.send` 断开也要分类。"""

    def test_send_failure_raises_auth_error(self):
        a = make_auth()

        class DeadWS:
            def send(self, data):
                raise RuntimeError("socket is already closed")

            def recv(self):
                raise RuntimeError("socket is already closed")

        with self.assertRaises(hw_auth.HuaweiAuthError) as ctx:
            a._call(DeadWS(), "Runtime.evaluate", {"expression": "1"})
        self.assertIn("CDP 连接已断开", str(ctx.exception))

    def test_mutex_budget_is_short(self):
        a = make_auth()
        self.assertTrue(a._auth_mutex.acquire(blocking=False))
        try:
            t0 = time.monotonic()
            with self.assertRaises(hw_auth.HuaweiAuthError):
                a.fetch_token()
            elapsed = time.monotonic() - t0
        finally:
            a._auth_mutex.release()
        self.assertLess(elapsed, 8.0, "锁预算不该绑到 page_timeout")


class TestRound2ParseLeak(unittest.TestCase):
    """P2-D：解析报错文案不能回显 cookie 值。"""

    def test_no_values_in_message(self):
        sentinel = ["SENTINEL-A-1111", "SENTINEL-B-2222", "SENTINEL-C-3333"]
        text = "CASTGC=named-value\nsid=named-sid\n" + "\n".join(sentinel)
        with self.assertRaises(hw_auth.HuaweiAuthError) as ctx:
            hw_auth.parse_cookie_fields(text)
        msg = str(ctx.exception)
        for value in sentinel:
            self.assertNotIn(value, msg)
        self.assertIn("行", msg)

    def test_no_values_in_count_message(self):
        sentinel = ["SENTINEL-D-4444", "SENTINEL-E-5555"]
        with self.assertRaises(hw_auth.HuaweiAuthError) as ctx:
            hw_auth.parse_cookie_fields("\n".join(sentinel))
        for value in sentinel:
            self.assertNotIn(value, str(ctx.exception))


class TestRound2LoginConfig(unittest.TestCase):
    """P3-A / P3-B：形状不对要备份告警；写不进去不要抛裸 OSError。"""

    def setUp(self):
        self.plugin = _FakePlugin()
        os.makedirs(self.plugin.data_dir, exist_ok=True)
        self.path = os.path.join(self.plugin.data_dir, "login_config.json")

    def _load(self, payload):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(payload)
        return hw_login.HuaweiLoginManager(self.plugin)

    def _backups(self):
        return [n for n in os.listdir(self.plugin.data_dir) if ".bad." in n]

    def test_top_level_array_backed_up(self):
        self._load("[1, 2, 3]")
        self.assertTrue(self._backups())

    def test_top_level_null_backed_up(self):
        self._load("null")
        self.assertTrue(self._backups())

    def test_truncated_backed_up(self):
        self._load('{"mode": "passw')
        self.assertTrue(self._backups())

    def test_bad_fields_warn_without_backup(self):
        mgr = self._load(json.dumps({"mode": "passw0rd", "daily_limit": "abc"}))
        self.assertEqual(mgr.daily_limit, 3)
        self.assertEqual(mgr.login_mode, "cookie")
        self.assertTrue(any(lvl == "warning" for lvl, _ in self.plugin.logger.records))

    def test_save_failure_is_swallowed(self):
        mgr = hw_login.HuaweiLoginManager(self.plugin)
        orig = hw_login.os.replace

        def boom(*a, **k):
            raise PermissionError("read-only")

        hw_login.os.replace = boom
        try:
            mgr.record_auto_failure()       # 不该抛
        finally:
            hw_login.os.replace = orig
        self.assertTrue(any(lvl == "warning" for lvl, _ in self.plugin.logger.records))


class TestRound2SmsScript(unittest.TestCase):
    """P3-D：逐框填写必须「框数 == 码长」，不能截断。"""

    def test_script_requires_length_match(self):
        script = hw_login.HuaweiLoginSession._sms_submit_script("12345678")
        self.assertIn("n!==code.length", script)
        self.assertIn("length_mismatch", script)
        self.assertNotIn("slice(0,6)", script)

    def test_process_action_length_mismatch(self):
        clock = _Clock()
        orig = hw_login.time
        hw_login.time = clock
        try:
            s, _, _ = new_session(sms_result="length_mismatch")
            s._set_state("NEED_SMS")
            s._enqueue_action("sms", "12345678")
            s._process_action()
        finally:
            hw_login.time = orig
        self.assertEqual(s._state, "NEED_SMS")
        self.assertFalse(s._sms_action_sent)
        self.assertIn("对不上", s._message)


class TestRound2Trust(unittest.TestCase):
    """P3-G：用户手选成功后退信重试计数；重试沿用上次选择。"""

    def test_retries_reset_after_user_choice(self):
        clock = _Clock()
        orig = hw_login.time
        hw_login.time = clock
        try:
            s, _, _ = new_session()
            s._set_state("NEED_TRUST")
            s._trust_retries = 1
            # 信任按钮点到了：脚本返回 'clicked'
            s._auth._js = lambda ws, expr: (
                "clicked" if "const btn=" in expr else json.dumps(
                    {"sms": False, "trust": True, "sms_error": False, "pwd_error": False}))
            s._enqueue_action("trust", "later")
            s._process_action()
        finally:
            hw_login.time = orig
        self.assertEqual(s._trust_retries, 0)
        self.assertEqual(s._trust_last_choice, "later")
        self.assertTrue(s._trust_action_sent)

    def test_retry_reuses_last_choice(self):
        clock = _Clock()
        orig = hw_login.time
        hw_login.time = clock
        try:
            s, _, _ = new_session({"sms": False, "trust": True,
                                   "sms_error": False, "pwd_error": False})
            s._set_state("SUBMITTING")
            s._trust_action_sent = True
            s._trust_action_at = clock.time()
            s._trust_last_choice = "later"
            clock.advance(hw_login.TRUST_RETRY_GRACE + 1)
            s._update_page_state()
            kind, payload = s._actions.get_nowait()
        finally:
            hw_login.time = orig
        self.assertEqual((kind, payload), ("trust", "later"))


class TestRound2HardenDir(unittest.TestCase):
    def test_returns_reason_on_missing_dir(self):
        self.assertNotEqual(hw_credentials.harden_dir_permissions(""), "")

    def test_returns_empty_on_existing_dir(self):
        d = boot.sandbox_dir("t_harden")
        self.assertEqual(hw_credentials.harden_dir_permissions(d), "")


# ==================== 第三轮：补强变异测试暴露的弱用例 ====================

class TestDayWindowSpan(unittest.TestCase):
    """原用例比较「两个都被钳过的值」，任何上限都能通过（变异 M05 存活）。"""

    def test_1095_is_a_year_more_than_730(self):
        s730, e730 = hw_client._day_window(730)
        s1095, e1095 = hw_client._day_window(1095)
        d730 = datetime.datetime.strptime(s730, "%Y%m%d").date()
        d1095 = datetime.datetime.strptime(s1095, "%Y%m%d").date()
        self.assertEqual((d730 - d1095).days, 365)

    def test_cap_applies(self):
        self.assertEqual(hw_client._day_window(5000), hw_client._day_window(1095))


class TestStoreHasExpiry(unittest.TestCase):
    """原用例靠 get() 先把行删掉才让 has() 为 False（变异 M14 存活）。"""

    def test_has_is_false_for_expired_row_never_fetched(self):
        store = hw_store.HealthStore(os.path.join(boot.sandbox_dir("t_has"), "health.db"))
        store.set("e", {"x": 1}, ttl=1)
        time.sleep(1.1)
        self.assertFalse(store.has("e"))      # 不先调 get()

    def test_has_is_false_for_corrupt_row(self):
        store = hw_store.HealthStore(os.path.join(boot.sandbox_dir("t_has2"), "health.db"))
        import sqlite3
        con = sqlite3.connect(store.db_path)
        con.execute("INSERT INTO kv(k, v, expire_at) VALUES('bad', '{oops', 0)")
        con.commit()
        con.close()
        self.assertFalse(store.has("bad"))
        # 损坏行不能把 _cached 卡成「永远返回 None」
        plugin = make_plugin()
        plugin.store = store
        calls = {"n": 0}

        def producer(client):
            calls["n"] += 1
            return {"ok": True}

        async def _client(force=False, stale_token=""):
            class C:
                token = "T"
            return C()

        plugin._client = _client
        asyncio.run(plugin._cached("bad", producer, ttl=60))
        self.assertEqual(calls["n"], 1)


class TestEmptyMatrixExtended(unittest.TestCase):
    """补上 `{"total":0}` / `{"code":0,…}` / `{"total":"0"}` —— 原用例漏掉的正是不合格面。"""

    def _client(self, payload):
        c = hw_client.HuaweiHealthClient("tok")
        c.session = _Session(payload)
        return c

    def test_parse_stats_envelope_and_zero(self):
        for payload in ({"total": 0}, {"count": 0}, {"totalCount": 0}, {"total": "0"},
                        {"code": 0, "message": "success"}, {"data": None, "code": 0}):
            self.assertEqual(hw_client._parse_stats(payload),
                             {"overall": {}, "daily": []}, payload)

    def test_zones_envelope_and_zero(self):
        for payload in ({"total": 0}, {"code": 0, "message": "success"},
                        {"sampleConfigs": None}):
            self.assertEqual(self._client(payload).heart_rate_zones(), {}, payload)

    def test_sleep_null_and_string_zero(self):
        for payload in ({"healthRecords": None}, {"total": "0"},
                        {"code": 0, "message": "success"}):
            self.assertEqual(self._client(payload).sleep_records(7), [], payload)

    def test_activities_null(self):
        for payload in ({"activityRecords": None}, {"total": "0"},
                        {"code": 0, "message": "success"}):
            self.assertEqual(self._client(payload).activities(30, 5), [], payload)

    def test_real_drift_still_raises(self):
        for fn in (lambda: hw_client._parse_stats({"weird": 1}),
                   lambda: self._client({"sleepRecords": []}).sleep_records(7),
                   lambda: self._client({"activityList": []}).activities(30, 5)):
            with self.assertRaises(hw_client.SchemaDrift):
                fn()


class TestHealthStatusProbe(unittest.TestCase):
    """变异 M12 存活：三种实测分支与 401/404 都没有覆盖。"""

    def _status_with(self, probe):
        plugin = make_plugin()
        plugin.store.set("token", {"token": "T", "expire_at": time.time() + 600})

        def _probe(*a, **k):
            return probe()

        real = hw_client.HuaweiHealthClient.resting_heart_rate
        hw_client.HuaweiHealthClient.resting_heart_rate = lambda self, days=7: _probe()
        try:
            return asyncio.run(plugin.health_status(boot.allowed_event()))
        finally:
            hw_client.HuaweiHealthClient.resting_heart_rate = real

    def test_ok(self):
        text = self._status_with(lambda: {"overall": {}, "daily": []})
        self.assertIn("token 可用", text)

    def test_expired(self):
        def boom():
            raise hw_client.AuthExpired("401")
        text = self._status_with(boom)
        self.assertIn("已失效", text)

    def test_probe_error_is_not_reported_as_channel_broken(self):
        def boom():
            raise hw_client.HuaweiHealthError("404")
        text = self._status_with(boom)
        self.assertIn("无法验证", text)
        self.assertNotIn("实测失败", text)

    def test_no_token_skips_probe(self):
        plugin = make_plugin()
        text = asyncio.run(plugin.health_status(boot.allowed_event()))
        self.assertIn("跳过", text)


class TestClearCacheCallSite(unittest.TestCase):
    """变异 M09 存活：删掉 clear_except 后「导入 cookie 仍读到旧账号数据」没人发现。"""

    def test_import_cookie_clears_cached_data(self):
        from astrbot.api.web import request

        plugin = make_plugin()
        api = hw_webapi.HuaweiHealthWebApi(plugin)
        plugin.store.set("hr:7", {"stale": True}, ttl=600)
        plugin.store.set("token", {"token": "T", "expire_at": time.time() + 600})

        async def run():
            request.body = {"fields": dict(SIX)}
            return await api.import_cookie()

        resp = asyncio.run(run())
        self.assertEqual(resp["status_code"], 200)
        self.assertIsNone(plugin.store.get("hr:7"))
        self.assertIsNone(plugin.store.get("token"))

    def test_clear_failure_is_reported(self):
        plugin = make_plugin()
        plugin.store.set("hr:7", {"stale": True}, ttl=600)
        real = plugin.store.clear_except

        def boom(keep):
            raise OSError("database is locked")

        plugin.store.clear_except = boom
        try:
            with self.assertRaises(Exception):
                asyncio.run(plugin._invalidate_auth_cache())
        finally:
            plugin.store.clear_except = real


class TestLoginStartOffLoop(unittest.TestCase):
    """变异 M16 存活：不验证 to_thread。"""

    def test_login_start_runs_off_event_loop_thread(self):
        from astrbot.api.web import request

        plugin = make_plugin()
        api = hw_webapi.HuaweiHealthWebApi(plugin)
        seen = {}

        def fake_start(*a, **k):
            seen["thread"] = threading.current_thread()
            return plugin.login_manager.status()

        plugin.login_manager.start = fake_start

        async def run():
            request.body = {}
            seen["loop"] = threading.current_thread()
            return await api.login_start()

        asyncio.run(run())
        self.assertIsNot(seen["thread"], seen["loop"])


class TestFrontendContracts(unittest.TestCase):
    """变异 M18/M19/M20 存活 = 前端零覆盖。这里做结构性断言（HTML 无法跑单测）。"""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(str(PLUGIN_DIR_UNDER_TEST), "pages", "health_console", "index.html")
        with open(path, "r", encoding="utf-8") as f:
            cls.html = f.read()

    def test_no_asset_token_in_api_urls(self):
        self.assertNotIn("function withToken", self.html)
        self.assertNotIn("asset_token=", self.html)

    def test_diag_summary_uses_dom_api(self):
        self.assertNotIn('$("diagSum").innerHTML', self.html)
        self.assertIn('$("diagSum").replaceChildren()', self.html)

    def test_credentials_status_handles_all_states(self):
        for state in ("corrupt", "locked", "unavailable", "absent"):
            self.assertIn(state, self.html, state)

    def test_sms_input_accepts_4_to_8(self):
        self.assertIn('maxlength="8"', self.html)
        self.assertIn("/^\\d{4,8}$/", self.html)

    def test_no_tainted_innerhtml(self):
        # 唯一真实污点是 bridge.ready() 的 e.message（经 summary 进入 diagSum）；
        # 其余 innerHTML 都只拼服务端常量/数字，这里只锁住真正危险的那几条链。
        for taint in ("summary", "e.message", "err.message", "lastErr"):
            for line in self.html.splitlines():
                if ".innerHTML" in line and taint in line:
                    self.fail("innerHTML 里出现了污点 %r：%s" % (taint, line.strip()))


# ==================== 第四轮：干掉变异测试最后 4 个存活项 ====================

class TestSleepRecordsRawType(unittest.TestCase):
    """变异 M02：raw 是 str/int 时不能退回静默空。"""

    def _client(self, payload):
        c = hw_client.HuaweiHealthClient("tok")
        c.session = _Session(payload)
        return c

    def test_non_dict_non_list_raises(self):
        for payload in ("oops", 42, 3.14):
            with self.assertRaises(hw_client.SchemaDrift, msg=repr(payload)):
                self._client(payload).sleep_records(7)

    def test_list_is_accepted(self):
        self.assertEqual(self._client([{"a": 1}]).sleep_records(7), [{"a": 1}])


class TestGenerationOnClear(unittest.TestCase):
    """变异 M08：清缓存必须推进 generation，否则在飞任务会把旧账号结果写回。"""

    def test_inflight_write_is_discarded_after_clear(self):
        plugin = make_plugin()
        plugin.store.set("k", {"old": True}, ttl=600)
        started = {"at": None}

        def producer(client):
            time.sleep(0.25)
            return {"stale": True}

        async def _client(force=False, stale_token=""):
            class C:
                token = "T"
            return C()

        plugin._client = _client

        async def run():
            task = asyncio.create_task(plugin._cached("k", producer, ttl=600))
            await asyncio.sleep(0.05)
            # 模拟「导入 cookie」：清缓存
            await asyncio.to_thread(plugin._clear_auth_cache_blocking)
            await task

        asyncio.run(run())
        self.assertIsNone(plugin.store.get("k"))

    def test_clear_bumps_generation(self):
        plugin = make_plugin()
        plugin._cache_generation["k"] = 0
        plugin._clear_health_cache()
        self.assertEqual(plugin._cache_generation["k"], 1)


class TestToolParamGuards(unittest.TestCase):
    """变异 M13：days/limit 传非整数不能变成裸 ValueError。"""

    def test_health_sleep_bad_days(self):
        plugin = make_plugin()
        client = _StubClient([])

        async def _client(force=False, stale_token=""):
            return client

        plugin._client = _client
        text = asyncio.run(plugin.health_sleep(boot.allowed_event(), days="7天"))
        self.assertIn("最近 7 天", text)

    def test_health_activities_bad_args(self):
        plugin = make_plugin()
        client = _StubClient([])

        async def _client(force=False, stale_token=""):
            return client

        plugin._client = _client
        text = asyncio.run(plugin.health_activities(boot.allowed_event(), days=None, limit="abc"))
        self.assertIn("没有运动记录", text)


class TestFrontendNoWithToken(unittest.TestCase):
    """变异 M20：把 withToken 拼回 API URL。"""

    def test_withtoken_symbol_is_gone(self):
        path = os.path.join(str(PLUGIN_DIR_UNDER_TEST), "pages", "health_console", "index.html")
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertNotIn("withToken", html)
        self.assertNotIn("asset_token=", html)
