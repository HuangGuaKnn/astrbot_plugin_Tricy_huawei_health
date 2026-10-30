"""Release archives must never include browser session directories."""

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import privacy_gate


class TestReleaseProfiles(unittest.TestCase):
    def test_deployment_master_keys_cannot_enter_release_archives(self):
        with tempfile.TemporaryDirectory(prefix="health-release-check-") as directory:
            archive = Path(directory) / "example.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("example-master.key", b"example-key-placeholder")
                handle.writestr("example-systemd.cred", b"example-credential-placeholder")
            violations = privacy_gate.scan_archive(archive)
            self.assertEqual(len(violations), 2)
            self.assertTrue(all(v.rule == "private-artifact-file" for v in violations))

    def test_session_profiles_are_rejected_even_without_secret_looking_content(self):
        with tempfile.TemporaryDirectory(prefix="health-release-check-") as directory:
            archive = Path(directory) / "example.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("login_browser_example/Default/Preferences", "{}")
                handle.writestr("browser_profile/Local State", "{}")
            violations = privacy_gate.scan_archive(archive)
            self.assertEqual(len(violations), 2)
            self.assertTrue(all(v.rule == "browser-profile-path" for v in violations))


class TestConfigKeyLiterals(unittest.TestCase):
    """前端把配置键名写成字符串常量时，闸门不该把它当成凭据值。

    回归背景（2026-10-31）：加「Cookie 导入方式」互斥开关时，前端写了
    ``const COOKIE_JSON_PATH = "cookie_json";``。而 ``_SENSITIVE_ASSIGNMENT_PATTERN``
    里有一条 ``[a-z0-9_-]*cookie[a-z0-9_-]*`` 且带 ``(?i)``，会把
    ``COOKIE_JSON_PATH = "..."`` 整体匹配，等号右边的键名字符串被判成凭据 ->
    CI 直接红。修法是给这 7 个配置键加白名单，但**不能**因此削弱真凭据的检测。
    """

    CONFIG_KEYS = (
        "cookie_json", "cookie_CASTGC", "cookie_sid", "cookie_hwid_cas_sid",
        "cookie_HuaweiID_CAS_ISCASLOGIN", "cookie_CASLOGINSITE", "cookie_LOGINACCSITE",
    )

    def test_config_key_names_are_not_secret_values(self):
        for key in self.CONFIG_KEYS:
            with self.subTest(key=key):
                self.assertFalse(privacy_gate._is_secret_value(key.encode("utf-8")),
                                 "%s 是插件自己的配置键名，不该判定为凭据" % key)

    def test_real_credentials_are_still_detected(self):
        """放行键名不能顺手放行掉真正的凭据——这几条必须仍然报警。"""
        for value in (b"TGT-1234567890-abcdef", b"deadbeef1234",
                      b"abc123def456", b"ghp_ABCDEFGHIJKLMNOP"):
            with self.subTest(value=value):
                self.assertTrue(privacy_gate._is_secret_value(value),
                                "%r 看起来就是凭据，必须仍然命中" % value)

    def test_similar_but_unknown_names_still_flagged(self):
        """只放行白名单里的精确名字，长得很像的不放行。"""
        for value in (b"cookie_json_backup", b"cookie_CASTGC2", b"config_cookie_json"):
            with self.subTest(value=value):
                self.assertTrue(privacy_gate._is_secret_value(value))


if __name__ == "__main__":
    unittest.main()
