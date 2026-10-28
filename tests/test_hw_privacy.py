# -*- coding: utf-8 -*-
"""hw_privacy.redact_error 单元测试

覆盖派活单 §5 T1 要求的 11 条脱敏规则，外加复合命中、空输入、非字符串对象、
幂等性，以及一处「落地改造」集成断言（hw_client 的 HTTP 错误文本）。

样本一律是**假凭据**：账户段用 ``<account>`` 占位、token 由片段拼出或带
``example`` / ``dummy`` 标记，仓库里不出现任何真实凭据、也不出现本机绝对路径。
"""

import os
import sys
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PLUGIN_DIR = os.environ.get("HW_AUDIT_PLUGIN_DIR") or _REPO_ROOT
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

import hw_privacy  # noqa: E402

redact_error = hw_privacy.redact_error

#: 真实格式的假凭据（不是任何真实 token / 不是任何真实账户）。
FAKE_GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"  # 40 位
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".c2lnbmF0dXJlLWV4YW1wbGU"
)
FAKE_WIN_PATH = r"C:\Users\<account>\.astrbot\data\plugin_data\demo\hw_cookies.json"
FAKE_UNC_PATH = "\\\\fileserver\\share\\demo\\hw_cookies.json"
FAKE_POSIX_PATH = "/home/example/.config/huawei/cookies.json"
FAKE_COOKIE_PAIR = "CASTGC=TGT-123456-example; sid=example-sid"


class TestRule1HeaderLines(unittest.TestCase):
    """规则 1：请求头整行 → ``名称: ***``。"""

    def test_authorization_header_line(self):
        out = redact_error("Authorization: Bearer " + FAKE_JWT)
        self.assertIn("Authorization: ***", out)
        self.assertNotIn("eyJhbGciOi", out)

    def test_set_cookie_and_cookie_lines(self):
        for header in ("Set-Cookie", "Cookie"):
            out = redact_error("%s: %s" % (header, FAKE_COOKIE_PAIR))
            self.assertIn("%s: ***" % header, out, header)
            self.assertNotIn("TGT-123456-example", out, header)
            self.assertNotIn("example-sid", out, header)

    def test_x_api_key_line(self):
        out = redact_error("X-Api-Key: dummy-key-1234567890")
        self.assertIn("X-Api-Key: ***", out)
        self.assertNotIn("dummy-key-1234567890", out)

    def test_header_inside_longer_text(self):
        out = redact_error("HTTP 400 bad request, Cookie: " + FAKE_COOKIE_PAIR + " 结束")
        self.assertIn("Cookie: ***", out)
        self.assertNotIn("example-sid", out)


class TestRule2AuthScheme(unittest.TestCase):
    """规则 2：``Bearer xxx`` / ``Basic xxx`` → ``authorization=***``。"""

    def test_bearer(self):
        out = redact_error("请求被拒：Bearer dummy-token-abcdef123456")
        self.assertIn("authorization=***", out)
        self.assertNotIn("dummy-token-abcdef123456", out)

    def test_basic(self):
        out = redact_error("Basic ZHVtbXktdXNlcjpkdW1teS1wYXNz")
        self.assertIn("authorization=***", out)
        self.assertNotIn("ZHVtbXktdXNlcjpkdW1teS1wYXNz", out)


class TestRule3SensitiveKeyValues(unittest.TestCase):
    """规则 3：敏感键值对 → ``键=***``。"""

    def test_assignments(self):
        cases = {
            "token=abc123def456": "abc123def456",
            "password=hunter2": "hunter2",
            "passwd=hunter2": "hunter2",
            "pwd=hunter2": "hunter2",
            "secret=abcdef123456": "abcdef123456",
            "ssecurity=xyz789abc": "xyz789abc",
            "api_key=key-1234567890": "key-1234567890",
            "private_key=example-private-key": "example-private-key",
            "uid=1234567890": "1234567890",
            "bot_id=99887766": "99887766",
            "session=abc-session-123": "abc-session-123",
        }
        for raw, secret in cases.items():
            out = redact_error("出错了：" + raw)
            self.assertNotIn(secret, out, raw)
            self.assertIn("***", out, raw)

    def test_quoted_json_style(self):
        out = redact_error('{"token": "abc123def456", "uid": 42}')
        self.assertNotIn("abc123def456", out)
        self.assertIn("***", out)

    def test_huawei_cookie_pairs(self):
        out = redact_error(FAKE_COOKIE_PAIR)
        self.assertNotIn("TGT-123456-example", out)
        self.assertNotIn("example-sid", out)
        self.assertIn("CASTGC=***", out)
        self.assertIn("sid=***", out)


class TestRule4KnownTokenFormats(unittest.TestCase):
    """规则 4：已知 token 格式 → ``***``。"""

    def test_github_personal_token(self):
        self.assertEqual(len(FAKE_GITHUB_TOKEN), 44)  # ghp_ + 40 位
        out = redact_error("clone failed: " + FAKE_GITHUB_TOKEN)
        self.assertNotIn(FAKE_GITHUB_TOKEN, out)
        self.assertNotIn("a1B2c3D4", out)
        self.assertIn("***", out)

    def test_openai_anthropic_stripe(self):
        samples = (
            "sk-" + "exampleOpenAIkey1234567890",
            "sk-ant-" + "example-anthropic-key-123456",
            "sk_live_" + "examplestripekey1234567890",
        )
        for sample in samples:
            out = redact_error("key " + sample + " rejected")
            self.assertNotIn(sample, out, sample)
            self.assertIn("***", out, sample)

    def test_google_aws_slack(self):
        samples = (
            "AIza" + "exampleGoogleApiKey1234567890",
            "AKIA" + "IOSFODNN7EXAMPLE",
            "xoxb-" + "1234567890-example-slack",
        )
        for sample in samples:
            out = redact_error("key " + sample + " rejected")
            self.assertNotIn(sample, out, sample)
            self.assertIn("***", out, sample)

    def test_jwt_and_private_key_block(self):
        out = redact_error("token=" + FAKE_JWT)
        self.assertNotIn("eyJhbGciOi", out)
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEexamplebody\n-----END RSA PRIVATE KEY-----"
        out = redact_error("加载失败：" + pem)
        self.assertNotIn("MIIEexamplebody", out)


class TestRule5Url(unittest.TestCase):
    """规则 5：任意 URL → ``[remote URL]``。"""

    def test_https_url(self):
        out = redact_error("请求 https://health.cloud.huawei.com/TrainingCamp 失败")
        self.assertIn("[remote URL]", out)
        self.assertNotIn("huawei.com", out)

    def test_url_with_userinfo(self):
        out = redact_error("connect https://user:pass@example.com/path?q=1 timed out")
        self.assertNotIn("user:pass", out)
        self.assertNotIn("example.com", out)

    def test_websocket_url(self):
        out = redact_error("CDP 目标地址异常：ws://127.0.0.1:9222/devtools/page/ABC")
        self.assertIn("[remote URL]", out)
        self.assertNotIn("9222", out)


class TestRule6WindowsPaths(unittest.TestCase):
    """规则 6：Windows 绝对路径 → ``[local path]``。"""

    def test_drive_path(self):
        out = redact_error("读取 %s 失败" % FAKE_WIN_PATH)
        self.assertIn("[local path]", out)
        self.assertNotIn("hw_cookies", out)
        self.assertNotIn("plugin_data", out)

    def test_quoted_path_with_spaces(self):
        raw = '"C:\\Program Files\\Some App\\profile\\config.json"'
        out = redact_error("浏览器启动失败：%s" % raw)
        self.assertIn("[local path]", out)
        self.assertNotIn("Some App", out)

    def test_unc_share(self):
        out = redact_error("无法写入 " + FAKE_UNC_PATH)
        self.assertIn("[local path]", out)
        self.assertNotIn("hw_cookies", out)

    def test_oserror_style_message(self):
        raw = "[Errno 13] Permission denied: '%s'" % FAKE_WIN_PATH
        out = redact_error(raw)
        self.assertNotIn("plugin_data", out)
        self.assertIn("[local path]", out)


class TestRule7PosixPaths(unittest.TestCase):
    """规则 7：POSIX 绝对路径 → ``[local path]``。"""

    def test_posix_path(self):
        out = redact_error("open %s failed" % FAKE_POSIX_PATH)
        self.assertIn("[local path]", out)
        self.assertNotIn("cookies.json", out)

    def test_posix_path_in_chinese_text(self):
        out = redact_error("读取 /usr/local/lib/huawei/demo.json 失败")
        self.assertIn("[local path]", out)
        self.assertNotIn("demo.json", out)


class TestRule8Email(unittest.TestCase):
    """规则 8：邮箱 → ``[email]``。"""

    def test_email(self):
        out = redact_error("账号 someone@example.com 登录失败")
        self.assertIn("[email]", out)
        self.assertNotIn("someone@", out)

    def test_email_with_plus_and_subdomain(self):
        out = redact_error("mailto: a.b+c@sub.example.co.uk 无法投递")
        self.assertNotIn("a.b+c@", out)
        self.assertIn("[email]", out)


class TestRule9AstrBotSession(unittest.TestCase):
    """规则 9：AstrBot 会话标识 → ``[session]``。"""

    def test_friend_message_session(self):
        out = redact_error("webchat:FriendMessage:webchat_Knn_7a10475d 报错")
        self.assertIn("[session]", out)
        self.assertNotIn("FriendMessage", out)
        self.assertNotIn("7a10475d", out)

    def test_group_message_session(self):
        out = redact_error("webchat:GroupMessage:group_12345 报错")
        self.assertIn("[session]", out)
        self.assertNotIn("group_12345", out)


class TestRule10ControlChars(unittest.TestCase):
    """规则 10：控制字符 → 空格，连续空白折叠。"""

    def test_control_characters(self):
        out = redact_error("bad\x00value\x1fwith\x7fcontrols")
        self.assertEqual(out, "bad value with controls")

    def test_newlines_and_tabs_collapse(self):
        out = redact_error("第一行\n\n\t第二行  第三行")
        self.assertEqual(out, "第一行 第二行 第三行")


class TestRule11LengthAndEmpty(unittest.TestCase):
    """规则 11：截断到 180 字符；空输入返回异常类型名。"""

    def test_truncated_to_max_length(self):
        out = redact_error("x" * 500)
        self.assertEqual(len(out), hw_privacy.MAX_LENGTH)
        self.assertEqual(hw_privacy.MAX_LENGTH, 180)

    def test_empty_string_returns_type_name(self):
        self.assertEqual(redact_error(""), "str")
        self.assertEqual(redact_error(Exception()), "Exception")

    def test_whitespace_only_returns_type_name(self):
        self.assertEqual(redact_error("   \n\t "), "str")

    def test_empty_exception_with_wrapper_still_safe(self):
        self.assertEqual(redact_error(ValueError()), "ValueError")


class TestBoundaryInputs(unittest.TestCase):
    """非字符串对象 / 怪对象：必须返回字符串且绝不抛。"""

    def test_non_string_objects(self):
        self.assertEqual(redact_error(12345), "12345")
        self.assertEqual(redact_error(None), "None")
        self.assertIsInstance(redact_error({"a": 1}), str)

    def test_broken_str_falls_back_to_type_name(self):
        class Broken:
            def __str__(self):
                raise RuntimeError("boom")

        self.assertEqual(redact_error(Broken()), "Broken")

    def test_exception_with_sensitive_message(self):
        out = redact_error(RuntimeError("token=abc123def456 at " + FAKE_WIN_PATH))
        self.assertNotIn("abc123def456", out)
        self.assertNotIn("plugin_data", out)


class TestCompoundAndIdempotent(unittest.TestCase):
    """多条规则同时命中；洗过的文本再洗一次不变。"""

    def test_all_rules_at_once(self):
        raw = (
            "Authorization: Bearer " + FAKE_JWT + "\n"
            "Cookie: " + FAKE_COOKIE_PAIR + "\n"
            "token=abc123def456 password=hunter2 uid=1234567890\n"
            "gh=" + FAKE_GITHUB_TOKEN + " sk=" + "sk-" + "exampleOpenAIkey1234567890" + "\n"
            "url=https://health.cloud.huawei.com/TrainingCamp\n"
            "path=" + FAKE_WIN_PATH + " posix=" + FAKE_POSIX_PATH + "\n"
            "mail=someone@example.com session=webchat:FriendMessage:webchat_Knn_7a10475d\n"
            "ctrl=\x00\x1f\x7f"
        )
        out = redact_error(raw)
        for leaked in (
            "eyJhbGciOi",
            "TGT-123456-example",
            "example-sid",
            "abc123def456",
            "hunter2",
            "1234567890",
            "a1B2c3D4",
            "exampleOpenAIkey1234567890",
            "huawei.com",
            "plugin_data",
            "cookies.json",
            "someone@",
            "FriendMessage",
            "7a10475d",
            "\x00",
        ):
            self.assertNotIn(leaked, out, leaked)
        self.assertLessEqual(len(out), hw_privacy.MAX_LENGTH)

    def test_idempotent(self):
        raw = "Cookie: %s token=abc123def456 %s" % (FAKE_COOKIE_PAIR, FAKE_WIN_PATH)
        once = redact_error(raw)
        self.assertEqual(redact_error(once), once)

    def test_plain_chinese_message_is_preserved(self):
        raw = "拿不到登录态：自动登录需要你输入手机验证码，请打开 WebUI 控制台完成。"
        self.assertEqual(redact_error(raw), raw)


class TestCallSiteIntegration(unittest.TestCase):
    """落地改造抽查：hw_client 的 HTTP 错误文本必须已经过 redact_error。"""

    def test_http_error_body_is_redacted(self):
        import hw_client

        class FakeResponse:
            status_code = 500
            text = '{"code": 500, "token": "abc123def456", "path": "%s"}' % FAKE_WIN_PATH

        with self.assertRaises(hw_client.HuaweiHealthError) as ctx:
            hw_client.HuaweiHealthClient._handle(FakeResponse())
        message = str(ctx.exception)
        self.assertNotIn("abc123def456", message)
        self.assertNotIn("plugin_data", message)
        self.assertIn("HTTP 500", message)


if __name__ == "__main__":
    unittest.main()
