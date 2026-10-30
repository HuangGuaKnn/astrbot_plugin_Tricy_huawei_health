"""Browser launcher exits are not proof that the actual browser failed to start."""

from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import boot

boot.install_paths()
import hw_auth


class PollingClock:
    """Advance polling time without waiting for a real browser or a long timeout."""

    def __init__(self, after_sleep=None):
        self.now = 0.0
        self.sleeps = []
        self.after_sleep = after_sleep

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds
        if self.after_sleep is not None:
            self.after_sleep()


class DevToolsLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="health-devtools-launcher-")
        self.addCleanup(self.temp.cleanup)
        self.profile = Path(self.temp.name) / "profile"
        self.profile.mkdir()
        self.port_file = self.profile / "DevToolsActivePort"
        self.launcher = Mock()
        self.launcher.poll.return_value = 0

    def delayed_writer(self, port):
        """Publish only after the reader has observed the initial missing file."""
        waiting, written = threading.Event(), threading.Event()
        errors = []

        def write():
            try:
                if not waiting.wait(2):
                    raise AssertionError("port reader never started waiting")
                self.port_file.write_text("%s\n/devtools/browser/example\n" % port,
                                          encoding="utf-8")
            except Exception as exc:
                errors.append(exc)
            finally:
                written.set()

        writer = threading.Thread(target=write, daemon=True)
        writer.start()

        def finish():
            waiting.set()
            writer.join(3)
            self.assertFalse(writer.is_alive(), "port writer did not finish")
            if errors:
                raise errors[0]

        self.addCleanup(finish)

        def wait_for_file(_seconds):
            waiting.set()
            if not written.wait(2):
                raise AssertionError("delayed port file was not published")

        return wait_for_file

    def test_exited_launcher_still_waits_for_delayed_port_file(self):
        wait_for_file = self.delayed_writer(32123)
        with patch.object(hw_auth.time, "sleep", side_effect=wait_for_file) as sleep:
            port = hw_auth.read_devtools_port(str(self.profile), timeout=3,
                                              proc=self.launcher)
        self.assertEqual(port, 32123)
        sleep.assert_called_once_with(0.1)
        self.launcher.poll.assert_not_called()

    def test_fetch_token_clears_stale_port_and_accepts_exited_launcher(self):
        self.port_file.write_text("12345\n/stale-browser\n", encoding="utf-8")
        cookie_file = Path(self.temp.name) / "test-cookies.json"
        cookie_file.write_text(json.dumps([
            {"name": "sid", "value": "example-session", "domain": ".huawei.com"},
        ]), encoding="utf-8")
        auth = hw_auth.HuaweiAuth(str(cookie_file), str(self.profile))
        wait_for_file = self.delayed_writer(32124)

        def launch(*_args, **_kwargs):
            self.assertFalse(self.port_file.exists(), "stale port must be removed before launch")
            return self.launcher

        with ExitStack() as stack:
            stack.enter_context(patch.object(hw_auth, "websocket", Mock()))
            stack.enter_context(patch.object(hw_auth, "find_browser", return_value="fake-browser"))
            popen = stack.enter_context(patch.object(hw_auth.subprocess, "Popen", side_effect=launch))
            stack.enter_context(patch.object(hw_auth.time, "sleep", side_effect=wait_for_file))
            stack.enter_context(patch.object(auth, "_cleanup_orphan_browsers"))
            wait_cdp = stack.enter_context(patch.object(auth, "_wait_cdp"))
            attach = stack.enter_context(patch.object(auth, "_attach", return_value=Mock()))
            stack.enter_context(patch.object(auth, "_call", return_value={}))
            stack.enter_context(patch.object(auth, "_wait_token", return_value="example-token"))
            stack.enter_context(patch.object(auth, "_js", return_value="9999999999"))
            stop = stack.enter_context(patch.object(auth, "_stop_process"))
            self.assertEqual(auth.fetch_token(), "example-token")
        popen.assert_called_once()
        wait_cdp.assert_called_once_with(32124)
        attach.assert_called_once_with(32124)
        stop.assert_called_once_with(self.launcher)
        self.launcher.poll.assert_not_called()

    def test_cancelled_before_wait_does_not_accept_even_a_ready_port(self):
        self.port_file.write_text("32125\n", encoding="utf-8")
        cancel = threading.Event()
        cancel.set()
        clock = PollingClock()
        with patch.object(hw_auth, "time", clock):
            self.assertEqual(hw_auth.read_devtools_port(
                str(self.profile), cancel=cancel, proc=self.launcher), 0)
        self.assertEqual(clock.sleeps, [])

    def test_cancel_during_wait_returns_before_deadline(self):
        cancel = threading.Event()
        clock = PollingClock(after_sleep=cancel.set)
        with patch.object(hw_auth, "time", clock):
            self.assertEqual(hw_auth.read_devtools_port(
                str(self.profile), timeout=40, cancel=cancel, proc=self.launcher), 0)
        self.assertEqual(clock.sleeps, [0.1])

    def test_exited_launcher_without_port_remains_bounded_by_timeout(self):
        for timeout in (0.2, 2.4):
            with self.subTest(timeout=timeout):
                clock = PollingClock()
                with patch.object(hw_auth, "time", clock):
                    self.assertEqual(hw_auth.read_devtools_port(
                        str(self.profile), timeout=timeout, proc=self.launcher), 0)
                self.assertGreaterEqual(clock.now, max(1.0, timeout))
                self.assertLess(clock.now, max(1.0, timeout) + 0.11)
        self.launcher.poll.assert_not_called()

    def test_empty_or_incomplete_port_file_times_out(self):
        for content in ("", "not-a-port\n", "0\n"):
            with self.subTest(content=content):
                self.port_file.write_text(content, encoding="utf-8")
                clock = PollingClock()
                with patch.object(hw_auth, "time", clock):
                    self.assertEqual(hw_auth.read_devtools_port(
                        str(self.profile), timeout=1, proc=self.launcher), 0)
                self.assertGreaterEqual(clock.now, 1)
                self.assertLess(clock.now, 1.11)

    def test_old_port_cleanup_is_idempotent(self):
        self.port_file.write_text("12345\n/stale-browser\n", encoding="utf-8")
        hw_auth.clear_devtools_port_file(str(self.profile))
        self.assertFalse(self.port_file.exists())
        hw_auth.clear_devtools_port_file(str(self.profile))


if __name__ == "__main__":
    unittest.main()
