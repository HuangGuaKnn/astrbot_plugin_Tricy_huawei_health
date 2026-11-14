"""Cold-start failures remain bounded through CDP and the tool entry point."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import boot
import pytest

boot.install_paths()
import hw_auth


class FakeSocket:
    def __init__(self, clock, send_time, replies):
        self.clock = clock
        self.send_time = send_time
        self.replies = iter(replies)
        self.timeout = 3
        self.send_called = False
        self.operations = []

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout

    def send(self, raw):
        self.send_called = True
        self.request_id = json.loads(raw)["id"]
        self.operations.append(("send", self.timeout))
        self._advance(self.send_time)

    def recv(self):
        self.operations.append(("recv", self.timeout))
        elapsed, matching = next(self.replies)
        self._advance(elapsed)
        return json.dumps({"id": self.request_id if matching else 0, "result": {}})

    def _advance(self, elapsed):
        self.clock[0] += min(self.timeout, elapsed)
        if elapsed > self.timeout:
            raise TimeoutError("synthetic socket timeout")


def make_auth():
    auth = object.__new__(hw_auth.HuaweiAuth)
    auth.page_timeout = 90
    return auth


def test_deadline_counts_send_and_unsolicited_events():
    clock = [0]
    ws = FakeSocket(clock, send_time=0.25, replies=[(0.25, False), (0.9, True)])
    with patch.object(hw_auth.time, "monotonic", side_effect=lambda: clock[0]):
        with pytest.raises(hw_auth.HuaweiAuthDeadline):
            make_auth()._call(ws, "Page.navigate", deadline=1)
    assert ws.operations == [("send", 1), ("recv", 0.75), ("recv", 0.5)]
    assert clock[0] == 1
    assert ws.timeout == 3


def test_deadline_already_expired_never_sends_request():
    clock = [1]
    ws = FakeSocket(clock, send_time=0, replies=[])
    with patch.object(hw_auth.time, "monotonic", side_effect=lambda: clock[0]):
        with pytest.raises(hw_auth.HuaweiAuthDeadline):
            make_auth()._call(ws, "Runtime.evaluate", deadline=1)
    assert not ws.send_called
    assert ws.timeout == 3


def test_deadline_browser_replies_in_time():
    clock = [0]
    ws = FakeSocket(clock, send_time=0.25, replies=[(0.25, True)])
    with patch.object(hw_auth.time, "monotonic", side_effect=lambda: clock[0]):
        assert make_auth()._call(ws, "Runtime.evaluate", deadline=1)["result"] == {}
    assert ws.timeout == 3


def test_wronghost_does_not_launch_cookie_authentication():
    main = boot.load_main()
    plugin = boot.make_plugin(main)
    plugin.login_manager.set_login_mode("password")
    Path(plugin.cookie_file).write_text("[]", encoding="utf-8")
    session = SimpleNamespace(
        failure_code="wronghost",
        snapshot=lambda: {"state": "FAILED", "message": "页面跳转到了非华为域名"},
    )
    plugin._fetch_auth = AsyncMock(side_effect=AssertionError("cookie fallback must not run"))

    async def query():
        try:
            with pytest.raises(main.HuaweiAuthError) as error:
                await plugin._token()
            assert error.value.code == "wronghost"
            plugin._fetch_auth.assert_not_awaited()
        finally:
            await plugin.terminate()

    with patch.object(plugin.login_manager, "start"), patch.object(
            plugin.login_manager, "current_session", return_value=session):
        asyncio.run(query())
