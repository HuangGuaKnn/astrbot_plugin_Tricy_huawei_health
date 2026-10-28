# -*- coding: utf-8 -*-
"""Stub of ``astrbot.api.event``."""


class AstrMessageEvent:
    def __init__(self, message="", sender="", session_id=""):
        self.message_str = message
        self.sender = sender
        self.session_id = session_id
        # --- T7 权限相关，与真实 AstrBot 的 AstrMessageEvent 对齐（纯新增）---
        # 默认「管理员 + 私聊」：既有 178 条用例里有 7 处直接
        # plugin.health_xxx(None) / 不设权限地调用工具，默认值保证它们语义不变。
        # 权限相关测试请显式设置 _admin / _private / _umo。
        self._umo = ""
        self._admin = True
        self._private = True

    @property
    def unified_msg_origin(self):
        return self._umo

    @unified_msg_origin.setter
    def unified_msg_origin(self, value):
        self._umo = value or ""

    def get_sender_id(self):
        return self.sender or ""

    def is_admin(self):
        return self._admin

    def is_private_chat(self):
        return self._private


class _Filter:
    """Records registered LLM tools so tests can compare against the README."""

    def __init__(self):
        self.llm_tools = {}
        # T7：on_llm_request 的注册结果，测试用它拿到插件注册的闸门函数。
        self.on_llm_request_handlers = []

    def llm_tool(self, *args, **kwargs):
        name = kwargs.get("name")

        def deco(func):
            func.__llm_tool__ = True
            func.__llm_tool_name__ = name or getattr(func, "__name__", "")
            self.llm_tools[func.__llm_tool_name__] = func
            return func

        if len(args) == 1 and callable(args[0]) and not kwargs:
            return deco(args[0])
        return deco

    def on_llm_request(self, *args, **kwargs):
        """T7：``@filter.on_llm_request()`` 的桩，行为与真实 AstrBot 一致（返回原函数）。"""

        def deco(func):
            func.__on_llm_request__ = True
            self.on_llm_request_handlers.append(func)
            return func

        if len(args) == 1 and callable(args[0]) and not kwargs:
            return deco(args[0])
        return deco

    def command(self, *args, **kwargs):
        def deco(func):
            return func

        return deco

    def event_message_type(self, *args, **kwargs):
        def deco(func):
            return func

        return deco


filter = _Filter()

__all__ = ["AstrMessageEvent", "filter"]
