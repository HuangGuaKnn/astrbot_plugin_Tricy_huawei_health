# -*- coding: utf-8 -*-
"""Stub of ``astrbot.api.event``."""


class AstrMessageEvent:
    def __init__(self, message="", sender="", session_id=""):
        self.message_str = message
        self.sender = sender
        self.session_id = session_id


class _Filter:
    """Records registered LLM tools so tests can compare against the README."""

    def __init__(self):
        self.llm_tools = {}

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
