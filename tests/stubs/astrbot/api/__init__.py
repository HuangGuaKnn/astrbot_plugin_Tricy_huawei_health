# -*- coding: utf-8 -*-
"""Stub of ``astrbot.api``."""


class AstrBotConfig(dict):
    """Real AstrBotConfig is a dict subclass with schema defaults applied."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class _Logger:
    def __init__(self):
        self.records = []

    def _log(self, level, msg, *a):
        self.records.append((level, msg))

    def debug(self, msg, *a, **k):
        self._log("debug", msg)

    def info(self, msg, *a, **k):
        self._log("info", msg)

    def warning(self, msg, *a, **k):
        self._log("warning", msg)

    def warn(self, msg, *a, **k):
        self._log("warning", msg)

    def error(self, msg, *a, **k):
        self._log("error", msg)

    def exception(self, msg, *a, **k):
        self._log("error", msg)


logger = _Logger()

__all__ = ["AstrBotConfig", "logger"]
