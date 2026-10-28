# -*- coding: utf-8 -*-
"""Minimal stand-in for the real ``astrbot`` package.

Only the surface used by ``astrbot_plugin_huawei_health`` is provided so that
``main.py`` / ``hw_webapi.py`` can be imported and unit-tested outside AstrBot.

This is a *test double*, not a copy of AstrBot.  Findings that depend on real
AstrBot behaviour (auth on register_web_api, tool timeouts, config injection)
must be marked as "needs platform verification" in the report.
"""

__all__ = ["api", "core"]
