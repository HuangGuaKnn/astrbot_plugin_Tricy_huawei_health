# -*- coding: utf-8 -*-
"""Stub of ``astrbot.api.star``."""


class Context:
    def __init__(self):
        self.web_apis = []

    def register_web_api(self, route, handler, methods, desc=""):
        self.web_apis.append({
            "route": route, "handler": handler, "methods": list(methods), "desc": desc,
        })


class Star:
    def __init__(self, context):
        self.context = context


def register(name, author, desc, version, *args, **kwargs):
    def deco(cls):
        cls.__plugin_meta__ = {
            "name": name, "author": author, "desc": desc, "version": version,
        }
        return cls

    return deco


__all__ = ["Context", "Star", "register"]
