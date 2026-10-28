# -*- coding: utf-8 -*-
"""Stub of ``astrbot.api.web``."""

import json as _json


def json_response(payload=None, status_code=200):
    """Real implementation returns a Quart response; a tuple keeps it inspectable."""
    return {"payload": payload, "status_code": status_code}


class _Request:
    """Set ``request.body`` before awaiting ``request.json()``."""

    def __init__(self):
        self.body = b"{}"

    async def json(self):
        if isinstance(self.body, (dict, list)):
            return self.body
        return _json.loads(self.body)


request = _Request()

__all__ = ["json_response", "request"]
