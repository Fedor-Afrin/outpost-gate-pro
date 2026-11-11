"""HTTP-клиент API роутера для CLI (стандартная библиотека, без зависимостей)."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class ApiError(Exception):
    pass


class Api:
    def __init__(self, base: str | None = None, token: str | None = None):
        self.base = base or os.getenv("OG_API") or f"http://127.0.0.1:{os.getenv('API_PORT', '8000')}"
        self.token = token or os.getenv("OG_TOKEN") or self._local_token()

    @staticmethod
    def _local_token() -> str | None:
        """`outpost` в консоли контейнера: root внутри контейнера и так управляет всем — выдаём токен сами."""
        if os.geteuid() != 0:
            return None
        try:
            from app.core import auth
            name = os.getenv("OG_USER") or next(u["name"] for u in auth.list_users() if u["role"] == "full")
            return auth.make_token(name, ttl=12 * 3600)
        except Exception:
            return None

    def call(self, method: str, path: str, body=None, raw: bool = False):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.base + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read()).get("detail")
            except ValueError:
                detail = e.reason
            if isinstance(detail, list):
                detail = "; ".join(d.get("msg", str(d)) for d in detail)
            raise ApiError(str(detail)) from e
        except urllib.error.URLError as e:
            raise ApiError(f"API недоступен ({self.base}): {e.reason}") from e
        if raw:
            return data.decode()
        return json.loads(data) if data else None

    def get(self, path):
        return self.call("GET", path)

    def post(self, path, body=None):
        return self.call("POST", path, body if body is not None else {})

    def put(self, path, body):
        return self.call("PUT", path, body)

    def patch(self, path, body):
        return self.call("PATCH", path, body)

    def delete(self, path):
        return self.call("DELETE", path)
