"""Настройки CLI пользователя: синтаксис командной строки (RouterOS или Linux). data/cli-prefs.json."""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

from app.core.config import settings

SYNTAXES = ("routeros", "linux")
_lock = threading.Lock()


def _path() -> Path:
    return Path(settings.data_dir) / "cli-prefs.json"


def _load() -> dict:
    try:
        d = json.loads(_path().read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def get(user: str) -> dict:
    """{"syntax": "routeros" | "linux" | None} — None: ещё не выбирал (спросить при входе)."""
    return {"syntax": (_load().get(user) or {}).get("syntax")}


def set_syntax(user: str, syntax: str) -> dict:
    if syntax not in SYNTAXES:
        raise ValueError("синтаксис: routeros или linux")
    with _lock:
        d = _load()
        d.setdefault(user, {})["syntax"] = syntax
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".cli-prefs.")
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, path)
    return get(user)
