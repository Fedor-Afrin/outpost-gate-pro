"""Настройки CLI пользователя: синтаксис командной строки (RouterOS или Linux). data/cli-prefs.json."""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

from app.core.config import settings

SYNTAXES = ("routeros", "linux")
LANGS = ("en", "ru", "he")
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
    """{"syntax": "routeros" | "linux" | None, "lang": "en" | "ru" | "he"} — syntax None: ещё не выбирал
    (спросить при входе); язык подсказок по умолчанию — английский."""
    u = _load().get(user) or {}
    return {"syntax": u.get("syntax"), "lang": u.get("lang") or "en"}


def set_syntax(user: str, syntax: str) -> dict:
    return update(user, syntax=syntax)


def update(user: str, syntax: str | None = None, lang: str | None = None) -> dict:
    if syntax is not None and syntax not in SYNTAXES:
        raise ValueError("синтаксис: routeros или linux")
    if lang is not None and lang not in LANGS:
        raise ValueError("язык: en, ru или he")
    with _lock:
        d = _load()
        if syntax is not None:
            d.setdefault(user, {})["syntax"] = syntax
        if lang is not None:
            d.setdefault(user, {})["lang"] = lang
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".cli-prefs.")
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, path)
    return get(user)
