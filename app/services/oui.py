"""Производитель устройства по MAC-адресу (база IEEE OUI из пакета ieee-data)."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

OUI_FILES = [Path("/usr/share/ieee-data/oui.txt")]
LINE_RE = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$")


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    for path in OUI_FILES:
        try:
            with path.open(encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = LINE_RE.match(line)
                    if m:
                        table[m.group(1).replace("-", ":")] = m.group(2)
        except OSError:
            continue
    return table


def vendor(mac: str) -> str | None:
    mac = mac.upper()
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return None
    if first & 0x02:  # бит «локально назначенный»: телефоны и ноутбуки с приватным MAC
        return "случайный MAC (приватный адрес)"
    return _table().get(mac[:8])
