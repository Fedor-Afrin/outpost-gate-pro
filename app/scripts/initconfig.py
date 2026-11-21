"""Начальный router.yaml для установки на сервер (install.sh запускает это внутри образа).

  python3 -m app.scripts.initconfig '<json>'  > router.yaml

JSON: {"identity": "office", "timezone": "Asia/Jerusalem",
       "wan":  {"interface": "eth0", "mode": "none|dhcp|static", "address": ..., "gateway": ..., "dns": [...]},
       "wan2": {...} или null,
       "lan":  {"address": "192.168.1.1/24", "ports": ["eth1", "eth2"], "wan_management": true}}
Конфиг собирается теми же моделями, что и API, и проверяется целиком — ошибка — код 2 и текст в stderr.
"""
from __future__ import annotations

import json
import sys

import yaml


def build(p: dict) -> dict:
    from app.models.lan import LanConfig
    from app.models.wan import Wan2Config, WanConfig
    from app.services.system import validate_config

    data: dict = {"system": {"identity": p.get("identity") or "outpost-gate-pro"}}
    data["wan"] = WanConfig(**p["wan"]).to_yaml()
    if p.get("wan2"):
        data["wan2"] = Wan2Config(enabled=True, **p["wan2"]).to_yaml()
        data["multiwan"] = {"mode": p.get("multiwan_mode") or "failover", "primary": "wan1"}
    lan_p = p.get("lan") or {}
    lan = LanConfig(id="lan1", name="LAN", enabled=bool(lan_p.get("ports") or lan_p.get("auto")),
                    address=lan_p.get("address") or "192.168.1.1/24", ports=lan_p.get("ports") or [],
                    wan_management=bool(lan_p.get("wan_management", True)))
    lan_yaml, fw = lan.to_yaml()
    data["lan"] = lan_yaml
    data["firewall"] = fw
    if p.get("timezone"):
        data["ntp"] = {"enabled": False, "timezone": p["timezone"]}
    validate_config(data)
    return data


def main(argv: list[str]) -> int:
    try:
        data = build(json.loads(argv[1]))
    except Exception as e:  # noqa: BLE001 — понятный текст для install.sh
        errs = getattr(e, "errors", None)
        msg = "; ".join(str(x.get("msg", "")).removeprefix("Value error, ") for x in errs()) if callable(errs) \
            else getattr(e, "message", None) or str(e)
        print(f"invalid parameters: {msg}", file=sys.stderr)
        return 2
    sys.stdout.write("# created by install.sh; from now on change the settings in the web UI\n")
    sys.stdout.write(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
