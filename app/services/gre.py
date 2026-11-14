"""
VPN → GRE: туннели «роутер — роутер» (как interface Tunnel в Cisco).

  ip link add gre1 type gre remote 10.8.1.3 local 10.8.1.2 ttl 64
  ip addr add 172.16.0.1/30 dev gre1; ip link set gre1 mtu 1380 up
  ip route replace 192.168.20.0/24 dev gre1 proto static metric 20      — «Сети за вторым роутером»
  ip route replace 10.8.1.3/32 dev awg0 metric 5                         — underlay: ко второму роутеру через туннель

Пакеты GRE (протокол 47) между 10.8.1.2 и 10.8.1.3 для сервера AmneziaWG — обычный трафик между двумя
клиентами, а внутри GRE ходят любые сети. OSPF по галочке: туннель добавляется в «Маршрутизацию»
как point-to-point (routing.with_gre). Что создал роутер, записано в data/gre.json — убирается ровно своё.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path

from app.core.config import settings
from app.core.store import store
from app.models.gre import GreConfig, GreStatus, GreTunnel, GreTunnelStatus

ROUTE_METRIC = 20          # статические маршруты в GRE
UNDERLAY_METRIC = 5        # /32 ко второму роутеру через туннель (точнее маршрутов full-туннеля 0/1, 128/1)
SYS_NET = Path(os.getenv("OG_SYS_NET", "/sys/class/net"))

_lock = threading.RLock()


class GreError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --- конфиг и состояние ----------------------------------------------------------------------
def get_config(data: dict | None = None) -> GreConfig:
    data = store.load() if data is None else data
    return GreConfig.from_yaml(data.get("gre"))


def _state_path() -> Path:
    return Path(settings.data_dir) / "gre.json"


def load_state() -> dict:
    try:
        return json.loads(_state_path().read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".gre.")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


# --- команды ----------------------------------------------------------------------------------
def ip(*args: str, check: bool = True) -> str:
    """ip … ; ошибка — GreError с текстом ядра. В тестах подменяется."""
    try:
        r = subprocess.run(["ip", *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GreError(500, f"ip {' '.join(args)}: {e}") from e
    if check and r.returncode != 0:
        raise GreError(400, f"ip {' '.join(args)}: {(r.stderr or r.stdout).strip()}")
    return r.stdout


def _json(*args: str):
    try:
        return json.loads(ip("-j", *args, check=False) or "[]")
    except ValueError:
        return []


def existing() -> dict[str, dict]:
    """GRE-интерфейсы в системе: имя -> {local, remote, ttl, up, addresses}. gre0 ядра пропускаем."""
    out = {}
    for link in _json("-d", "address", "show", "type", "gre"):
        name = link.get("ifname", "").split("@")[0]
        if not name or name == "gre0":
            continue
        info = (link.get("linkinfo") or {}).get("info_data") or {}
        out[name] = {
            "local": None if info.get("local") in (None, "any", "0.0.0.0") else info.get("local"),
            "remote": info.get("remote"),
            "ttl": info.get("ttl"),
            "up": "UP" in (link.get("flags") or []),
            "mtu": link.get("mtu"),
            "addresses": [f"{a['local']}/{a['prefixlen']}" for a in link.get("addr_info") or []
                          if a.get("family") == "inet"],
        }
    return out


def _routes_on(dev: str) -> list[str]:
    return [r["dst"] for r in _json("route", "show", "dev", dev, "proto", "static") if r.get("dst")]


def _iface_exists(name: str) -> bool:
    return (SYS_NET / name).exists()


def _bytes(name: str) -> tuple[int, int]:
    def read(what):
        try:
            return int((SYS_NET / name / "statistics" / what).read_text())
        except (OSError, ValueError):
            return 0
    return read("rx_bytes"), read("tx_bytes")


# --- применение -------------------------------------------------------------------------------
def _same(cur: dict, t: GreTunnel) -> bool:
    ttl = cur.get("ttl")
    return cur.get("remote") == t.remote and cur.get("local") == t.local and (ttl in (None, 0) or ttl == t.ttl)


def _bring_up(t: GreTunnel, cur: dict | None) -> None:
    if cur and not _same(cur, t):
        ip("link", "del", t.name)
        cur = None
    if cur is None:
        args = ["link", "add", t.name, "type", "gre", "remote", t.remote]
        if t.local:
            args += ["local", t.local]
        ip(*args, "ttl", str(t.ttl))
    ip("link", "set", t.name, "mtu", str(t.mtu), "up")
    have = (cur or {}).get("addresses") or []
    for a in have:
        if a != t.address:
            ip("addr", "del", a, "dev", t.name, check=False)
    if t.address not in have:
        ip("addr", "add", t.address, "dev", t.name)
    want = set(t.routes)
    for r in _routes_on(t.name):
        if r not in want:
            ip("route", "del", r, "dev", t.name, "proto", "static", check=False)
    for r in t.routes:
        ip("route", "replace", r, "dev", t.name, "proto", "static", "metric", str(ROUTE_METRIC))


def _underlay_up(t: GreTunnel) -> bool:
    """/32 ко второму роутеру через underlay. False — интерфейса underlay пока нет (туннель не поднят)."""
    if not t.underlay:
        return True
    if not _iface_exists(t.underlay):
        return False
    ip("route", "replace", f"{t.remote}/32", "dev", t.underlay, "metric", str(UNDERLAY_METRIC))
    return True


def _underlay_down(dst: str, dev: str) -> None:
    ip("route", "del", f"{dst}/32", "dev", dev, "metric", str(UNDERLAY_METRIC), check=False)


def apply(cfg: GreConfig | None = None) -> dict[str, str]:
    """Привести GRE к настройкам. -> {туннель: ошибка} (остальные туннели поднимаются всё равно)."""
    cfg = cfg or get_config()
    with _lock:
        state = load_state()
        cur = existing()
        want = {t.name: t for t in cfg.tunnels if t.enabled}
        errors: dict[str, str] = {}

        for name in state.get("managed", []):                 # убрали или выключили — удалить своё
            if name not in want and name in cur:
                ip("link", "del", name, check=False)
                print(f"[gre] {name} удалён")
        for u in state.get("underlay", []):
            t = want.get(u["tunnel"])
            if not t or t.underlay != u["dev"] or t.remote != u["remote"]:
                _underlay_down(u["remote"], u["dev"])

        underlay = []
        for t in want.values():
            try:
                _bring_up(t, cur.get(t.name))
                if t.underlay:
                    if _underlay_up(t):
                        underlay.append({"tunnel": t.name, "remote": t.remote, "dev": t.underlay})
                    else:
                        errors[t.name] = f"нет интерфейса {t.underlay} — включите туннель, поверх которого идёт GRE"
                print(f"[gre] {t.name}: {t.local or 'auto'} → {t.remote}, {t.address}, маршрутов {len(t.routes)}")
            except GreError as e:
                errors[t.name] = e.message
                print(f"[gre] ERROR: {t.name}: {e.message}")
        save_state({"managed": sorted(want), "underlay": underlay, "errors": errors})
        return errors


def watch() -> list[str]:
    """Раз в 10 с (сборщик мониторинга): туннель пропал или underlay появился позже (AmneziaWG
    поднялся после GRE, переподключился) — восстановить. -> что восстановлено."""
    cfg = get_config()
    want = [t for t in cfg.tunnels if t.enabled]
    if not want:
        return []
    fixed = []
    with _lock:
        cur = existing()
        for t in want:
            missing = t.name not in cur
            no_underlay = bool(t.underlay) and _iface_exists(t.underlay) and not _json(
                "route", "show", f"{t.remote}/32", "dev", t.underlay)
            if missing or no_underlay:
                fixed.append(t.name)
    if fixed:
        apply(cfg)
        print(f"[gre] восстановлено: {', '.join(fixed)}")
    return fixed


def teardown() -> None:
    with _lock:
        state = load_state()
        for u in state.get("underlay", []):
            _underlay_down(u["remote"], u["dev"])
        for name in state.get("managed", []):
            ip("link", "del", name, check=False)
        save_state({})


def apply_startup() -> None:
    try:
        apply()
    except Exception as e:  # noqa: BLE001
        print(f"[gre] ERROR: {e}")


def update(new: GreConfig) -> GreStatus:
    from app.services import firewall, routing
    old = get_config()
    with store.transaction() as data:
        data["gre"] = new.to_yaml()
    try:
        apply(new)
    except GreError:
        with store.transaction() as data:
            data["gre"] = old.to_yaml()
        apply(old)
        raise
    # OSPF: туннели с галочкой — в frr.conf; фаервол: пропустить GRE и транзит LAN ↔ GRE
    if routing.active() or any(t.ospf for t in new.tunnels + old.tunnels):
        try:
            routing.apply()
        except Exception as e:  # noqa: BLE001
            print(f"[gre] WARNING: OSPF: {e}")
    firewall.refresh()
    try:                                     # split-туннель: адрес второго роутера — в AllowedIPs
        from app.services import vpn
        vpn.sync_allowed_ips()
    except Exception as e:  # noqa: BLE001
        print(f"[gre] WARNING: AllowedIPs: {e}")
    return status()


def firewall_rules():
    from app.services.firewall import GreRules
    tunnels = [t for t in get_config().tunnels if t.enabled]
    return GreRules([t.name for t in tunnels], sorted({t.remote for t in tunnels})) if tunnels else None


# --- статус -----------------------------------------------------------------------------------
def underlay_interfaces() -> list[str]:
    try:
        names = sorted(p.name for p in SYS_NET.iterdir())
    except OSError:
        return []
    prefer = ("awg", "wg", "l2tp", "ppp", "tun")
    skip = ("lo", "gre", "gretap", "erspan", "docker", "veth", "br-", "ifb")
    names = [n for n in names if not n.startswith(skip)]
    return sorted(names, key=lambda n: (not n.startswith(prefer), n))


def status() -> GreStatus:
    from app.services import routing
    cfg = get_config()
    state = load_state()
    cur = existing()
    ospf_on = False
    try:
        ospf_on = routing.get_config().ospf.enabled
    except Exception:  # noqa: BLE001
        pass
    out, warnings = [], []
    for t in cfg.tunnels:
        c = cur.get(t.name)
        rx, tx = _bytes(t.name) if c else (0, 0)
        under = None
        if t.underlay and t.enabled:
            under = bool(_json("route", "show", f"{t.remote}/32", "dev", t.underlay))
        out.append(GreTunnelStatus(
            name=t.name, enabled=t.enabled, exists=bool(c), up=bool(c and c["up"]), rx_bytes=rx, tx_bytes=tx,
            underlay_ok=under, peer_hint=t.peer_hint, error=(state.get("errors") or {}).get(t.name)))
        if t.ospf and t.enabled and not ospf_on:
            warnings.append(f"{t.name}: OSPF выключен в «Маршрутизации» — галочка OSPF не действует")
    return GreStatus(config=cfg, tunnels=out, ospf_enabled=ospf_on,
                     interfaces=underlay_interfaces(), warnings=warnings)


def ospf_additions(cfg: GreConfig | None = None) -> list[tuple[GreTunnel, str]]:
    """Туннели с галочкой OSPF: (туннель, сеть внутри GRE) — для routing.with_gre."""
    cfg = cfg or get_config()
    return [(t, t.network) for t in cfg.tunnels if t.enabled and t.ospf]

