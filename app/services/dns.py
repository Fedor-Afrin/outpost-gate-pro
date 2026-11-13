"""
DNS-сервер BIND 9: рекурсия и кэш для сегментов LAN плюс свои зоны.

router.yaml (секция dns:) — источник правды. Роутер генерирует named.conf и файлы зон
целиком, проверяет их (named-checkconf, named-checkzone) и применяет без перезапуска (SIGHUP).

Имена из DHCP: устройства сегмента с доменом office.lan попадают в зону office.lan
(router.office.lan, laptop.office.lan…). Роутер раз в 15 секунд сверяет аренды Kea и
закреплённые адреса с зонами и при изменениях переписывает их — без DDNS-ключей и журналов.
Обратные зоны (…in-addr.arpa) сами получают PTR для всех A-записей из своей сети.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from app.core.config import settings
from app.core.process import ManagedProcess
from app.core.store import store
from app.models.dns import (DnsConfig, DnsName, DnsRecord, DnsStatus, DnsZone, ZoneInfo,
                            default_config, reverse_network)
from app.models.lan import HOSTNAME_RE

NAMED = "named"
_named = ManagedProcess("named")
_lock = threading.RLock()
_watch: threading.Thread | None = None
_last_auto = ""


class DnsError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def zone_dir() -> Path:
    return Path(settings.data_dir) / "bind"


# --- конфиг ----------------------------------------------------------------------------------
def get_config() -> DnsConfig:
    raw = store.load().get("dns")
    return default_config() if raw is None else DnsConfig.model_validate(raw)


def ensure_zone(domain: str | None) -> None:
    """Сегменту LAN назначили домен, которого нет среди зон, — создать зону (имена из DHCP)."""
    if not domain:
        return
    cfg = get_config()
    if cfg.zone(domain):
        return
    cfg.zones.append(DnsZone(name=domain))
    with store.transaction() as data:
        data["dns"] = cfg.to_yaml()
    print(f"[dns] создана зона {domain} для сегмента LAN")


# --- что знает роутер о сети ---------------------------------------------------------------
def _segments():
    from app.services import lan
    return lan.segments()


def _active_segments():
    from app.services import lan
    return [s for s in lan.segments() if s.enabled and lan.segment_active(s)]


def upstream(cfg: DnsConfig) -> list[str]:
    if cfg.forwarders:
        return cfg.forwarders
    from app.services import wan
    try:
        lines = wan.resolv_file().read_text().splitlines()
    except OSError:
        return []
    out = []
    for l in lines:
        p = l.split()
        if len(p) >= 2 and p[0] == "nameserver":
            try:
                ip = ipaddress.ip_address(p[1])
            except ValueError:
                continue
            if not ip.is_loopback:
                out.append(str(ip))
    return out


def auto_names(cfg: DnsConfig, segments=None, leases=None, static=None) -> list[DnsName]:
    """Имена, которые роутер добавляет в зоны сам: router и устройства из DHCP."""
    from app.services import lan
    segments = segments if segments is not None else [s for s in _segments() if s.enabled]
    leases = leases if leases is not None else lan.leases()
    static = static if static is not None else {s.id: lan.static_leases(s.id) for s in segments}
    out: list[DnsName] = []
    for z in cfg.zones:
        if z.reverse:
            continue
        taken = {r.name.lower() for r in z.records}
        used = set()

        def add(name: str, ip: str, source: str):
            n = name.lower()
            if n in taken or n in used or not HOSTNAME_RE.match(name):
                return
            used.add(n)
            out.append(DnsName(zone=z.name, name=n, type="A", value=ip, source=source))

        segs = [s for s in segments if s.domain == z.name]
        for s in segs:
            add("router", s.router_ip, "router")
            add("ns", s.router_ip, "router")
        if not z.dhcp_names:
            continue
        for s in segs:
            for st in static.get(s.id, []):
                if st.name and ipaddress.ip_address(st.ip) in s.network:
                    add(st.name, st.ip, "static-lease")
        for l in leases:
            seg = next((s for s in segs if ipaddress.ip_address(l.ip) in s.network), None)
            if seg and l.hostname:
                add(l.hostname, l.ip, "dhcp")
    # PTR в обратные зоны
    a_records = [(z.name, r.name, r.value) for z in cfg.zones if not z.reverse for r in z.records if r.type == "A"]
    a_records += [(n.zone, n.name, n.value) for n in out if n.type == "A"]
    for z in cfg.zones:
        net = reverse_network(z.name) if z.reverse and z.auto_ptr else None
        if not net:
            continue
        explicit = {r.name for r in z.records if r.type == "PTR"}
        seen = set()
        for zone, name, ip in a_records:
            addr = ipaddress.ip_address(ip)
            if addr not in net:
                continue
            label = ".".join(reversed(str(addr).split(".")[net.prefixlen // 8:]))
            if label in explicit or label in seen:
                continue
            seen.add(label)
            fqdn = (zone if name == "@" else f"{name}.{zone}") + "."
            out.append(DnsName(zone=z.name, name=label, type="PTR", value=fqdn, source="ptr"))
    return out


# --- генерация файлов -----------------------------------------------------------------------
def zone_file(zone: DnsZone, auto: list[DnsName], serial: int, ns_ip: str | None) -> str:
    ns = f"ns.{zone.name}." if not zone.reverse else "localhost."
    lines = [f"; generated by OutpostGate Pro - do not edit by hand",
             f"$ORIGIN {zone.name}.", f"$TTL {zone.ttl}",
             f"@ IN SOA {ns} hostmaster.{zone.name}. ( {serial} 3600 600 604800 300 )",
             f"@ IN NS {ns}"]
    names = {r.name.lower() for r in zone.records}
    if not zone.reverse and "ns" not in names and not any(a.name == "ns" for a in auto):
        lines.append(f"ns IN A {ns_ip or '127.0.0.1'}")
    for r in zone.records:
        ttl = f" {r.ttl}" if r.ttl is not None else ""
        comment = f" ; {r.comment}" if r.comment else ""
        lines.append(f"{r.name}{ttl} IN {r.type} {r.rdata()}{comment}")
    for a in auto:
        lines.append(f"{a.name} IN {a.type} {a.value} ; auto: {a.source}")
    return "\n".join(lines) + "\n"


def named_conf(cfg: DnsConfig, listen: list[str], trusted: list[str], forwarders: list[str],
               directory: str) -> str:
    acl = "; ".join(["127.0.0.0/8", *trusted]) + ";"
    fwd = ""
    if forwarders:
        fwd = (f"    forwarders {{ {'; '.join(forwarders)}; }};\n"
               f"    forward {'only' if cfg.forward_only else 'first'};\n")
    zones = "".join(
        f'zone "{z.name}" {{\n    type primary;\n    file "{directory}/db.{z.name}";\n'
        f"    allow-query {{ trusted; }};\n    allow-transfer {{ none; }};\n}};\n\n"
        for z in cfg.zones)
    return f"""// generated by OutpostGate Pro - do not edit by hand
acl trusted {{ {acl} }};

options {{
    directory "{directory}";
    pid-file none;
    listen-on port 53 {{ {'; '.join(['127.0.0.1', *listen])}; }};
    listen-on-v6 {{ none; }};
    allow-query {{ trusted; }};
    recursion yes;
    allow-recursion {{ trusted; }};
    allow-transfer {{ none; }};
{fwd}    dnssec-validation {'auto' if cfg.dnssec else 'no'};
    max-cache-size {cfg.cache_mb}m;
    version none;
    hostname none;
    server-id none;
    interface-interval 1;
}};

logging {{
    channel console {{ stderr; severity info; print-time yes; print-category yes; }};
    category default {{ console; }};
    category lame-servers {{ null; }};
}};

{zones}"""


def _serials() -> dict:
    try:
        return json.loads((zone_dir() / "serials.json").read_text())
    except (OSError, ValueError):
        return {}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def _check(cmd: list[str], what: str) -> None:
    if not shutil.which(cmd[0]):
        return
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        msg = " ".join((r.stdout + r.stderr).split())[-400:]
        raise DnsError(400, f"{what}: {msg}")


def render(cfg: DnsConfig, segments, auto: list[DnsName], directory: Path) -> dict[Path, str]:
    """Все файлы BIND: {путь: текст}. Серийный номер зоны растёт только при изменении."""
    active = [s for s in segments if s.enabled]
    listen = [s.router_ip for s in active if s.dns_enabled]
    trusted = [str(s.network) for s in active] + cfg.allow
    files = {directory / "named.conf": named_conf(cfg, listen, trusted, upstream(cfg), str(directory))}
    serials = _serials()
    new_serials = {}
    for z in cfg.zones:
        za = [a for a in auto if a.zone == z.name]
        ns_ip = next((s.router_ip for s in active if s.domain == z.name), active[0].router_ip if active else None)
        body = zone_file(z, za, 0, ns_ip)
        digest = hashlib.sha1(body.encode()).hexdigest()
        old = serials.get(z.name, {})
        serial = old.get("serial", 0)
        if old.get("digest") != digest:
            serial = max(serial + 1, int(time.time()))
        new_serials[z.name] = {"serial": serial, "digest": digest}
        files[directory / f"db.{z.name}"] = zone_file(z, za, serial, ns_ip)
    files[directory / "serials.json"] = json.dumps(new_serials, indent=1)
    return files


# --- процесс ---------------------------------------------------------------------------------
def installed() -> bool:
    return shutil.which(NAMED) is not None


def running() -> bool:
    return _named.running()


def apply(cfg: DnsConfig | None = None) -> None:
    """Записать named.conf и зоны, проверить и применить (запуск / SIGHUP / остановка)."""
    global _last_auto
    cfg = cfg or get_config()
    with _lock:
        segments = _segments()
        serving = [s for s in segments if s.enabled and s.dns_enabled]
        if not serving:
            if _named.running():
                _named.stop()
                print("[dns] DNS не включён ни на одном LAN — BIND остановлен")
            return
        if not installed():
            raise DnsError(500, "нет BIND 9 в образе — пересоберите образ (docker compose build)")
        auto = auto_names(cfg)
        files = render(cfg, segments, auto, zone_dir())
        # проверка во временной папке, потом — на место
        with tempfile.TemporaryDirectory() as tmpd:
            tmp = Path(tmpd)
            tfiles = render(cfg, segments, auto, tmp)
            for p, text in tfiles.items():
                p.write_text(text)
            _check(["named-checkconf", str(tmp / "named.conf")], "BIND: ошибка в настройках")
            for z in cfg.zones:
                _check(["named-checkzone", "-q", z.name, str(tmp / f"db.{z.name}")], f"зона {z.name}")
        for p, text in files.items():
            _write(p, text)
        _last_auto = _auto_digest(auto)
        if _named.running():
            _named.signal(signal.SIGHUP)
        else:
            _named.start([NAMED, "-f", "-c", str(zone_dir() / "named.conf")])
        _start_watch()


def update(new: DnsConfig) -> DnsStatus:
    old = store.load().get("dns")
    with store.transaction() as data:
        data["dns"] = new.to_yaml()
    try:
        apply(new)
    except DnsError:
        with store.transaction() as data:
            if old is None:
                data.pop("dns", None)
            else:
                data["dns"] = old
        try:
            apply()
        except DnsError as e:
            print(f"[dns] ERROR: откат не удался: {e.message}")
        raise
    from app.services import dhcp, lan
    try:
        lan.reload_dhcp()          # домены сегментов в DHCP (domain-name, search) могли измениться
    except dhcp.DhcpError as e:
        print(f"[dns] WARNING: DHCP: {e.message}")
    return status()


def on_upstream_changed() -> None:
    """WAN или VPN поменяли DNS провайдера — обновить forwarders (если они «авто»)."""
    if not _named.running():
        return
    try:
        if not get_config().forwarders:
            apply()
    except DnsError as e:
        print(f"[dns] WARNING: {e.message}")


def _auto_digest(auto: list[DnsName]) -> str:
    return hashlib.sha1(json.dumps([a.model_dump() for a in auto], sort_keys=True).encode()).hexdigest()


def _watch_loop() -> None:
    while _named.running():
        time.sleep(15)
        try:
            cfg = get_config()
            if _auto_digest(auto_names(cfg)) != _last_auto:
                apply(cfg)
                print("[dns] имена из DHCP обновлены")
        except Exception as e:  # наблюдатель не должен падать
            print(f"[dns] WARNING: обновление имён: {e}")


def _start_watch() -> None:
    global _watch
    if _watch and _watch.is_alive():
        return
    _watch = threading.Thread(target=_watch_loop, name="dns-dhcp-names", daemon=True)
    _watch.start()


def apply_startup() -> None:
    try:
        apply()
    except DnsError as e:
        print(f"[dns] ERROR: {e.message}")


def stop() -> None:
    _named.stop()


# --- состояние -------------------------------------------------------------------------------
def status() -> DnsStatus:
    cfg = get_config()
    segments = _segments()
    try:
        auto = auto_names(cfg)
    except Exception:
        auto = []
    serials = _serials()
    zones = []
    for z in cfg.zones:
        zones.append(ZoneInfo(
            name=z.name, reverse=z.reverse, records=len(z.records),
            dhcp_names=sum(1 for a in auto if a.zone == z.name and a.source in ("dhcp", "static-lease")),
            segments=[s.id for s in segments if s.enabled and s.domain == z.name],
            serial=serials.get(z.name, {}).get("serial")))
    st = DnsStatus(config=cfg, installed=installed(), running=running(), zones=zones, auto_names=auto,
                   forwarders=upstream(cfg),
                   listen=[s.router_ip for s in segments if s.enabled and s.dns_enabled],
                   segments=[{"id": s.id, "name": s.name, "domain": s.domain, "dns_enabled": s.dns_enabled,
                              "enabled": s.enabled, "network": str(s.network)} for s in segments])
    if not st.installed and st.listen:
        st.error = "нет BIND 9 в образе — пересоберите образ (docker compose build)"
    elif st.listen and not st.running:
        st.error = "BIND не запущен — см. docker logs"
    return st
