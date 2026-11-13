"""
DHCP-сервер Kea (ISC): один процесс kea-dhcp4 на все сегменты LAN.

Конфиг генерируется целиком из router.yaml (сегменты lan:/lans:, их пулы, опции и
закреплённые адреса), проверяется (kea-dhcp4 -t) и применяется без перезапуска (SIGHUP).
Аренды — файл memfile (CSV) в data/: их читают вкладки DHCP и DNS (имена устройств).
Платные модули Kea не используются.
"""
from __future__ import annotations

import csv
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
from app.models.lan import HOSTNAME_RE, LanConfig, Lease, StaticLease
from app.services import oui

KEA = "kea-dhcp4"
_kea = ManagedProcess("kea-dhcp4")
_lock = threading.RLock()

# опции, которые Kea знает по имени (стандартные определения)
NAMED = {"ntp_servers": "ntp-servers", "wins_servers": "netbios-name-servers"}


class DhcpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _data(name: str) -> Path:
    return Path(settings.data_dir) / name


def leases_file() -> Path:
    return _data("kea-leases4.csv")


def subnet_id(seg: LanConfig) -> int:
    return int(seg.id[3:])          # lan1 -> 1, lan7 -> 7: стабильно при изменениях


def seconds(lease_time: str) -> int:
    return int(lease_time[:-1]) * {"m": 60, "h": 3600, "d": 86400}[lease_time[-1]]


def _raw(code: int, hexdata: str) -> dict:
    return {"code": code, "space": "dhcp4", "csv-format": False, "data": hexdata}


def option_data(seg: LanConfig, upstream_dns: list[str]) -> list[dict]:
    o = seg.dhcp_options
    out = [{"name": "routers", "data": seg.router_ip}]
    dns = o.dns_servers or ([seg.router_ip] if seg.dns_enabled else upstream_dns)
    if dns:
        out.append({"name": "domain-name-servers", "data": ", ".join(dns)})
    if seg.domain:
        out.append({"name": "domain-name", "data": seg.domain})
    search = o.domain_search or ([seg.domain] if seg.domain else [])
    if search:
        out.append({"name": "domain-search", "data": ", ".join(search)})
    for field, name in NAMED.items():
        if getattr(o, field):
            out.append({"name": name, "data": ", ".join(getattr(o, field))})
    if o.time_offset is not None:
        out.append({"name": "time-offset", "data": str(o.time_offset)})
    if o.mtu:
        out.append({"name": "interface-mtu", "data": str(o.mtu)})
    if o.tftp_server:
        out.append({"name": "tftp-server-name", "data": o.tftp_server})
    if o.boot_file:
        out.append({"name": "boot-file-name", "data": o.boot_file})
    # опции без стандартного определения в Kea — готовыми байтами
    if o.tftp_servers_150:
        out.append(_raw(150, "".join(ipaddress.IPv4Address(x).packed.hex() for x in o.tftp_servers_150)))
    if o.sip_servers:      # RFC 3361: первый байт 1 — дальше IPv4-адреса
        out.append(_raw(120, "01" + "".join(ipaddress.IPv4Address(x).packed.hex() for x in o.sip_servers)))
    if o.provisioning_url:
        out.append(_raw(160, o.provisioning_url.encode().hex()))
    if o.static_routes:    # 121 (RFC 3442) и 249 (то же для старых Windows)
        h = o.classless_routes_hex()
        out += [_raw(121, h), _raw(249, h)]
    if o.wpad_url:
        out.append(_raw(252, o.wpad_url.encode().hex()))
    if o.vendor_43:
        out.append(_raw(43, o.vendor_43))
    for c in o.custom:
        out.append(_raw(c.code, c.hex()))
    return out


def reservations(seg: LanConfig, static: list[StaticLease]) -> list[dict]:
    out = []
    for s in static:
        if ipaddress.ip_address(s.ip) not in seg.network:
            continue
        r = {"hw-address": s.mac, "ip-address": s.ip}
        if s.name and HOSTNAME_RE.match(s.name):
            r["hostname"] = s.name
        out.append(r)
    return out


def kea_conf(segments: list[tuple[LanConfig, list[StaticLease]]], upstream_dns: list[str],
             leases: str, socket_path: str) -> dict:
    """segments — включённые сегменты с DHCP и их закреплённые адреса."""
    subnets = []
    for seg, static in segments:
        subnets.append({
            "id": subnet_id(seg),
            "subnet": str(seg.network),
            "interface": seg.bridge,
            "pools": [{"pool": f"{seg.pool_start} - {seg.pool_end}"}],
            "valid-lifetime": seconds(seg.lease_time),
            "option-data": option_data(seg, upstream_dns),
            "reservations": reservations(seg, static),
            "user-context": {"lan": seg.id, "name": seg.name},
        })
    return {"Dhcp4": {
        "interfaces-config": {"interfaces": [seg.bridge for seg, _ in segments], "dhcp-socket-type": "raw"},
        "lease-database": {"type": "memfile", "persist": True, "name": leases, "lfc-interval": 3600},
        "control-socket": {"socket-type": "unix", "socket-name": socket_path},
        "authoritative": True,
        "calculate-tee-times": True,
        "valid-lifetime": 43200,
        # имя устройства (опция 12) сохраняется в аренде — по нему DNS-зона получает имена из DHCP;
        # сами DDNS-обновления не отправляются: зоны пишет роутер
        "dhcp-ddns": {"enable-updates": True},
        "ddns-send-updates": False,
        "hostname-char-set": "[^A-Za-z0-9.-]",
        "hostname-char-replacement": "",
        "subnet4": subnets,
        "loggers": [{"name": "kea-dhcp4", "output_options": [{"output": "stdout"}], "severity": "INFO"}],
    }}


# --- процесс ---------------------------------------------------------------------------------
def installed() -> bool:
    return shutil.which(KEA) is not None


def running() -> bool:
    return _kea.running()


def _env() -> dict:
    run = _data("kea")
    run.mkdir(parents=True, exist_ok=True)
    return {**os.environ, "KEA_LOCKFILE_DIR": str(run), "KEA_PIDFILE_DIR": str(run)}


def check(conf_path: Path) -> None:
    if not installed():
        return
    r = subprocess.run([KEA, "-t", str(conf_path)], capture_output=True, text=True, timeout=30, env=_env())
    if r.returncode != 0:
        lines = [l for l in (r.stdout + r.stderr).splitlines() if "ERROR" in l or "error" in l.lower()]
        raise DhcpError(400, "Kea не принял конфигурацию: " + " ".join((lines or [r.stdout + r.stderr])[-2:])[-400:])


def apply(segments: list[tuple[LanConfig, list[StaticLease]]], upstream_dns: list[str]) -> None:
    """Записать конфиг и применить: запуск, перечитывание (SIGHUP) или остановка."""
    with _lock:
        if not segments:
            if _kea.running():
                _kea.stop()
            return
        if not installed():
            raise DhcpError(500, "нет Kea DHCP в образе — пересоберите образ (docker compose build)")
        migrate_dnsmasq_leases(segments)
        conf = kea_conf(segments, upstream_dns, str(leases_file()), str(_data("kea/kea4-ctrl.sock")))
        path = _data("kea-dhcp4.conf")
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".kea.", suffix=".conf")
        with os.fdopen(fd, "w") as f:
            json.dump(conf, f, indent=2)
        try:
            check(Path(tmp))
        except DhcpError:
            Path(tmp).unlink(missing_ok=True)
            raise
        os.replace(tmp, path)
        if _kea.running():
            _kea.signal(signal.SIGHUP)
            print(f"[dhcp] Kea перечитал конфигурацию: {', '.join(s.bridge for s, _ in segments)}")
        else:
            _kea.start([KEA, "-c", str(path)], env=_env())


def stop() -> None:
    _kea.stop()


# --- аренды ----------------------------------------------------------------------------------
def migrate_dnsmasq_leases(segments) -> None:
    """Один раз при переходе с dnsmasq: перенести его аренды, чтобы устройства сохранили адреса."""
    old, new = _data("dnsmasq.leases"), leases_file()
    if new.exists() or not old.exists():
        return
    rows = []
    for line in old.read_text().splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        expiry, mac, ip, name = p[:4]
        seg = next((s for s, _ in segments if ipaddress.ip_address(ip) in s.network), None)
        if not seg:
            continue
        exp = int(expiry) if expiry != "0" else int(time.time()) + 86400 * 365
        rows.append([ip, mac, "", 43200, exp, subnet_id(seg), 0, 0, "" if name == "*" else name, 0, ""])
    with new.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["address", "hwaddr", "client_id", "valid_lifetime", "expire", "subnet_id",
                    "fqdn_fwd", "fqdn_rev", "hostname", "state", "user_context"])
        w.writerows(rows)
    old.rename(old.with_suffix(".leases.migrated"))
    print(f"[dhcp] аренды dnsmasq перенесены в Kea: {len(rows)}")


def read_leases(subnets: dict[int, str] | None = None, now: float | None = None) -> list[Lease]:
    """Действующие аренды из файлов Kea (с учётом сжатия LFC: .completed, .1, .2)."""
    now = now or time.time()
    base = leases_file()
    by_ip: dict[str, dict] = {}
    for p in (base.with_name(base.name + ".completed"), base.with_name(base.name + ".1"),
              base.with_name(base.name + ".2"), base):
        try:
            with p.open(newline="") as f:
                for row in csv.DictReader(f):
                    if row.get("address"):
                        by_ip[row["address"]] = row
        except OSError:
            continue
    out = []
    for ip, r in by_ip.items():
        try:
            expire, life, state = int(r.get("expire") or 0), int(r.get("valid_lifetime") or 0), int(r.get("state") or 0)
        except ValueError:
            continue
        infinite = life == 0xFFFFFFFF
        if state != 0 or (not infinite and expire <= now):
            continue
        mac = (r.get("hwaddr") or "").lower()
        if not mac:
            continue
        sid = int(r.get("subnet_id") or 0)
        out.append(Lease(ip=ip, mac=mac, lan=(subnets or {}).get(sid, f"lan{sid}"),
                         hostname=(r.get("hostname") or "").rstrip(".").split(".")[0] or None,
                         vendor=oui.vendor(mac), expires=None if infinite else float(expire)))
    return sorted(out, key=lambda l: ipaddress.ip_address(l.ip))
