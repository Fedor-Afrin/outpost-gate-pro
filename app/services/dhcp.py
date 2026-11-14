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
# Kea 2.6.3+ разрешает файлы аренд только в /var/lib/kea, сокеты и pid — только в /run/kea.
# /var/lib/kea становится ссылкой на data/kea: аренды переживают пересоздание контейнера.
KEA_LIB = Path(os.getenv("KEA_LIB_DIR", "/var/lib/kea"))
KEA_RUN = Path(os.getenv("KEA_RUN_DIR", "/run/kea"))
SYS_NET = Path(os.getenv("OG_SYS_NET", "/sys/class/net"))

# Kea слушает через raw-сокеты, а они привязаны к экземпляру интерфейса (ifindex), не к имени:
# если мост пересоздан (смена портов, VLAN, адреса, переустановка), Kea продолжает слушать старый
# и молча перестаёт выдавать адреса. Запоминаем номера мостов и перечитываем Kea, когда они меняются.
_ifindex: dict[str, int] = {}


def ifindexes(names) -> dict[str, int]:
    """Номера интерфейсов; 0 — интерфейса сейчас нет."""
    out = {}
    for n in names:
        try:
            out[n] = int((SYS_NET / n / "ifindex").read_text().strip())
        except (OSError, ValueError):
            out[n] = 0
    return out
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
    """Файл аренд на постоянном диске (data/kea/); Kea видит его как /var/lib/kea/…"""
    return _data("kea") / "kea-leases4.csv"


def _prepare_dirs() -> None:
    real = _data("kea")
    real.mkdir(parents=True, exist_ok=True)
    old = _data("kea-leases4.csv")            # первая версия этапа 2 держала аренды прямо в data/
    if old.exists() and not leases_file().exists():
        old.rename(leases_file())
    if not (KEA_LIB.is_symlink() and Path(os.readlink(KEA_LIB)) == real):
        if KEA_LIB.is_symlink() or KEA_LIB.is_file():
            KEA_LIB.unlink()
        elif KEA_LIB.is_dir():
            for item in KEA_LIB.iterdir():    # то, что положил пакет kea, — в постоянную папку
                target = real / item.name
                if not target.exists():
                    shutil.move(str(item), target)
            shutil.rmtree(KEA_LIB, ignore_errors=True)
        KEA_LIB.parent.mkdir(parents=True, exist_ok=True)
        KEA_LIB.symlink_to(real)
    KEA_RUN.mkdir(parents=True, exist_ok=True)
    # первая версия переноса аренд из dnsmasq писала строки с \r\n — Kea такой файл не открывает
    lf = leases_file()
    if lf.exists():
        raw = lf.read_bytes()
        if b"\r" in raw:
            lf.write_bytes(raw.replace(b"\r\n", b"\n").replace(b"\r", b""))
            print("[dhcp] файл аренд Kea исправлен (переводы строк)")


def subnet_id(seg: LanConfig) -> int:
    return int(seg.id[3:])          # lan1 -> 1, lan7 -> 7: стабильно при изменениях


def seconds(lease_time: str) -> int:
    return int(lease_time[:-1]) * {"m": 60, "h": 3600, "d": 86400}[lease_time[-1]]


def _raw(code: int, hexdata: str) -> dict:
    return {"code": code, "space": "dhcp4", "csv-format": False, "data": hexdata}


def option_data(seg: LanConfig, upstream_dns: list[str], ntp_router: bool = False) -> list[dict]:
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
        elif field == "ntp_servers" and ntp_router:      # роутер раздаёт время (System → Время)
            out.append({"name": name, "data": seg.router_ip})
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
             leases: str, ntp_router: bool = False) -> dict:
    """segments — включённые сегменты с DHCP и их закреплённые адреса."""
    subnets = []
    for seg, static in segments:
        subnets.append({
            "id": subnet_id(seg),
            "subnet": str(seg.network),
            "interface": seg.bridge,
            "pools": [{"pool": f"{seg.pool_start} - {seg.pool_end}"}],
            "valid-lifetime": seconds(seg.lease_time),
            "option-data": option_data(seg, upstream_dns, ntp_router),
            "reservations": reservations(seg, static),
            "user-context": {"lan": seg.id, "name": seg.name},
        })
    return {"Dhcp4": {
        "interfaces-config": {"interfaces": [seg.bridge for seg, _ in segments], "dhcp-socket-type": "raw"},
        "lease-database": {"type": "memfile", "persist": True, "name": leases, "lfc-interval": 3600},
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
    KEA_RUN.mkdir(parents=True, exist_ok=True)
    return {**os.environ, "KEA_LOCKFILE_DIR": str(KEA_RUN), "KEA_PIDFILE_DIR": str(KEA_RUN)}


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
        _prepare_dirs()
        migrate_dnsmasq_leases(segments)
        from app.services import ntp
        conf = kea_conf(segments, upstream_dns, str(KEA_LIB / leases_file().name), ntp.serves_lan())
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
        bridges = [s.bridge for s, _ in segments]
        if _kea.running():
            _kea.signal(signal.SIGHUP)
            print(f"[dhcp] Kea перечитал конфигурацию: {', '.join(bridges)}")
        else:
            _kea.start([KEA, "-c", str(path)], env=_env())
        _ifindex.clear()
        _ifindex.update(ifindexes(bridges))


def watch_interfaces() -> list[str]:
    """Мосты пересозданы после запуска Kea — перечитать (Kea заново откроет сокеты, аренды сохранятся).
    Вызывается сборщиком мониторинга раз в 10 с. -> список пересозданных мостов."""
    with _lock:
        if not _ifindex or not _kea.running():
            return []
        now = ifindexes(_ifindex)
        changed = [n for n, i in now.items() if i and i != _ifindex[n]]
        if not changed:
            return []
        _kea.signal(signal.SIGHUP)
        _ifindex.update({n: now[n] for n in changed})
        print(f"[dhcp] мост пересоздан ({', '.join(changed)}) — Kea перечитал интерфейсы")
        return changed


def stop() -> None:
    _kea.stop()
    _ifindex.clear()


# --- аренды ----------------------------------------------------------------------------------
def migrate_dnsmasq_leases(segments) -> None:
    """Один раз при переходе с dnsmasq: перенести его аренды, чтобы устройства сохранили адреса."""
    old, new = _data("dnsmasq.leases"), leases_file()
    if new.exists() or not old.exists():
        return
    new.parent.mkdir(parents=True, exist_ok=True)
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
        w = csv.writer(f, lineterminator="\n")     # Kea не принимает \r\n (Windows-переводы строк)
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
