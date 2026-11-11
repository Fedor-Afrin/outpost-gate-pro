"""
LAN — все порты, кроме WAN, в мосту br-lan; dnsmasq раздаёт адреса и DNS; NAT в WAN.

Как и WAN, LAN записывает в data/lan.json, что именно он сделал (какие порты
забрал в мост, какие адреса перенёс с портов на мост), чтобы при выключении
или смене настроек вернуть всё как было.
"""
from __future__ import annotations

import ipaddress
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from app.core.config import settings
from app.core.store import store
from app.models.lan import LanConfig, LanStatus, Lease, Port, StaticLease, StaticLeaseView
from app.services import firewall, netlink, oui, wan

BRIDGE = "br-lan"

_lock = threading.RLock()
_dnsmasq: subprocess.Popen | None = None


class LanError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --- файлы ---------------------------------------------------------------------------
def _data(name: str) -> Path:
    return Path(settings.data_dir) / name


def state_file() -> Path:
    return _data("lan.json")


def load_state() -> dict:
    try:
        return json.loads(state_file().read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    path = state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".lan.")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def get_config() -> LanConfig:
    data = store.load()
    return LanConfig.from_yaml(data.get("lan"), data.get("firewall"))


# --- dnsmasq ---------------------------------------------------------------------------
def dnsmasq_conf(cfg: LanConfig, leases_file: str, resolv_file: str, hosts_file: str = "") -> str:
    iface = ipaddress.ip_interface(cfg.address)
    lines = [
        "# сгенерировано OutpostGate Pro — не редактировать вручную",
        "keep-in-foreground",
        "log-facility=-",            # журнал — в docker logs
        "pid-file=",
        "user=root",
        f"interface={BRIDGE}",
        "bind-dynamic",              # слушать только адрес моста, порт 53 хоста не занимаем
        "",
        "# --- DNS ---",
        f"resolv-file={resolv_file}",   # вышестоящие DNS от WAN, файл обновляется на лету
        "domain-needed",
        "bogus-priv",
        "cache-size=1000",
        "domain=lan",
        "local=/lan/",
        "expand-hosts",
        "",
    ]
    if cfg.dhcp_enabled:
        lines += [
            "# --- DHCP ---",
            f"dhcp-range={cfg.pool_start},{cfg.pool_end},{iface.network.netmask},{cfg.lease_time}",
            f"dhcp-option=option:router,{iface.ip}",
            f"dhcp-option=option:dns-server,{iface.ip}",
            f"dhcp-leasefile={leases_file}",
            *([f"dhcp-hostsfile={hosts_file}"] if hosts_file else []),   # закреплённые адреса, SIGHUP = перечитать
            "dhcp-authoritative",
            "dhcp-rapid-commit",
        ]
    else:
        lines.append(f"no-dhcp-interface={BRIDGE}")
    return "\n".join(lines) + "\n"


def dnsmasq_running() -> bool:
    return _dnsmasq is not None and _dnsmasq.poll() is None


def start_dnsmasq(cfg: LanConfig) -> None:
    global _dnsmasq
    conf = _data("dnsmasq.conf")
    if not wan.resolv_file().exists():
        wan.write_upstream_dns(wan.get_config().dns)
    write_hosts_file()
    conf.write_text(dnsmasq_conf(cfg, str(_data("dnsmasq.leases")), str(wan.resolv_file()),
                                 str(_data("dnsmasq.hosts"))))
    try:
        _dnsmasq = subprocess.Popen(["dnsmasq", f"--conf-file={conf}"])
    except FileNotFoundError as e:
        raise LanError(500, "нет dnsmasq — пересоберите образ") from e
    print(f"[lan] dnsmasq запущен (pid {_dnsmasq.pid})")


def stop_dnsmasq() -> None:
    global _dnsmasq
    if dnsmasq_running():
        _dnsmasq.terminate()
        try:
            _dnsmasq.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _dnsmasq.kill()
            _dnsmasq.wait()
        print("[lan] dnsmasq остановлен")
    _dnsmasq = None


def leases() -> list[Lease]:
    """Формат файла dnsmasq: <срок> <MAC> <IP> <имя|*> <client-id|*>"""
    try:
        lines = _data("dnsmasq.leases").read_text().splitlines()
    except OSError:
        return []
    static = {l.mac: l for l in static_leases()}
    out = []
    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        expiry, mac, ip, name = parts[:4]
        out.append(Lease(
            ip=ip, mac=mac,
            hostname=None if name == "*" else name,
            vendor=oui.vendor(mac),
            expires=None if expiry == "0" else float(expiry),
            static=mac.lower() in static,
            name=static[mac.lower()].name if mac.lower() in static else None,
        ))
    return sorted(out, key=lambda l: tuple(int(x) for x in l.ip.split(".")))


# --- закреплённые адреса ----------------------------------------------------------
def _static_raw(data: dict) -> list[dict]:
    return (((data.get("lan") or {}).get("dhcp-server") or {}).get("static-leases")) or []


def static_leases() -> list[StaticLease]:
    return [StaticLease(**x) for x in _static_raw(store.load())]


def static_view(cfg: LanConfig | None = None) -> list[StaticLeaseView]:
    cfg = cfg or get_config()
    iface = ipaddress.ip_interface(cfg.address)
    start, end = ipaddress.ip_address(cfg.pool_start), ipaddress.ip_address(cfg.pool_end)
    out = []
    for l in static_leases():
        ip = ipaddress.ip_address(l.ip)
        out.append(StaticLeaseView(
            **l.model_dump(),
            in_pool=start <= ip <= end,
            valid=ip in iface.network and ip != iface.ip,
        ))
    return sorted(out, key=lambda x: ipaddress.ip_address(x.ip))


def write_hosts_file() -> None:
    path = _data("dnsmasq.hosts")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(l.dnsmasq_line() + "\n" for l in static_leases()))


def reload_dnsmasq() -> None:
    write_hosts_file()
    if dnsmasq_running():
        _dnsmasq.send_signal(signal.SIGHUP)   # перечитать dhcp-hostsfile без разрыва для клиентов


def _validate_static(item: StaticLease, others: list[StaticLease]) -> None:
    cfg = get_config()
    iface = ipaddress.ip_interface(cfg.address)
    ip = ipaddress.ip_address(item.ip)
    if ip not in iface.network:
        raise LanError(400, f"{ip} вне сети LAN {iface.network}")
    if ip == iface.ip:
        raise LanError(400, f"{ip} — это адрес самого роутера")
    if ip in (iface.network.network_address, iface.network.broadcast_address):
        raise LanError(400, f"{ip} — адрес сети или broadcast")
    for o in others:
        if o.mac == item.mac:
            raise LanError(409, f"MAC {item.mac} уже закреплён за {o.ip}")
        if o.ip == item.ip:
            raise LanError(409, f"адрес {item.ip} уже закреплён за {o.mac}")


def _save_static(items: list[StaticLease]) -> None:
    with store.transaction() as data:
        lan_cfg = data.get("lan") or {}
        dhcp = lan_cfg.get("dhcp-server") or {}
        dhcp["static-leases"] = [i.model_dump(exclude_none=True) for i in items]
        lan_cfg["dhcp-server"] = dhcp
        data["lan"] = lan_cfg
    reload_dnsmasq()


def add_static(item: StaticLease) -> list[StaticLeaseView]:
    with _lock:
        items = static_leases()
        _validate_static(item, items)
        _save_static(items + [item])
    return static_view()


def update_static(mac: str, item: StaticLease) -> list[StaticLeaseView]:
    mac = mac.lower()
    with _lock:
        items = static_leases()
        if not any(i.mac == mac for i in items):
            raise LanError(404, f"MAC {mac} не закреплён")
        others = [i for i in items if i.mac != mac]
        _validate_static(item, others)
        _save_static([item if i.mac == mac else i for i in items])
    return static_view()


def delete_static(mac: str) -> list[StaticLeaseView]:
    mac = mac.lower()
    with _lock:
        items = static_leases()
        if not any(i.mac == mac for i in items):
            raise LanError(404, f"MAC {mac} не закреплён")
        _save_static([i for i in items if i.mac != mac])
    return static_view()


# --- порты -------------------------------------------------------------------------
def wan_interface() -> str | None:
    try:
        return wan.load_state().get("interface") or wan.resolve_interface(wan.get_config())
    except wan.WanError:
        return None


def lan_ports(cfg: LanConfig, wan_if: str | None) -> list[str]:
    existing = set(wan.candidates())
    if cfg.ports:
        return [p for p in cfg.ports if p in existing and p != wan_if]
    return [p for p in sorted(existing) if p != wan_if]


def _check_overlap(cfg: LanConfig, wan_if: str | None) -> None:
    lan_net = ipaddress.ip_interface(cfg.address).network
    for ifname, cidr in netlink.kernel_ipv4_addresses():
        if ifname == wan_if and ipaddress.ip_interface(cidr).network.overlaps(lan_net):
            raise LanError(400, f"сеть LAN {lan_net} пересекается с адресом на WAN ({wan_if}: {cidr}). "
                                f"Выберите другую сеть LAN или уберите адрес в CLI: /ip address print, затем remove")


def _wait_for_ports(seconds: float = 5.0) -> None:
    """В GNS3 интерфейсы появляются не сразу: ждём, пока их число перестанет меняться."""
    deadline = time.monotonic() + seconds
    last, stable_since = None, time.monotonic()
    while time.monotonic() < deadline:
        now = len(wan.candidates())
        if now != last:
            last, stable_since = now, time.monotonic()
        elif time.monotonic() - stable_since >= 1.0:
            return
        time.sleep(0.25)


# --- применение ------------------------------------------------------------------------
def teardown(state: dict) -> None:
    """Вернуть всё, как было до включения LAN."""
    stop_dnsmasq()
    firewall.remove()
    if state.get("address"):
        try:
            netlink.addr_del(BRIDGE, state["address"])
        except netlink.NetlinkOpError as e:
            print(f"[lan] WARNING: {e}")
    for port in state.get("ports", []):
        try:
            netlink.link_set_master(port, None)
        except netlink.NetlinkOpError as e:
            print(f"[lan] WARNING: {e}")
    for port, cidr in state.get("moved", []):
        try:
            netlink.addr_add(port, cidr)
        except netlink.NetlinkOpError as e:
            print(f"[lan] WARNING: {e}")
    if state.get("bridge"):
        netlink.link_delete(BRIDGE)
    save_state({})


def setup(cfg: LanConfig) -> None:
    wan_if = wan_interface()
    if not wan_if:
        raise LanError(400, "сначала нужен WAN: интерфейс WAN не найден")
    _check_overlap(cfg, wan_if)
    ports = lan_ports(cfg, wan_if)

    state: dict = {"bridge": True, "ports": [], "moved": [], "address": None}
    mac = netlink.link_info(ports[0]).get("mac") if ports else None
    netlink.bridge_create(BRIDGE, mac)
    save_state(state)

    for port in ports:
        # адреса порта переезжают на мост (иначе порт моста с IP работает некорректно)
        for ifname, cidr in netlink.kernel_ipv4_addresses():
            if ifname == port:
                netlink.addr_del(port, cidr)
                state["moved"].append([port, cidr])
                netlink.addr_add(BRIDGE, cidr)
        netlink.link_set_master(port, BRIDGE)
        netlink.link_set_up(port)
        state["ports"].append(port)
        save_state(state)

    netlink.link_set_up(BRIDGE)
    netlink.addr_add(BRIDGE, cfg.address)
    state["address"] = cfg.address
    save_state(state)

    start_dnsmasq(cfg)
    try:
        firewall.refresh(cfg)         # NAT и правила с учётом WAN, LAN и VPN
    except firewall.FirewallError as e:
        raise LanError(500, str(e)) from e
    print(f"[lan] {BRIDGE} {cfg.address}, порты: {', '.join(ports) or 'нет'}")


def apply(cfg: LanConfig) -> None:
    with _lock:
        teardown(load_state())
        if cfg.enabled:
            setup(cfg)


def update(new: LanConfig) -> LanStatus:
    old = get_config()
    try:
        apply(new)
    except (netlink.NetlinkOpError, LanError) as e:
        try:
            apply(old)
        except Exception as rollback_err:
            print(f"[lan] ERROR: откат не удался: {rollback_err}")
        if isinstance(e, LanError):
            raise
        raise LanError(400, str(e)) from e
    lan_yaml, fw_yaml = new.to_yaml()
    with store.transaction() as cfg:
        keep = _static_raw(cfg)                     # закреплённые адреса живут отдельно
        if keep:
            lan_yaml["dhcp-server"]["static-leases"] = keep
        cfg["lan"] = lan_yaml
        cfg.setdefault("firewall", {})
        cfg["firewall"] = {**(cfg["firewall"] or {}), **fw_yaml}
    return status()


def on_wan_changed() -> None:
    """WAN поменялся (интерфейс или режим) — пересобрать LAN, NAT и фаервол."""
    cfg = get_config()
    if cfg.enabled:
        try:
            apply(cfg)
        except (netlink.NetlinkOpError, LanError) as e:
            print(f"[lan] ERROR после смены WAN: {e}")


def apply_startup() -> None:
    cfg = get_config()
    if not cfg.enabled:
        teardown(load_state())   # остатки от прошлого запуска (режим host)
        return
    _wait_for_ports()
    apply(cfg)


# --- статус ----------------------------------------------------------------------------
def status() -> LanStatus:
    cfg = get_config()
    st = load_state()
    wan_if = wan_interface()
    in_lan = set(st.get("ports", []))

    ports = []
    for name in sorted(set(wan.candidates()) | in_lan):
        info = netlink.link_info(name)
        role = "wan" if name == wan_if else ("lan" if name in in_lan else "none")
        ports.append(Port(name=name, role=role, **info))
    ports.sort(key=lambda p: (p.role != "wan", p.name))

    active = bool(st.get("address")) and (BRIDGE, st["address"]) in set(netlink.kernel_ipv4_addresses())
    return LanStatus(
        config=cfg,
        active=active,
        bridge=BRIDGE,
        wan_interface=wan_if,
        ports=ports,
        dns_dhcp_running=dnsmasq_running(),
        leases=leases(),
        static_leases=static_view(cfg),
    )
