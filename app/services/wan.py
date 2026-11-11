"""
WAN — один фиксированный интерфейс в интернет.

Режимы:
  dhcp    — адрес, шлюз и DNS получает DHCP-клиент (busybox udhcpc);
  static  — IP/маска, шлюз и DNS заданы вручную;
  none    — роутер не трогает WAN (адрес задан системой: Docker, netplan).

Что именно роутер поставил на WAN (адрес, шлюз), записывается в
data/wan.json — так при смене режима мы убираем ровно своё и не трогаем чужое.
Шлюз WAN становится маршрутом по умолчанию с distance=WAN_METRIC.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

from app.core.config import settings
from app.core.store import store
from app.models.wan import WanConfig, WanStatus
from app.services import netlink

WAN_METRIC = 1
APP_HOME = Path(__file__).resolve().parents[2]          # /opt/outpost-gate-pro
HOOK = APP_HOME / "app" / "scripts" / "udhcpc-hook.sh"
# Эти интерфейсы не бывают WAN: loopback, мосты, туннели, служебные Docker
NOT_WAN = ("lo", "br-", "wg", "awg", "docker", "veth", "ppp", "l2tp", "tun", "tap")

_lock = threading.RLock()
_dhcp: subprocess.Popen | None = None


class WanError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --- состояние (что поставил роутер) -----------------------------------------
def state_file() -> Path:
    return Path(settings.data_dir) / "wan.json"


def load_state() -> dict:
    try:
        return json.loads(state_file().read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    path = state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".wan.")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def cleanup(state: dict) -> None:
    """Убрать с WAN то, что поставил роутер (адрес и маршрут по умолчанию)."""
    ifname = state.get("interface")
    if state.get("gateway"):
        try:
            netlink.route_del("0.0.0.0/0", state["gateway"], None, WAN_METRIC)
        except netlink.NetlinkOpError as e:
            print(f"[wan] WARNING: {e}")
    if ifname and state.get("address"):
        try:
            netlink.addr_del(ifname, state["address"])
        except netlink.NetlinkOpError as e:
            print(f"[wan] WARNING: {e}")


# --- вышестоящие DNS (для dnsmasq в LAN) ----------------------------------------
def resolv_file() -> Path:
    return Path(settings.data_dir) / "resolv.wan"


def system_nameservers() -> list[str]:
    """DNS из /etc/resolv.conf контейнера — запасной вариант (Docker, хост)."""
    try:
        lines = Path("/etc/resolv.conf").read_text().splitlines()
    except OSError:
        return []
    return [l.split()[1] for l in lines if l.startswith("nameserver") and len(l.split()) > 1]


def write_upstream_dns(dns: list[str]) -> None:
    """dnsmasq сам следит за этим файлом и подхватывает изменения без перезапуска.

    Если поднят VPN в режиме «весь трафик» и у него есть DNS — они важнее DNS провайдера
    (иначе DNS-запросы утекали бы мимо туннеля).
    """
    from app.services import vpn   # здесь, чтобы не было циклического импорта
    servers = vpn.dns_override() or dns or system_nameservers() or ["1.1.1.1", "8.8.8.8"]
    path = resolv_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".resolv.")
    with os.fdopen(fd, "w") as f:
        f.write("".join(f"nameserver {s}\n" for s in servers))
    os.replace(tmp, path)


def refresh_upstream_dns() -> None:
    write_upstream_dns(get_config().dns or load_state().get("dns", []))


def current_gateway() -> str | None:
    """Шлюз провайдера: маршрут по умолчанию через WAN с наименьшей метрикой."""
    ifname = load_state().get("interface")
    if not ifname:
        try:
            ifname = resolve_interface(get_config())
        except WanError:
            return None
    defaults = sorted((r for r in netlink.kernel_ipv4_routes()
                       if r["dst"] == "0.0.0.0/0" and r["interface"] == ifname and r["gateway"]),
                      key=lambda r: r["metric"])
    return defaults[0]["gateway"] if defaults else None


# --- интерфейс ------------------------------------------------------------------
def candidates() -> list[str]:
    return sorted(n for n in netlink.link_names() if not n.startswith(NOT_WAN))


def detect_interface() -> str | None:
    """auto: интерфейс маршрута по умолчанию; если его нет — первый подходящий."""
    allowed = set(candidates())
    defaults = sorted(
        (r for r in netlink.kernel_ipv4_routes()
         if r["dst"] == "0.0.0.0/0" and r["interface"] in allowed),
        key=lambda r: r["metric"],
    )
    if defaults:
        return defaults[0]["interface"]
    names = sorted(allowed)
    return names[0] if names else None


def resolve_interface(cfg: WanConfig) -> str:
    if cfg.interface != "auto":
        if cfg.interface not in netlink.link_names():
            raise WanError(400, f"интерфейс '{cfg.interface}' не существует")
        return cfg.interface
    name = detect_interface()
    if not name:
        raise WanError(500, "не найден ни один интерфейс, подходящий для WAN")
    return name


def get_config() -> WanConfig:
    return WanConfig(**(store.load().get("wan") or {}))


# --- DHCP-клиент ------------------------------------------------------------------
def dhcp_running() -> bool:
    return _dhcp is not None and _dhcp.poll() is None


def start_dhcp(ifname: str) -> None:
    global _dhcp
    cmd = [
        "busybox", "udhcpc",
        "-i", ifname,
        "-f",            # не уходить в фон: процессом управляет роутер
        "-R",            # при остановке освободить аренду
        "-t", "5", "-T", "3", "-A", "10",   # 5 попыток по 3 с, пауза 10 с, и снова
        "-s", str(HOOK),
        "-x", f"hostname:{socket.gethostname()}",
    ]
    env = {**os.environ, "ROUTER_HOME": str(APP_HOME), "ROUTER_DATA": settings.data_dir}
    try:
        _dhcp = subprocess.Popen(cmd, env=env)
    except FileNotFoundError as e:
        raise WanError(500, "нет busybox (udhcpc) — пересоберите образ") from e
    print(f"[wan] DHCP-клиент запущен на {ifname} (pid {_dhcp.pid})")


def stop_dhcp() -> None:
    global _dhcp
    if dhcp_running():
        _dhcp.terminate()            # udhcpc с -R отпустит аренду и вызовет deconfig
        try:
            _dhcp.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _dhcp.kill()
            _dhcp.wait()
        print("[wan] DHCP-клиент остановлен")
    _dhcp = None


def renew() -> None:
    if not dhcp_running():
        raise WanError(409, "DHCP-клиент не запущен (WAN не в режиме dhcp)")
    _dhcp.send_signal(signal.SIGUSR1)   # udhcpc: SIGUSR1 = renew


# --- применение -------------------------------------------------------------------
def apply(cfg: WanConfig) -> None:
    with _lock:
        stop_dhcp()
        cleanup(load_state())
        ifname = resolve_interface(cfg)
        state: dict = {"interface": ifname, "mode": cfg.mode, "state": cfg.mode}

        if cfg.mode == "static":
            netlink.link_set_up(ifname)
            netlink.addr_add(ifname, cfg.address)
            state["address"] = cfg.address        # сохранить сразу: откат уберёт и это
            save_state(state)
            netlink.route_add("0.0.0.0/0", cfg.gateway, None, WAN_METRIC)
            state.update(gateway=cfg.gateway, dns=cfg.dns)
        elif cfg.mode == "dhcp":
            netlink.link_set_up(ifname)
            state["state"] = "searching"
            save_state(state)
            write_upstream_dns(cfg.dns)       # до получения аренды
            start_dhcp(ifname)
            return
        save_state(state)
        write_upstream_dns(cfg.dns)


def update(new: WanConfig) -> WanStatus:
    old = get_config()
    try:
        apply(new)
    except (netlink.NetlinkOpError, WanError) as e:
        try:
            apply(old)                        # вернуть как было
        except Exception as rollback_err:
            print(f"[wan] ERROR: откат не удался: {rollback_err}")
        if isinstance(e, WanError):
            raise
        raise WanError(400, str(e)) from e
    with store.transaction() as cfg:
        cfg["wan"] = new.to_yaml()
    from app.services import lan, vpn     # LAN и VPN зависят от WAN: NAT, фаервол, маршрут до сервера
    lan.on_wan_changed()
    vpn.on_wan_changed()
    return status()


def apply_startup() -> None:
    """При старте: зафиксировать WAN-интерфейс (если auto) и применить настройки."""
    cfg = get_config()
    if cfg.interface == "auto":
        detected = detect_interface()
        if detected:
            with store.transaction() as data:
                wan = data.get("wan") or {}
                wan.update(interface=detected)
                wan.setdefault("mode", cfg.mode)
                data["wan"] = wan
            cfg = get_config()
            print(f"[wan] WAN-интерфейс определён автоматически: {detected}")
    try:
        apply(cfg)
        print(f"[wan] WAN {cfg.interface}: режим {cfg.mode}")
    except (netlink.NetlinkOpError, WanError) as e:
        print(f"[wan] ERROR: {e}")


# --- статус -------------------------------------------------------------------
def status() -> WanStatus:
    cfg = get_config()
    st = load_state()
    try:
        ifname = st.get("interface") or resolve_interface(cfg)
    except WanError:
        ifname = None

    link = netlink.link_info(ifname) if ifname else {}

    addrs = [a for i, a in netlink.kernel_ipv4_addresses() if i == ifname]
    defaults = sorted((r for r in netlink.kernel_ipv4_routes()
                       if r["dst"] == "0.0.0.0/0" and r["interface"] == ifname),
                      key=lambda r: r["metric"])
    return WanStatus(
        config=cfg,
        interface=ifname,
        addresses=addrs,
        gateway=defaults[0]["gateway"] if defaults else None,
        dns=cfg.dns or st.get("dns", []),
        dhcp_running=dhcp_running(),
        dhcp_state=st.get("state"),
        lease_expires=st.get("lease_expires"),
        interfaces=candidates(),
        **link,
    )
