"""
WAN — интерфейс в интернет; до двух провайдеров: wan1 (секция wan:) и wan2 (секция wan2:).

Режимы:
  dhcp    — адрес, шлюз и DNS получает DHCP-клиент (busybox udhcpc);
  static  — IP/маска, шлюз и DNS заданы вручную;
  none    — роутер не трогает WAN (адрес задан системой: Docker, netplan).

Что именно роутер поставил на WAN (адрес, шлюз), записывается в
data/wan.json — так при смене режима мы убираем ровно своё и не трогаем чужое.
Шлюз WAN становится маршрутом по умолчанию с distance=WAN_METRIC.
Если включён второй WAN, маршрутами по умолчанию, таблицами и правилами для обоих каналов
управляет app/services/multiwan.py (резерв или балансировка, проверка связи).
Состояние второго WAN — в data/wan2.json, его DHCP-клиент — свой процесс udhcpc.
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
from app.models.wan import Wan2Config, WanConfig, WanStatus
from app.services import netlink

WAN_METRIC = 1
APP_HOME = Path(__file__).resolve().parents[2]          # /opt/outpost-gate-pro
HOOK = APP_HOME / "app" / "scripts" / "udhcpc-hook.sh"
# Эти интерфейсы не бывают WAN: loopback, мосты, туннели, служебные Docker
NOT_WAN = ("lo", "br-", "wg", "awg", "docker", "veth", "ppp", "l2tp", "tun", "tap")

WANS = ("wan1", "wan2")
_lock = threading.RLock()
_dhcp: dict[str, subprocess.Popen] = {}


class WanError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --- состояние (что поставил роутер) -----------------------------------------
def state_file() -> Path:
    return Path(settings.data_dir) / "wan.json"


def _state_path(wid: str = "wan1") -> Path:
    return state_file() if wid == "wan1" else state_file().with_name(f"{wid}.json")


def load_state(wid: str = "wan1") -> dict:
    try:
        return json.loads(_state_path(wid).read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict, wid: str = "wan1") -> None:
    path = _state_path(wid)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".wan.")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def multi() -> bool:
    """Включён ли второй WAN (тогда маршрутами по умолчанию управляет multiwan)."""
    try:
        return get_config("wan2").enabled
    except Exception:  # noqa: BLE001 — ошибка в секции wan2 не должна ломать основной WAN
        return False


def set_gateway(wid: str, gateway: str | None, proto: int | None = None) -> None:
    """Шлюз провайдера -> маршрут по умолчанию (один WAN) или таблица канала + мульти-WAN."""
    if multi():
        from app.services import multiwan
        multiwan.sync()
    elif wid == "wan1" and gateway:
        netlink.route_add("0.0.0.0/0", gateway, None, WAN_METRIC,
                          **({"proto": proto} if proto is not None else {}))


def drop_gateway(wid: str, gateway: str | None) -> None:
    if not gateway:
        return
    try:
        netlink.route_del("0.0.0.0/0", gateway, None, WAN_METRIC)   # маршрут одного WAN, если был
    except netlink.NetlinkOpError as e:
        print(f"[wan] WARNING: {e}")


def cleanup(state: dict, wid: str = "wan1") -> None:
    """Убрать с WAN то, что поставил роутер (адрес и маршрут по умолчанию)."""
    ifname = state.get("interface")
    if state.get("gateway"):
        drop_gateway(wid, state["gateway"])
        if multi():
            from app.services import multiwan
            multiwan.forget(wid)
    if ifname and state.get("address"):
        try:
            netlink.addr_del(ifname, state["address"])
        except netlink.NetlinkOpError as e:
            print(f"[wan] WARNING: {e}")
    if state.get("vlan"):            # WAN на VLAN провайдера: интерфейс создавал роутер
        try:
            netlink.link_delete(state["vlan"])
        except netlink.NetlinkOpError as e:
            print(f"[wan] WARNING: {e}")


# --- вышестоящие DNS (forwarders для BIND в LAN) ----------------------------------------
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
    """Список DNS провайдера; BIND берёт из него forwarders (если они не заданы вручную).

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
    old = path.read_text() if path.exists() else None
    os.replace(tmp, path)
    if old != path.read_text():
        try:
            from app.services import dns
            dns.on_upstream_changed()
        except Exception as e:  # DNS не должен мешать WAN
            print(f"[wan] WARNING: DNS: {e}")


def refresh_upstream_dns() -> None:
    """DNS провайдера. Два WAN: сначала DNS действующего канала, потом второго."""
    if multi():
        from app.services import multiwan
        order = multiwan.dns_order()
        dns: list[str] = []
        for wid in order:
            for x in get_config(wid).dns or load_state(wid).get("dns", []):
                if x not in dns:
                    dns.append(x)
        write_upstream_dns(dns)
        return
    write_upstream_dns(get_config().dns or load_state().get("dns", []))


def active_interfaces() -> list[str]:
    """Все WAN-интерфейсы, через которые сейчас может идти трафик (для NAT и фаервола)."""
    out = []
    for wid in WANS:
        if wid == "wan2" and not multi():
            continue
        name = load_state(wid).get("interface")
        if not name and wid == "wan1":
            try:
                name = resolve_interface(get_config())
            except WanError:
                name = None
        if name and name not in out:
            out.append(name)
    return out


def physical_ports() -> list[str]:
    """Порты, занятые провайдерами (и их физические порты под VLAN) — их нельзя отдать LAN."""
    out = []
    for wid in WANS:
        if wid == "wan2" and not multi():
            continue
        st = load_state(wid)
        for x in (st.get("interface"), st.get("base")):
            if x and x not in out:
                out.append(x)
        if wid == "wan2":
            cfg_if = get_config("wan2").interface
            if cfg_if and cfg_if not in out:
                out.append(cfg_if)
    return out


def current_gateway() -> str | None:
    """Шлюз провайдера: маршрут по умолчанию через WAN с наименьшей метрикой.
    Два WAN — шлюз канала, через который сейчас идёт трафик."""
    if multi():
        from app.services import multiwan
        return multiwan.active_gateway()
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
    """Физические порты: без мостов, туннелей и VLAN-интерфейсов (eth1.10)."""
    return sorted(n for n in netlink.link_names() if not n.startswith(NOT_WAN) and "." not in n)


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


def get_config(wid: str = "wan1") -> WanConfig:
    if wid == "wan2":
        return Wan2Config(**(store.load().get("wan2") or {}))
    return WanConfig(**(store.load().get("wan") or {}))


# --- DHCP-клиент ------------------------------------------------------------------
def dhcp_running(wid: str = "wan1") -> bool:
    p = _dhcp.get(wid)
    return p is not None and p.poll() is None


def start_dhcp(ifname: str, wid: str = "wan1") -> None:
    cmd = [
        "busybox", "udhcpc",
        "-i", ifname,
        "-f",            # не уходить в фон: процессом управляет роутер
        "-R",            # при остановке освободить аренду
        "-t", "5", "-T", "3", "-A", "10",   # 5 попыток по 3 с, пауза 10 с, и снова
        "-s", str(HOOK),
        "-x", f"hostname:{socket.gethostname()}",
    ]
    env = {**os.environ, "ROUTER_HOME": str(APP_HOME), "ROUTER_DATA": settings.data_dir, "WAN_ID": wid}
    try:
        _dhcp[wid] = subprocess.Popen(cmd, env=env)
    except FileNotFoundError as e:
        raise WanError(500, "нет busybox (udhcpc) — пересоберите образ") from e
    print(f"[wan] {wid}: DHCP-клиент запущен на {ifname} (pid {_dhcp[wid].pid})")


def stop_dhcp(wid: str | None = None) -> None:
    for w in ([wid] if wid else list(_dhcp)):
        p = _dhcp.get(w)
        if p is not None and p.poll() is None:
            p.terminate()            # udhcpc с -R отпустит аренду и вызовет deconfig
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            print(f"[wan] {w}: DHCP-клиент остановлен")
        _dhcp.pop(w, None)


def renew(wid: str = "wan1") -> None:
    if not dhcp_running(wid):
        raise WanError(409, "DHCP-клиент не запущен (WAN не в режиме dhcp)")
    _dhcp[wid].send_signal(signal.SIGUSR1)   # udhcpc: SIGUSR1 = renew


# --- применение -------------------------------------------------------------------
def apply(cfg: WanConfig, wid: str = "wan1") -> None:
    with _lock:
        stop_dhcp(wid)
        cleanup(load_state(wid), wid)
        if wid == "wan2" and not getattr(cfg, "enabled", False):
            save_state({}, wid)
            return
        ifname = resolve_interface(cfg)
        state: dict = {"interface": ifname, "mode": cfg.mode, "state": cfg.mode}
        if cfg.vlan_id and cfg.mode != "none":
            base, ifname = ifname, netlink.vlan_name(ifname, cfg.vlan_id)
            netlink.link_set_up(base)
            netlink.vlan_create(ifname, base, cfg.vlan_id)
            state.update(interface=ifname, base=base, vlan=ifname)
            save_state(state, wid)

        if cfg.mode == "static":
            netlink.link_set_up(ifname)
            netlink.addr_add(ifname, cfg.address)
            state["address"] = cfg.address        # сохранить сразу: откат уберёт и это
            save_state(state, wid)
            state.update(gateway=cfg.gateway, dns=cfg.dns)
            if not multi():
                netlink.route_add("0.0.0.0/0", cfg.gateway, None, WAN_METRIC)
            save_state(state, wid)
            if multi():
                from app.services import multiwan
                multiwan.sync()
        elif cfg.mode == "dhcp":
            netlink.link_set_up(ifname)
            state["state"] = "searching"
            save_state(state, wid)
            refresh_upstream_dns() if wid == "wan2" else write_upstream_dns(cfg.dns)   # до получения аренды
            start_dhcp(ifname, wid)
            return
        save_state(state, wid)
        refresh_upstream_dns() if multi() else write_upstream_dns(cfg.dns)


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
    _after_change()
    return status()


def _after_change() -> None:
    from app.services import lan, vpn     # LAN и VPN зависят от WAN: NAT, фаервол, маршрут до сервера
    lan.on_wan_changed()
    vpn.on_wan_changed()


def _check_wan2(new: Wan2Config) -> None:
    if not new.enabled:
        return
    wan1 = load_state().get("interface")
    taken = {x for x in (wan1, load_state().get("base")) if x}
    try:
        taken.add(resolve_interface(get_config()))
    except WanError:
        pass
    if new.interface in taken:
        raise WanError(400, f"порт {new.interface} уже занят WAN1")
    if new.interface not in candidates():
        raise WanError(400, f"интерфейс '{new.interface}' не существует")
    from app.services import lan
    for s in lan.segments():
        if s.enabled and new.interface in s.ports:
            raise WanError(400, f"порт {new.interface} отдан сегменту LAN «{s.name}» — сначала уберите его оттуда")


def update_wan2(new: Wan2Config) -> WanStatus:
    """Второй провайдер: включить, выключить, сменить настройки. Ошибка — откат."""
    from app.services import multiwan
    _check_wan2(new)
    old = get_config("wan2")
    raw_old = store.load().get("wan2")
    with store.transaction() as cfg:
        cfg["wan2"] = new.to_yaml()           # multi() должен видеть новое значение уже при apply
    try:
        if old.enabled and not new.enabled:
            apply(new, "wan2")
            multiwan.teardown()               # вернуть один WAN: его маршрут по умолчанию
        else:
            if new.enabled and not old.enabled:
                multiwan.reset_health()
            apply(new, "wan2")
            multiwan.sync()
    except (netlink.NetlinkOpError, WanError, multiwan.MultiWanError) as e:
        with store.transaction() as cfg:
            if raw_old is None:
                cfg.pop("wan2", None)
            else:
                cfg["wan2"] = raw_old
        try:
            apply(old, "wan2")
            multiwan.sync() if old.enabled else multiwan.teardown()
        except Exception as rollback_err:  # noqa: BLE001
            print(f"[wan] ERROR: откат WAN2 не удался: {rollback_err}")
        if isinstance(e, WanError):
            raise
        raise WanError(400, str(getattr(e, "message", e))) from e
    refresh_upstream_dns()
    _after_change()
    return status("wan2")


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
    try:
        cfg2 = get_config("wan2")
    except Exception as e:  # noqa: BLE001
        print(f"[wan] ERROR: WAN2: {e}")
        return
    from app.services import multiwan
    if not cfg2.enabled:
        # конфигурацию восстановили без второго WAN — убрать его следы
        try:
            if load_state("wan2"):
                apply(cfg2, "wan2")
            if multiwan.installed():
                multiwan.teardown()
        except Exception as e:  # noqa: BLE001
            print(f"[wan] WARNING: WAN2: {e}")
        return
    if cfg2.enabled:
        try:
            multiwan.reset_health()
            apply(cfg2, "wan2")
            multiwan.sync()
            print(f"[wan] WAN2 {cfg2.interface}: режим {cfg2.mode}")
        except (netlink.NetlinkOpError, WanError, multiwan.MultiWanError) as e:
            print(f"[wan] ERROR: WAN2: {getattr(e, 'message', e)}")


# --- статус -------------------------------------------------------------------
def status(wid: str = "wan1") -> WanStatus:
    cfg = get_config(wid)
    st = load_state(wid)
    try:
        ifname = st.get("interface") or (resolve_interface(cfg) if cfg.interface else None)
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
        dhcp_running=dhcp_running(wid),
        dhcp_state=st.get("state"),
        lease_expires=st.get("lease_expires"),
        interfaces=candidates(),
        multi=multi(),
        **link,
    )
