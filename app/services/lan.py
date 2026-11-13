"""
LAN — сегменты: у каждого свой мост, адрес, порты, DHCP (Kea), DNS (BIND) и домен.

  lan1 — основной сегмент, мост br-lan, секция lan: в router.yaml; порты «auto» —
         все, кроме WAN и портов других сегментов;
  lan2, lan3… — дополнительные (секция lans:), мосты br-lan2…, порты — явно.

Между сегментами транзит закрыт, пока в сегменте не разрешено forward-to (фаервол).
Как и WAN, каждый сегмент записывает в data/, что именно он сделал (порты в мосту,
перенесённые адреса), чтобы при выключении или смене настроек вернуть всё как было.
"""
from __future__ import annotations

import ipaddress
import json
import os
import tempfile
import threading
import time
from pathlib import Path

from app.core.config import settings
from app.core.store import store
from app.models.lan import (DhcpSegmentView, DhcpSettings, DhcpStatus, LanConfig, LanStatus, Lease, Port,
                            SegmentStatus, StaticLease, StaticLeaseView)
from app.services import firewall, netlink, oui, wan

BRIDGE = "br-lan"
MAX_SEGMENTS = 16

_lock = threading.RLock()


class LanError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --- файлы состояния -------------------------------------------------------------------
def _data(name: str) -> Path:
    return Path(settings.data_dir) / name


def state_file(seg_id: str = "lan1") -> Path:
    return _data("lan.json" if seg_id == "lan1" else f"lan-{seg_id}.json")


def load_state(seg_id: str = "lan1") -> dict:
    try:
        return json.loads(state_file(seg_id).read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict, seg_id: str = "lan1") -> None:
    path = state_file(seg_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not state:
        path.unlink(missing_ok=True) if seg_id != "lan1" else path.write_text("{}")
        return
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".lan.")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def _known_state_ids() -> list[str]:
    ids = ["lan1"]
    folder = _data("lan.json").parent
    for p in sorted(folder.glob("lan-lan*.json")) if folder.exists() else []:
        ids.append(p.stem[len("lan-"):])
    return ids


# --- конфиг -----------------------------------------------------------------------------
def _seg_from(data: dict, item: dict | None, seg_id: str | None = None) -> LanConfig:
    return LanConfig.from_yaml(item, data.get("firewall"), seg_id)


def segments(data: dict | None = None) -> list[LanConfig]:
    data = store.load() if data is None else data
    out = [_seg_from(data, data.get("lan"), "lan1")]
    for item in data.get("lans") or []:
        out.append(_seg_from(data, item))
    return out


def get_config() -> LanConfig:
    """Основной сегмент (lan1) — для старых вызовов и CLI."""
    return segments()[0]


def get_segment(seg_id: str, data: dict | None = None) -> LanConfig:
    for s in segments(data):
        if s.id == seg_id:
            return s
    raise LanError(404, f"нет сегмента {seg_id}")


def renumber(ip: str, old_net, new_net, router_ip) -> str | None:
    """Тот же номер хоста в новой сети: 192.168.88.20 (/24) -> 192.168.1.20. None — не помещается."""
    try:
        offset = int(ipaddress.ip_address(ip)) - int(old_net.network_address)
    except ValueError:
        return None
    if offset <= 0 or offset >= new_net.num_addresses - 1:
        return None
    new = ipaddress.ip_address(int(new_net.network_address) + offset)
    return None if new == router_ip else str(new)


def coerce(seg_id: str, raw: dict) -> LanConfig:
    """Разобрать изменённый сегмент. Если сменилась сеть, а диапазон пула остался от старой —
    перенести его номера хостов в новую сеть (не помещаются — диапазон по умолчанию)."""
    old = get_segment(seg_id)
    raw = dict(raw)
    try:
        iface = ipaddress.ip_interface(str(raw.get("address") or ""))
    except ValueError:
        return LanConfig.model_validate(raw)           # ошибку адреса покажет сама модель
    nn = iface.network
    if old.network != nn and iface.version == 4:
        old_ip, new_ip = old.router_ip, str(iface.ip)
        opts = raw.get("dhcp_options")
        if isinstance(opts, dict):                     # опции DHCP, указывавшие на роутер, — на новый адрес
            opts = dict(opts)
            for k in ("dns_servers", "ntp_servers", "wins_servers", "tftp_servers_150", "sip_servers"):
                if isinstance(opts.get(k), list):
                    opts[k] = [new_ip if x == old_ip else x for x in opts[k]]
            if opts.get("tftp_server") == old_ip:
                opts["tftp_server"] = new_ip
            raw["dhcp_options"] = opts
        moved = False
        for k in ("pool_start", "pool_end"):
            v = raw.get(k)
            try:
                inside = v and ipaddress.ip_address(v) in nn
            except ValueError:
                continue
            if v and not inside:
                raw[k] = renumber(v, old.network, nn, iface.ip)
                moved = True
        if moved:
            try:
                return LanConfig.model_validate(raw)
            except ValueError:
                raw["pool_start"] = raw["pool_end"] = None
    return LanConfig.model_validate(raw)


def renumber_segment(old: LanConfig | None, new: LanConfig, static: list[dict]) -> tuple[LanConfig, list[dict]]:
    """Сеть сегмента сменилась: закреплённые адреса переезжают в новую сеть с тем же номером хоста.
    (Диапазон пула переносится раньше, в coerce: модель не примет пул вне сети.)"""
    if old is None or old.network == new.network:
        return new, static
    on, nn, rip = old.network, new.network, ipaddress.ip_interface(new.address).ip
    out = []
    for x in static:
        ip = x.get("ip")
        if ip and ipaddress.ip_address(ip) in on:
            moved = renumber(ip, on, nn, rip)
            x = {**x, "ip": moved} if moved else x
        out.append(x)
    return new, out


def _save_segment(data: dict, seg: LanConfig) -> None:
    """Записать сегмент в data (yaml), сохранив его закреплённые адреса."""
    lan_yaml, fw_yaml = seg.to_yaml()
    if seg.id == "lan1":
        keep = _static_raw(data, "lan1")
        if keep:
            lan_yaml["dhcp-server"]["static-leases"] = keep
        data["lan"] = lan_yaml
        data["firewall"] = {**(data.get("firewall") or {}), **fw_yaml}
        return
    items = data.get("lans") or []
    for i, item in enumerate(items):
        if item.get("id") == seg.id:
            keep = _static_raw(data, seg.id)
            if keep:
                lan_yaml["dhcp-server"]["static-leases"] = keep
            items[i] = lan_yaml
            break
    else:
        items.append(lan_yaml)
    data["lans"] = items


def _validate_all(segs: list[LanConfig]) -> None:
    ids = [s.id for s in segs]
    for s in segs:
        for t in s.forward_to:
            if t not in ids:
                raise LanError(400, f"{s.name}: транзит в несуществующий сегмент {t}")
    active = [s for s in segs if s.enabled]
    for i, a in enumerate(active):
        for b in active[i + 1:]:
            if a.network.overlaps(b.network):
                raise LanError(400, f"сети сегментов {a.name} ({a.network}) и {b.name} ({b.network}) пересекаются")
    used: dict[str, str] = {}
    vids: dict[int, str] = {}
    wan_ports = set(_wan_ports())
    for s in active:
        if s.id != "lan1" and not s.ports and not s.trunk_ports:
            raise LanError(400, f"{s.name}: выберите порты — дополнительный сегмент не может быть без портов")
        for p in s.ports:
            if p in used:
                raise LanError(400, f"порт {p} уже в сегменте {used[p]}")
            used[p] = s.name
        if s.vlan_id:
            if s.vlan_id in vids:
                raise LanError(400, f"VLAN {s.vlan_id} уже у сегмента {vids[s.vlan_id]}")
            vids[s.vlan_id] = s.name
            wan_vid = wan.get_config().vlan_id
            for p in s.trunk_ports:
                if p in wan_ports and wan_vid == s.vlan_id:
                    raise LanError(400, f"VLAN {s.vlan_id} на {p} уже занят WAN")


# --- порты -------------------------------------------------------------------------
def wan_interface() -> str | None:
    try:
        return wan.load_state().get("interface") or wan.resolve_interface(wan.get_config())
    except wan.WanError:
        return None


def _wan_ports() -> list[str]:
    """Интерфейсы WAN (оба провайдера) и, если WAN на VLAN, физические порты (без тега они не годятся для LAN)."""
    try:
        st = wan.load_state()
    except Exception:
        st = {}
    out = [x for x in (st.get("interface"), st.get("base")) if x]
    if not out:
        w = wan_interface()
        out = [w] if w else []
    try:
        out += [x for x in wan.physical_ports() if x not in out]
    except Exception:  # noqa: BLE001 — второй WAN не должен ломать LAN
        pass
    return out


def lan_ports(cfg: LanConfig, wan_if: str | None, taken: set[str] = frozenset()) -> list[str]:
    """Порты сегмента без тега. lan1 с «auto» — все свободные, кроме WAN и портов других сегментов."""
    existing = set(wan.candidates())
    exclude = set(_wan_ports()) | ({wan_if} if wan_if else set())
    if cfg.ports:
        return [p for p in cfg.ports if p in existing and p not in exclude]
    if cfg.id != "lan1":
        return []
    return [p for p in sorted(existing) if p not in exclude and p not in taken]


def _check_overlap(cfg: LanConfig, wan_if: str | None) -> None:
    lan_net = cfg.network
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


# --- мосты -------------------------------------------------------------------------
def teardown(state: dict, seg_id: str = "lan1") -> None:
    """Вернуть всё, как было до включения сегмента."""
    bridge = state.get("bridge_name") or (BRIDGE if seg_id == "lan1" else f"br-{seg_id}")
    if state.get("address"):
        try:
            netlink.addr_del(bridge, state["address"])
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
    for vif in state.get("vlans", []):
        try:
            netlink.link_delete(vif)
        except netlink.NetlinkOpError as e:
            print(f"[lan] WARNING: {e}")
    if state.get("bridge"):
        netlink.link_delete(bridge)
    save_state({}, seg_id)


def setup(cfg: LanConfig, wan_if: str, taken: set[str] = frozenset()) -> list[str]:
    _check_overlap(cfg, wan_if)
    ports = lan_ports(cfg, wan_if, taken)
    bridge = cfg.bridge

    state: dict = {"bridge": True, "bridge_name": bridge, "ports": [], "moved": [], "address": None, "vlans": []}
    mac = netlink.link_info(ports[0]).get("mac") if ports else None
    netlink.bridge_create(bridge, mac)
    save_state(state, cfg.id)

    for port in ports:
        # адреса порта переезжают на мост (иначе порт моста с IP работает некорректно)
        for ifname, cidr in netlink.kernel_ipv4_addresses():
            if ifname == port:
                netlink.addr_del(port, cidr)
                state["moved"].append([port, cidr])
                netlink.addr_add(bridge, cidr)
        netlink.link_set_master(port, bridge)
        netlink.link_set_up(port)
        state["ports"].append(port)
        save_state(state, cfg.id)

    existing = set(wan.candidates())
    for parent in cfg.trunk_ports if cfg.vlan_id else []:
        if parent not in existing:
            print(f"[lan] WARNING: {cfg.name}: порта {parent} нет — VLAN {cfg.vlan_id} на нём пропущен")
            continue
        vif = netlink.vlan_name(parent, cfg.vlan_id)
        netlink.link_set_up(parent)
        netlink.vlan_create(vif, parent, cfg.vlan_id)
        state["vlans"].append(vif)
        save_state(state, cfg.id)
        netlink.link_set_master(vif, bridge)
        netlink.link_set_up(vif)

    netlink.link_set_up(bridge)
    netlink.addr_add(bridge, cfg.address)
    state["address"] = cfg.address
    save_state(state, cfg.id)
    tagged = f", VLAN {cfg.vlan_id} на {', '.join(cfg.trunk_ports)}" if state["vlans"] else ""
    print(f"[lan] {cfg.name}: {bridge} {cfg.address}, порты: {', '.join(ports) or 'нет'}{tagged}")
    return ports


def segment_active(cfg: LanConfig) -> bool:
    st = load_state(cfg.id)
    return bool(st.get("address")) and (cfg.bridge, st["address"]) in set(netlink.kernel_ipv4_addresses())


def _apply_all(segs: list[LanConfig]) -> None:
    """Пересобрать все сегменты, затем DHCP, DNS и фаервол."""
    for sid in _known_state_ids():
        teardown(load_state(sid), sid)
    active = [s for s in segs if s.enabled]
    if active:
        wan_if = wan_interface()
        if not wan_if:
            raise LanError(400, "сначала нужен WAN: интерфейс WAN не найден")
        taken = {p for s in active if s.id != "lan1" for p in s.ports}
        for s in sorted(active, key=lambda x: x.id != "lan1"):
            setup(s, wan_if, taken)
    try:
        firewall.refresh(segs[0])          # NAT и правила с учётом WAN, всех LAN и VPN
    except firewall.FirewallError as e:
        raise LanError(500, str(e)) from e
    _services(segs)


def _services(segs: list[LanConfig] | None = None) -> None:
    """DHCP (Kea) и DNS (BIND) по текущим сегментам."""
    from app.services import dhcp, dns
    segs = segs if segs is not None else segments()
    try:
        dhcp.apply(_dhcp_segments(segs), dns.upstream(dns.get_config()))
    except dhcp.DhcpError as e:
        raise LanError(e.status, e.message) from e
    try:
        dns.apply()
    except dns.DnsError as e:
        raise LanError(e.status, e.message) from e
    from app.services import files
    try:
        files.apply()             # Samba слушает мосты сегментов — они могли смениться
    except files.FilesError as e:
        print(f"[lan] WARNING: файловый сервер: {e.message}")
    from app.services import ntp
    try:
        if ntp.serves_lan():
            ntp.apply()           # раздача времени — сетям сегментов (allow)
    except ntp.NtpError as e:
        print(f"[lan] WARNING: NTP: {e.message}")
    from app.services import qos
    try:
        qos.apply()               # очереди висят на мостах сегментов и на WAN — они могли смениться
    except qos.QosError as e:
        print(f"[lan] WARNING: QoS: {e.message}")


def _dhcp_segments(segs: list[LanConfig]):
    return [(s, static_leases(s.id)) for s in segs if s.enabled and s.dhcp_enabled]


def reload_dhcp() -> None:
    from app.services import dhcp, dns
    segs = segments()
    dhcp.apply(_dhcp_segments(segs), dns.upstream(dns.get_config()))


def apply(cfg: LanConfig | None = None) -> None:
    """Совместимость: применить все сегменты (cfg — новый lan1, ещё не сохранённый)."""
    with _lock:
        segs = segments()
        if cfg is not None:
            segs = [cfg] + segs[1:]
        _apply_all(segs)


def _transaction(change) -> list[LanConfig]:
    """Изменить сегменты в router.yaml и применить; ошибка — откат и к файлу, и к системе."""
    from app.services import dns
    with _lock:
        before = store.load()
        snapshot = json.loads(json.dumps({k: before.get(k) for k in ("lan", "lans", "firewall")}))
        with store.transaction() as data:
            change(data)
            segs = segments(data)
            _validate_all(segs)
        try:
            for s in segs:
                if s.enabled and s.domain:
                    dns.ensure_zone(s.domain)
            _apply_all(segs)
        except (netlink.NetlinkOpError, LanError) as e:
            with store.transaction() as data:
                for k, v in snapshot.items():
                    if v is None:
                        data.pop(k, None)
                    else:
                        data[k] = v
            try:
                _apply_all(segments())
            except Exception as rollback_err:
                print(f"[lan] ERROR: откат не удался: {rollback_err}")
            if isinstance(e, LanError):
                raise
            raise LanError(400, str(e)) from e
        return segs


def _update_with_renumber(data: dict, seg_id: str, new: LanConfig) -> None:
    old = next((s for s in segments(data) if s.id == seg_id), None)
    new, static = renumber_segment(old, new, _static_raw(data, seg_id))
    _save_segment(data, new)
    if static:
        item = data["lan"] if seg_id == "lan1" else next(i for i in data["lans"] if i.get("id") == seg_id)
        item.setdefault("dhcp-server", {})["static-leases"] = static


def update(new: LanConfig) -> LanStatus:
    """Основной сегмент (PUT /api/lan). Смена сети — диапазон и закреплённые адреса переезжают следом."""
    new = new.model_copy(update={"id": "lan1"})
    _transaction(lambda data: _update_with_renumber(data, "lan1", new))
    return status()


def update_segment(seg_id: str, new: LanConfig) -> list[SegmentStatus]:
    get_segment(seg_id)
    new = new.model_copy(update={"id": seg_id})
    _transaction(lambda data: _update_with_renumber(data, seg_id, new))
    return segments_status()


def add_segment(new: LanConfig) -> list[SegmentStatus]:
    segs = segments()
    if len(segs) >= MAX_SEGMENTS:
        raise LanError(400, f"не больше {MAX_SEGMENTS} сегментов")
    ids = {s.id for s in segs}
    seg_id = next(f"lan{i}" for i in range(2, 100) if f"lan{i}" not in ids)
    name = new.name if new.name != "LAN" else seg_id.upper()
    new = new.model_copy(update={"id": seg_id, "name": name})
    _transaction(lambda data: _save_segment(data, new))
    return segments_status()


def delete_segment(seg_id: str) -> list[SegmentStatus]:
    if seg_id == "lan1":
        raise LanError(400, "основной сегмент нельзя удалить — его можно выключить")
    get_segment(seg_id)

    def change(data):
        data["lans"] = [i for i in data.get("lans") or [] if i.get("id") != seg_id]
        for item in [data.get("lan") or {}, *(data.get("lans") or [])]:
            if seg_id in (item.get("forward-to") or []):
                item["forward-to"] = [x for x in item["forward-to"] if x != seg_id]
    _transaction(change)
    return segments_status()


def update_dhcp(seg_id: str, new: DhcpSettings) -> DhcpStatus:
    """Вкладка DHCP: пул, срок, опции — без пересборки моста."""
    seg = get_segment(seg_id)
    try:
        merged = LanConfig.model_validate({**seg.model_dump(), **new.model_dump()})
    except ValueError as e:
        raise LanError(422, str(e)) from e
    from app.services import dhcp
    with _lock:
        before = json.loads(json.dumps({k: store.load().get(k) for k in ("lan", "lans")}))
        with store.transaction() as data:
            _save_segment(data, merged)
        try:
            reload_dhcp()
        except dhcp.DhcpError as e:
            with store.transaction() as data:
                for k, v in before.items():
                    if v is None:
                        data.pop(k, None)
                    else:
                        data[k] = v
            try:
                reload_dhcp()
            except dhcp.DhcpError:
                pass
            raise LanError(e.status, e.message) from e
    return dhcp_status()


def on_wan_changed() -> None:
    """WAN поменялся (интерфейс или режим) — пересобрать LAN, NAT и фаервол."""
    segs = segments()
    if any(s.enabled for s in segs):
        try:
            with _lock:
                _apply_all(segs)
        except (netlink.NetlinkOpError, LanError) as e:
            print(f"[lan] ERROR после смены WAN: {e}")


def apply_startup() -> None:
    segs = segments()
    if not any(s.enabled for s in segs):
        for sid in _known_state_ids():
            teardown(load_state(sid), sid)   # остатки от прошлого запуска (режим host)
        _services(segs)
        return
    _wait_for_ports()
    with _lock:
        _apply_all(segs)


def stop_services() -> None:
    from app.services import dhcp, dns
    dhcp.stop()
    dns.stop()


# --- аренды и закреплённые адреса ----------------------------------------------------
def _static_raw(data: dict, seg_id: str = "lan1") -> list[dict]:
    if seg_id == "lan1":
        item = data.get("lan") or {}
    else:
        item = next((i for i in data.get("lans") or [] if i.get("id") == seg_id), {})
    return ((item.get("dhcp-server") or {}).get("static-leases")) or []


def static_leases(seg_id: str = "lan1") -> list[StaticLease]:
    return [StaticLease(**x) for x in _static_raw(store.load(), seg_id)]


def all_static() -> list[StaticLease]:
    return [x for s in segments() for x in static_leases(s.id)]


def leases() -> list[Lease]:
    from app.services import dhcp
    segs = segments()
    subnets = {dhcp.subnet_id(s): s.id for s in segs}
    static = {l.mac: l for l in all_static()}
    out = []
    for l in dhcp.read_leases(subnets):
        st = static.get(l.mac)
        out.append(l.model_copy(update={"static": st is not None, "name": st.name if st else None}))
    return out


def static_view(cfg: LanConfig | None = None) -> list[StaticLeaseView]:
    cfg = cfg or get_config()
    start, end = ipaddress.ip_address(cfg.pool_start), ipaddress.ip_address(cfg.pool_end)
    out = []
    for l in static_leases(cfg.id):
        ip = ipaddress.ip_address(l.ip)
        out.append(StaticLeaseView(**l.model_dump(), in_pool=start <= ip <= end,
                                   valid=ip in cfg.network and str(ip) != cfg.router_ip))
    return sorted(out, key=lambda x: ipaddress.ip_address(x.ip))


def _validate_static(cfg: LanConfig, item: StaticLease, others: list[StaticLease]) -> None:
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


def _save_static(seg_id: str, items: list[StaticLease]) -> None:
    raw = [i.model_dump(exclude_none=True) for i in items]
    with store.transaction() as data:
        if seg_id == "lan1":
            lan_cfg = data.get("lan") or {}
            lan_cfg.setdefault("dhcp-server", {})["static-leases"] = raw
            data["lan"] = lan_cfg
        else:
            for item in data.get("lans") or []:
                if item.get("id") == seg_id:
                    item.setdefault("dhcp-server", {})["static-leases"] = raw
    from app.services import dhcp
    try:
        reload_dhcp()
    except dhcp.DhcpError as e:
        print(f"[lan] WARNING: DHCP: {e.message}")


def _seg_for_static(seg_id: str | None, ip: str | None = None) -> LanConfig:
    if seg_id:
        return get_segment(seg_id)
    if ip:   # старый API без сегмента: по адресу
        for s in segments():
            if ipaddress.ip_address(ip) in s.network:
                return s
    return get_config()


def add_static(item: StaticLease, seg_id: str | None = None) -> list[StaticLeaseView]:
    with _lock:
        cfg = _seg_for_static(seg_id, item.ip)
        items = static_leases(cfg.id)
        _validate_static(cfg, item, [x for x in all_static()])
        _save_static(cfg.id, items + [item])
        return static_view(get_segment(cfg.id))


def _find_static(mac: str, seg_id: str | None) -> LanConfig:
    for s in ([get_segment(seg_id)] if seg_id else segments()):
        if any(i.mac == mac for i in static_leases(s.id)):
            return s
    raise LanError(404, f"MAC {mac} не закреплён")


def update_static(mac: str, item: StaticLease, seg_id: str | None = None) -> list[StaticLeaseView]:
    mac = mac.lower()
    with _lock:
        cfg = _find_static(mac, seg_id)
        items = static_leases(cfg.id)
        others = [i for i in all_static() if i.mac != mac]
        _validate_static(cfg, item, others)
        _save_static(cfg.id, [item if i.mac == mac else i for i in items])
        return static_view(get_segment(cfg.id))


def delete_static(mac: str, seg_id: str | None = None) -> list[StaticLeaseView]:
    mac = mac.lower()
    with _lock:
        cfg = _find_static(mac, seg_id)
        _save_static(cfg.id, [i for i in static_leases(cfg.id) if i.mac != mac])
        return static_view(get_segment(cfg.id))


# --- статус ----------------------------------------------------------------------------
def segments_status() -> list[SegmentStatus]:
    all_leases = leases()
    out = []
    for s in segments():
        st = load_state(s.id)
        out.append(SegmentStatus(config=s, bridge=s.bridge, active=segment_active(s),
                                 ports=st.get("ports", []),
                                 clients=sum(1 for l in all_leases if l.lan == s.id)))
    return out


def status() -> LanStatus:
    from app.services import dhcp, dns
    segs = segments()
    cfg = segs[0]
    wan_if = wan_interface()
    in_seg = {p: s.id for s in segs for p in load_state(s.id).get("ports", [])}
    tagged: dict[str, list[str]] = {}
    for s in segs:
        if s.vlan_id and load_state(s.id).get("vlans"):
            for p in s.trunk_ports:
                tagged.setdefault(p, []).append(f"{s.vlan_id} ({s.name})")
    wan_vid = wan.get_config().vlan_id
    wan_ports = _wan_ports()

    ports = []
    for name in sorted((set(wan.candidates()) | set(in_seg)) - {w for w in wan_ports if "." in w}):
        info = netlink.link_info(name)
        is_wan = name in wan_ports
        role = "wan" if is_wan else ("lan" if name in in_seg or name in tagged else "none")
        vl = list(tagged.get(name, []))
        if is_wan and wan_vid:
            vl.insert(0, f"{wan_vid} (WAN)")
        ports.append(Port(name=name, role=role, segment=in_seg.get(name), vlans=vl, **info))
    ports.sort(key=lambda p: (p.role != "wan", p.name))

    all_leases = leases()
    return LanStatus(
        config=cfg,
        active=segment_active(cfg),
        bridge=BRIDGE,
        wan_interface=wan_if,
        ports=ports,
        dns_dhcp_running=dhcp.running() or dns.running(),
        leases=[l for l in all_leases if l.lan == "lan1"],
        static_leases=static_view(cfg),
        segments=segments_status(),
    )


def dhcp_status() -> DhcpStatus:
    from app.services import dhcp
    segs = segments()
    views = []
    for s in segs:
        views.append(DhcpSegmentView(
            id=s.id, name=s.name, bridge=s.bridge, enabled=s.enabled, address=s.address,
            network=str(s.network), domain=s.domain, dns_enabled=s.dns_enabled,
            settings=DhcpSettings(dhcp_enabled=s.dhcp_enabled, pool_start=s.pool_start, pool_end=s.pool_end,
                                  lease_time=s.lease_time, dhcp_options=s.dhcp_options),
            static_leases=static_view(s)))
    need = any(s.enabled and s.dhcp_enabled for s in segs)
    st = DhcpStatus(running=dhcp.running(), installed=dhcp.installed(), segments=views, leases=leases())
    if need and not st.installed:
        st.error = "нет Kea DHCP в образе — пересоберите образ (docker compose build)"
    elif need and not st.running:
        st.error = "Kea не запущен — см. docker logs"
    return st
