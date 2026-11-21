"""
Низкоуровневые операции с ядром через netlink (pyroute2).

Единственное место, где код трогает сеть системы. Всё остальное
(API, CLI, агент) работает через сервисы, которые вызывают эти функции.
"""
from __future__ import annotations

import errno
import ipaddress


class NetlinkOpError(Exception):
    pass


def _ipr():
    from pyroute2 import IPRoute  # импорт здесь — чтобы тесты работали без pyroute2
    return IPRoute()


def link_names() -> set[str]:
    with _ipr() as ipr:
        return {l.get_attr("IFLA_IFNAME") for l in ipr.get_links()}


def _index(ipr, ifname: str) -> int:
    idx = ipr.link_lookup(ifname=ifname)
    if not idx:
        raise NetlinkOpError(f"интерфейс {ifname} не найден")
    return idx[0]


def link_info(ifname: str) -> dict:
    """{'mac': ..., 'link_up': bool} или {} если интерфейса нет."""
    with _ipr() as ipr:
        idx = ipr.link_lookup(ifname=ifname)
        if not idx:
            return {}
        link = ipr.get_links(idx[0])[0]
        return {"mac": link.get_attr("IFLA_ADDRESS"), "link_up": bool(link["flags"] & 0x40)}


def link_set_up(ifname: str) -> None:
    """ip link set <ifname> up"""
    with _ipr() as ipr:
        ipr.link("set", index=_index(ipr, ifname), state="up")


def link_set_mtu(ifname: str, mtu: int) -> None:
    with _ipr() as ipr:
        ipr.link("set", index=_index(ipr, ifname), mtu=mtu)


def wireguard_create(name: str) -> None:
    """ip link add <name> type wireguard (модуль ядра хоста)."""
    from pyroute2 import NetlinkError
    with _ipr() as ipr:
        if ipr.link_lookup(ifname=name):
            return
        try:
            ipr.link("add", ifname=name, kind="wireguard")
        except NetlinkError as e:
            raise NetlinkOpError(
                f"не удалось создать {name}: модуль ядра wireguard недоступен "
                f"(на хосте выполните: sudo modprobe wireguard) — {e}") from e


# --- мост (bridge) --------------------------------------------------------------
def bridge_create(name: str, mac: str | None = None) -> None:
    """ip link add <name> type bridge (без STP и задержки — порты работают сразу)."""
    from pyroute2 import NetlinkError
    with _ipr() as ipr:
        if not ipr.link_lookup(ifname=name):
            try:
                ipr.link("add", ifname=name, kind="bridge", br_stp_state=0, br_forward_delay=0)
            except NetlinkError as e:
                raise NetlinkOpError(f"не удалось создать мост {name}: {e}") from e
        if mac:  # MAC моста = MAC первого порта: соседи (ARP) не заметят переезда адреса
            ipr.link("set", index=_index(ipr, name), address=mac)


def vlan_name(parent: str, vid: int) -> str:
    """eth1 + 10 -> eth1.10 (имя интерфейса в Linux — не длиннее 15 символов)."""
    suffix = f".{vid}"
    return parent[: 15 - len(suffix)] + suffix


def vlan_create(name: str, parent: str, vid: int) -> None:
    """ip link add link <parent> name <name> type vlan id <vid>."""
    from pyroute2 import NetlinkError
    with _ipr() as ipr:
        if ipr.link_lookup(ifname=name):
            return
        try:
            ipr.link("add", ifname=name, kind="vlan", link=_index(ipr, parent), vlan_id=vid)
        except NetlinkError as e:
            raise NetlinkOpError(f"не удалось создать VLAN {vid} на {parent}: {e}") from e


def link_delete(name: str) -> None:
    with _ipr() as ipr:
        idx = ipr.link_lookup(ifname=name)
        if idx:
            ipr.link("del", index=idx[0])


def link_set_master(port: str, bridge: str | None) -> None:
    """ip link set <port> master <bridge>  /  nomaster (bridge=None)."""
    from pyroute2 import NetlinkError
    with _ipr() as ipr:
        try:
            idx = _index(ipr, port)
        except NetlinkOpError:
            if bridge is None:
                return
            raise
        master = _index(ipr, bridge) if bridge else 0
        try:
            ipr.link("set", index=idx, master=master)
        except NetlinkError as e:
            raise NetlinkOpError(f"не удалось подключить {port} к {bridge}: {e}") from e


def kernel_ipv4_addresses() -> list[tuple[str, str]]:
    """[(ifname, '192.168.1.1/24'), ...] — IPv4-адреса, реально назначенные в ядре."""
    with _ipr() as ipr:
        names = {l["index"]: l.get_attr("IFLA_IFNAME") for l in ipr.get_links()}
        out = []
        for a in ipr.get_addr(family=2):  # AF_INET
            ip = a.get_attr("IFA_ADDRESS")
            if ip:
                out.append((names.get(a["index"], str(a["index"])), f"{ip}/{a['prefixlen']}"))
        return out


def addr_add(ifname: str, cidr: str) -> None:
    from pyroute2 import NetlinkError
    iface = ipaddress.ip_interface(cidr)
    kwargs = {"address": str(iface.ip), "prefixlen": iface.network.prefixlen}
    if iface.version == 4 and iface.network.prefixlen <= 30:
        kwargs["broadcast"] = str(iface.network.broadcast_address)  # как делает RouterOS
    with _ipr() as ipr:
        try:
            ipr.addr("add", index=_index(ipr, ifname), **kwargs)
        except NetlinkError as e:
            if e.code != errno.EEXIST:  # уже есть — это нормально
                raise NetlinkOpError(f"не удалось добавить {cidr} на {ifname}: {e}") from e


def addr_del(ifname: str, cidr: str) -> None:
    from pyroute2 import NetlinkError
    iface = ipaddress.ip_interface(cidr)
    with _ipr() as ipr:
        try:
            idx = _index(ipr, ifname)
        except NetlinkOpError:
            return  # интерфейса нет — удалять нечего
        try:
            ipr.addr("del", index=idx, address=str(iface.ip), prefixlen=iface.network.prefixlen)
        except NetlinkError as e:
            if e.code not in (errno.EADDRNOTAVAIL, errno.ENODEV):
                raise NetlinkOpError(f"не удалось удалить {cidr} с {ifname}: {e}") from e


# --- маршруты -----------------------------------------------------------------
RT_TABLE_MAIN = 254
RTN_UNICAST = 1
RT_SCOPE_LINK = 253
RTPROT_KERNEL = 2   # connected — ядро создаёт само при назначении адреса
RTPROT_BGP, RTPROT_OSPF = 186, 188   # так помечает маршруты zebra (FRRouting)
RTPROT_STATIC = 4   # наши статические маршруты помечаем этим proto
RTPROT_DHCP = 16    # маршрут по умолчанию, полученный DHCP-клиентом WAN


def kernel_ipv4_routes() -> list[dict]:
    """Маршруты основной таблицы:
    [{'dst': '0.0.0.0/0', 'gateway': '172.18.0.1', 'interface': 'eth0', 'metric': 0, 'proto': 3}, ...]
    """
    with _ipr() as ipr:
        names = {l["index"]: l.get_attr("IFLA_IFNAME") for l in ipr.get_links()}
        out = []
        for r in ipr.get_routes(family=2, table=RT_TABLE_MAIN):
            if r["type"] != RTN_UNICAST:
                continue
            dst = r.get_attr("RTA_DST") or "0.0.0.0"
            out.append({
                "dst": f"{dst}/{r['dst_len']}",
                "gateway": r.get_attr("RTA_GATEWAY"),
                "interface": names.get(r.get_attr("RTA_OIF")),
                "metric": r.get_attr("RTA_PRIORITY") or 0,
                "proto": r["proto"],
            })
        return out


def _route_kwargs(ipr, dst: str, gateway: str | None, ifname: str | None, metric: int) -> dict:
    net = ipaddress.ip_network(dst)
    kw = {"dst_len": net.prefixlen, "priority": metric, "table": RT_TABLE_MAIN}
    if net.prefixlen:
        kw["dst"] = str(net.network_address)
    if gateway:
        kw["gateway"] = gateway
    if ifname:
        kw["oif"] = _index(ipr, ifname)
        if not gateway:
            kw["scope"] = RT_SCOPE_LINK  # как `ip route add ... dev eth1`
    return kw


def _route_present(dst, gateway, ifname, metric) -> bool:
    for r in kernel_ipv4_routes():
        if r["dst"] == dst and r["metric"] == metric:
            if gateway and r["gateway"] == gateway:
                return True
            if not gateway and r["interface"] == ifname and not r["gateway"]:
                return True
    return False


def route_add(dst: str, gateway: str | None = None, ifname: str | None = None, metric: int = 1,
              proto: int = RTPROT_STATIC) -> None:
    from pyroute2 import NetlinkError
    via = gateway or ifname
    with _ipr() as ipr:
        kw = _route_kwargs(ipr, dst, gateway, ifname, metric)
        try:
            ipr.route("add", proto=proto, **kw)
        except NetlinkError as e:
            if e.code == errno.EEXIST:
                if _route_present(dst, gateway, ifname, metric):
                    return  # точно такой маршрут уже есть
                raise NetlinkOpError(
                    f"маршрут {dst} с distance={metric} уже существует через другой шлюз") from e
            if e.code == errno.ENETUNREACH:
                raise NetlinkOpError(
                    f"шлюз {via} недоступен: нет подключённой сети, в которую он входит") from e
            raise NetlinkOpError(f"не удалось добавить маршрут {dst} via {via}: {e}") from e


def route_del(dst: str, gateway: str | None = None, ifname: str | None = None, metric: int = 1) -> None:
    from pyroute2 import NetlinkError
    with _ipr() as ipr:
        try:
            kw = _route_kwargs(ipr, dst, gateway, ifname, metric)
        except NetlinkOpError:
            return  # интерфейса нет — маршрута тоже нет
        try:
            ipr.route("del", **kw)
        except NetlinkError as e:
            if e.code not in (errno.ESRCH, errno.ENODEV):
                raise NetlinkOpError(f"не удалось удалить маршрут {dst}: {e}") from e
