"""Работа с интерфейсами через netlink (pyroute2)."""
from pyroute2 import IPRoute

from app.models.interface import Interface

IFF_RUNNING = 0x40  # флаг "линк есть"


def _collect() -> list[Interface]:
    result: list[Interface] = []
    with IPRoute() as ipr:
        # адреса: index -> ["192.168.1.1/24", ...]
        addrs: dict[int, list[str]] = {}
        for a in ipr.get_addr():
            ip = a.get_attr("IFA_ADDRESS")
            if ip:
                addrs.setdefault(a["index"], []).append(f"{ip}/{a['prefixlen']}")

        for link in ipr.get_links():
            stats = link.get_attr("IFLA_STATS64") or {}
            result.append(
                Interface(
                    index=link["index"],
                    name=link.get_attr("IFLA_IFNAME"),
                    mac=link.get_attr("IFLA_ADDRESS"),
                    mtu=link.get_attr("IFLA_MTU"),
                    state=(link.get_attr("IFLA_OPERSTATE") or "unknown").lower(),
                    running=bool(link["flags"] & IFF_RUNNING),
                    addresses=addrs.get(link["index"], []),
                    rx_bytes=stats.get("rx_bytes", 0),
                    tx_bytes=stats.get("tx_bytes", 0),
                )
            )
    return result


def list_interfaces() -> list[Interface]:
    return _collect()


def get_interface(name: str) -> Interface | None:
    return next((i for i in _collect() if i.name == name), None)
