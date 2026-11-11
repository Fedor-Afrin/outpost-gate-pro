"""
Обработчик событий DHCP-клиента WAN (вызывается из udhcpc-hook.sh).

  deconfig            — аренды нет: убрать адрес и маршрут, которые ставили раньше
  bound / renew       — аренда получена: адрес на WAN, шлюз -> маршрут по умолчанию
  leasefail / nak     — сервер не ответил / отказал: ждём, udhcpc повторит сам
"""
from __future__ import annotations

import ipaddress
import os
import sys
import time

from app.services import netlink, wan


def _lease_from_env(env) -> tuple[str, str | None, list[str], int]:
    ip = env["ip"]
    prefix = env.get("mask") or ipaddress.ip_network(f"0.0.0.0/{env.get('subnet', '255.255.255.255')}").prefixlen
    address = str(ipaddress.ip_interface(f"{ip}/{prefix}"))
    routers = (env.get("router") or "").split()
    dns = (env.get("dns") or "").split()
    lease = int(env.get("lease") or 0)
    return address, (routers[0] if routers else None), dns, lease


def handle(event: str, env=os.environ) -> None:
    state = wan.load_state()
    ifname = env.get("interface") or state.get("interface")

    if event == "deconfig":
        wan.cleanup(state)
        state.update(interface=ifname, state="searching", address=None, gateway=None, dns=[],
                     lease_expires=None)
        print(f"[dhcp] {ifname}: нет аренды, ищу DHCP-сервер")

    elif event in ("bound", "renew"):
        address, gateway, dns, lease = _lease_from_env(env)
        if state.get("address") and state["address"] != address:
            netlink.addr_del(ifname, state["address"])
        netlink.addr_add(ifname, address)
        if state.get("gateway") and state["gateway"] != gateway:
            netlink.route_del("0.0.0.0/0", state["gateway"], None, wan.WAN_METRIC)
        if gateway:
            netlink.route_add("0.0.0.0/0", gateway, None, wan.WAN_METRIC, proto=netlink.RTPROT_DHCP)
        state.update(interface=ifname, state="bound", address=address, gateway=gateway, dns=dns,
                     lease_expires=time.time() + lease if lease else None)
        wan.write_upstream_dns(wan.get_config().dns or dns)   # DNS, заданные вручную, важнее
        from app.services import vpn
        vpn.refresh_endpoint_route()      # шлюз мог смениться — маршрут до VPN-сервера через новый
        print(f"[dhcp] {ifname}: {event} {address} gw {gateway} dns {' '.join(dns)} lease {lease}s")

    elif event in ("leasefail", "nak"):
        state["state"] = "searching"
        print(f"[dhcp] {ifname}: {event}")

    wan.save_state(state)


if __name__ == "__main__":
    try:
        handle(sys.argv[1] if len(sys.argv) > 1 else "")
    except Exception as e:  # ошибка хука не должна убивать DHCP-клиент
        print(f"[dhcp] ERROR: {e}", file=sys.stderr)
