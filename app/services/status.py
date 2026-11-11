"""
Status — сводка на стартовой странице: WAN, VPN, LAN, система, трафик интерфейсов.
Каждый блок собирается независимо: ошибка в одном не ломает всю страницу.
"""
from __future__ import annotations

import time


def _safe(fn):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 — сводка должна показаться в любом случае
        return {"error": str(e)}


def _system() -> dict:
    from app.services import system
    r = system.resource()
    return {k: r.get(k) for k in ("identity", "version", "mode", "uptime", "cpu_percent", "temperature", "model")} | {
        "memory_percent": r["memory"].get("percent"), "disk_percent": r["disk"].get("percent"),
        "safe_mode": system.safe_mode.status()["active"]}


def _wan() -> dict:
    from app.services import wan
    w = wan.status()
    return {"interface": w.interface, "link_up": w.link_up, "mode": w.config.mode, "state": w.dhcp_state,
            "addresses": w.addresses, "gateway": w.gateway, "dns": w.dns}


def _lan() -> dict:
    from app.services import lan
    l = lan.status()
    lan_ports = [p for p in l.ports if p.role == "lan"]
    now = time.time()
    active_leases = [x for x in l.leases if x.expires is None or x.expires > now]
    return {"enabled": l.config.enabled, "active": l.active, "address": l.config.address,
            "ports": len(lan_ports), "ports_up": sum(p.link_up for p in lan_ports),
            "dhcp": l.config.dhcp_enabled, "dns_dhcp_running": l.dns_dhcp_running,
            "clients": len(active_leases), "static": len(l.static_leases)}


def _vpn() -> dict:
    from app.services import vpn
    kind = vpn.enabled_kind()
    if not kind:
        return {"enabled": None}
    st = vpn.status(kind)
    cfg = st.config
    out = {"enabled": kind, "mode": cfg.mode, "killswitch": cfg.killswitch and cfg.mode == "full",
           "connected": st.connected, "endpoint": getattr(cfg, "endpoint", None) or getattr(cfg, "server", None),
           "endpoint_ip": st.endpoint_ip, "rx_bytes": st.rx_bytes, "tx_bytes": st.tx_bytes, "error": st.error}
    if kind == "l2tp":
        out.update(ipsec_up=st.ipsec_up, tunnel_ip=st.local_ip)
    else:
        out.update(latest_handshake=st.latest_handshake, tunnel_ip=(cfg.addresses or [None])[0])
    return out


def _firewall() -> dict:
    from app.services import firewall, firewall_rules
    return {"active": firewall.is_active(), "rules": len([r for _, r in firewall_rules.rules() if r.enabled]),
            "forwards": len([f for _, f in firewall_rules.forwards() if f.enabled])}


def _traffic() -> list[dict]:
    from app.services import interfaces, lan, wan
    wan_if = (wan.load_state().get("interface") or None)
    lan_ports = set(lan.load_state().get("ports", []))
    vpn_ifaces = {"wg0", "awg0", "l2tp0"}
    out = []
    for i in interfaces.list_interfaces():
        if i.name == "lo":
            continue
        role = ("wan" if i.name == wan_if else "lan" if i.name == lan.BRIDGE or i.name in lan_ports
                else "vpn" if i.name in vpn_ifaces else "")
        out.append({"name": i.name, "role": role, "running": i.running,
                    "rx_bytes": i.rx_bytes, "tx_bytes": i.tx_bytes})
    return out


def overview() -> dict:
    return {"time": time.time(), "system": _safe(_system), "wan": _safe(_wan), "lan": _safe(_lan),
            "vpn": _safe(_vpn), "firewall": _safe(_firewall), "traffic": _safe(_traffic)}
