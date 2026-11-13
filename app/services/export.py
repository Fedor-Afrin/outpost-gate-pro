"""
Экспорт конфигурации текстом, как /export в RouterOS: меню и команды add/set.

Читается и сравнивается (diff) лучше, чем router.yaml. Секреты (ключи VPN, пароли, токены,
community SNMP) по умолчанию скрыты — как в RouterOS 7; show_sensitive=True — показать.
Команды записаны в синтаксисе CLI роутера; источник правды по-прежнему router.yaml
(System → Резервные копии).
"""
from __future__ import annotations

import re
from datetime import datetime

from app.models.dns import DnsConfig
from app.models.files import FilesConfig
from app.models.l2tp import L2tpConfig
from app.models.monitoring import MonitoringConfig
from app.models.ntp import NtpConfig
from app.models.qos import QosConfig
from app.models.routing import RoutingConfig
from app.models.scheduler import Task
from app.models.wan import MultiWanConfig, Wan2Config, WanConfig
from app.models.wireguard import WgConfig

SAFE = re.compile(r"^[A-Za-z0-9_.:/@*+,\-]+$")


def q(v) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        v = ",".join(str(x) for x in v)
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    s = "" if v is None else str(v)
    if s and SAFE.match(s):
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def line(verb: str, *pairs: tuple[str, object], find: str | None = None) -> str:
    parts = [verb] + ([f"[ find {find} ]"] if find else [])
    for k, v in pairs:
        if v is None or v == [] or v == "":
            continue
        parts.append(f"{k}={q(v)}")
    return " ".join(parts)


def _limit(up, down) -> str:
    """RouterOS: max-limit=отдача/загрузка, 0 — без ограничения."""
    f = lambda x: f"{int(x) if float(x).is_integer() else x}M" if x else "0"  # noqa: E731
    return f"{f(up)}/{f(down)}"


class _Out:
    def __init__(self):
        self.lines: list[str] = []

    def menu(self, path: str, items: list[str]) -> None:
        items = [x for x in items if x]
        if items:
            self.lines.append(path)
            self.lines += items


def export_text(data: dict, *, show_sensitive: bool = False, version: str = "", identity: str | None = None,
                users: list[dict] | None = None, now: datetime | None = None) -> str:
    from app.services import firewall_rules as fr
    from app.services import lan
    data = data or {}
    sec = (lambda v: v) if show_sensitive else (lambda v: None)
    now = now or datetime.now()
    o = _Out()
    ident = identity or (data.get("system") or {}).get("identity") or "outpost-gate-pro"
    o.lines += [f"# {now:%Y-%m-%d %H:%M:%S} by OutpostGate Pro {version}".rstrip(),
                f"# identity: {ident}" + ("" if show_sensitive else " · секреты скрыты (show-sensitive — показать)")]

    o.menu("/system identity", [line("set", ("name", ident))])
    ntp = NtpConfig.model_validate(data.get("ntp") or {})
    if ntp.timezone:
        o.menu("/system clock", [line("set", ("time-zone-name", ntp.timezone))])

    # --- WAN ---------------------------------------------------------------------------------------
    w = WanConfig(**(data.get("wan") or {}))
    o.menu("/wan", [line("set", ("interface", w.interface), ("mode", w.mode), ("address", w.address),
                         ("gateway", w.gateway), ("dns", w.dns), ("vlan-id", w.vlan_id))])
    w2 = Wan2Config(**(data.get("wan2") or {}))
    if w2.enabled or data.get("wan2"):
        o.menu("/ip wan2", [line("set", ("enabled", w2.enabled), ("interface", w2.interface), ("mode", w2.mode),
                                 ("address", w2.address), ("gateway", w2.gateway), ("dns", w2.dns),
                                 ("vlan-id", w2.vlan_id))])
        mw = MultiWanConfig.model_validate(data.get("multiwan") or {})
        o.menu("/ip multiwan", [line("set", ("mode", mw.mode), ("primary", mw.primary), ("weight1", mw.weight1),
                                     ("weight2", mw.weight2), ("check-targets", mw.check_targets),
                                     ("interval", mw.interval), ("fail-after", mw.fail_after),
                                     ("recover-after", mw.recover_after))])

    # --- LAN, DHCP --------------------------------------------------------------------------------
    segs = lan.segments(data)
    o.menu("/lan segment", [line("set" if s.id == "lan1" else "add",
                                 *([] if s.id == "lan1" else [("id", s.id)]),
                                 ("name", s.name), ("address", s.address), ("ports", s.ports or "auto"),
                                 ("vlan-id", s.vlan_id), ("trunk-ports", s.trunk_ports),
                                 ("dns", s.dns_enabled), ("domain", s.domain), ("forward-to", s.forward_to),
                                 ("wan-management", s.wan_management), ("disabled", not s.enabled),
                                 find="id=lan1" if s.id == "lan1" else None) for s in segs])
    o.menu("/ip dhcp-server", [line("set", ("disabled", not s.dhcp_enabled),
                                    ("pool", f"{s.pool_start}-{s.pool_end}" if s.pool_start and s.pool_end else None),
                                    ("lease-time", s.lease_time), find=f"lan={s.id}") for s in segs])
    opts = []
    for s in segs:
        d = s.dhcp_options
        pairs = [("dns-servers", d.dns_servers), ("domain-search", d.domain_search), ("ntp-servers", d.ntp_servers),
                 ("time-offset", d.time_offset), ("mtu", d.mtu), ("wins-servers", d.wins_servers),
                 ("tftp-server", d.tftp_server), ("boot-file", d.boot_file), ("tftp-150", d.tftp_servers_150),
                 ("sip-servers", d.sip_servers), ("provisioning-url", d.provisioning_url),
                 ("static-routes", d.static_routes), ("wpad-url", d.wpad_url), ("vendor-43", d.vendor_43)]
        if any(v not in (None, [], "") for _, v in pairs):
            opts.append(line("set", *pairs, find=f"lan={s.id}"))
        for c in d.custom:
            opts.append(line("add", ("lan", s.id), ("code", c.code), ("type", c.type), ("value", c.value),
                             ("comment", c.comment)))
    o.menu("/ip dhcp-server option", opts)
    leases = []
    for s in segs:
        for x in lan._static_raw(data, s.id):
            leases.append(line("add", ("server", s.name), ("mac-address", x.get("mac")), ("address", x.get("ip")),
                               ("comment", x.get("name"))))
    o.menu("/ip dhcp-server lease", leases)

    # --- DNS --------------------------------------------------------------------------------------
    if data.get("dns") is not None:
        dns = DnsConfig.model_validate(data["dns"])
        o.menu("/ip dns", [line("set", ("servers", dns.forwarders), ("forward-only", dns.forward_only),
                                ("dnssec", dns.dnssec), ("cache-size", f"{dns.cache_mb}M"))])
        o.menu("/ip dns zone", [line("add", ("name", z.name), ("ttl", z.ttl), ("dhcp-names", z.dhcp_names),
                                     ("auto-ptr", z.auto_ptr)) for z in dns.zones])
        recs = []
        for z in dns.zones:
            for r in z.records:
                fqdn = z.name if r.name in ("@", "") else f"{r.name}.{z.name}"
                recs.append(line("add", ("name", fqdn), ("type", r.type), ("value", r.value), ("ttl", r.ttl),
                                 ("priority", r.priority), ("weight", r.weight), ("port", r.port),
                                 ("comment", r.comment)))
        o.menu("/ip dns static", recs)

    # --- адреса и маршруты ------------------------------------------------------------------------
    ip = data.get("ip") or {}
    o.menu("/ip address", [line("add", ("address", e.get("address")), ("interface", e.get("interface")),
                                ("comment", e.get("comment")), ("disabled", True if e.get("disabled") else None))
                           for e in ip.get("addresses") or []])
    o.menu("/ip route", [line("add", ("dst-address", e.get("dst-address")), ("gateway", e.get("gateway")),
                              ("distance", e.get("distance")), ("comment", e.get("comment")),
                              ("disabled", True if e.get("disabled") else None))
                         for e in ip.get("routes") or []])

    # --- фаервол ----------------------------------------------------------------------------------
    fw = data.get("firewall") or {}
    zone = lambda z: None if z == "any" else z.upper()  # noqa: E731
    rules = []
    for d in fw.get("rules") or []:
        r = fr.FirewallRule(**fr._from_yaml(d, fr._RULE_KEYS))
        rules.append(line("add", ("chain", r.chain), ("action", r.action),
                          ("protocol", None if r.protocol == "all" else r.protocol), ("src-address", r.src),
                          ("dst-address", r.dst), ("src-port", r.src_ports), ("dst-port", r.dst_ports),
                          ("in-interface-list", zone(r.in_zone)), ("out-interface-list", zone(r.out_zone)),
                          ("comment", r.description), ("disabled", True if not r.enabled else None)))
    o.menu("/ip firewall filter", rules)
    nat = []
    for d in fw.get("forwards") or []:
        f = fr.PortForward(**fr._from_yaml(d, fr._FWD_KEYS))
        nat.append(line("add", ("chain", "dstnat"), ("action", "dst-nat"), ("protocol", f.protocol),
                        ("dst-port", f.wan_port), ("to-addresses", f.to_ip), ("to-ports", f.to_port),
                        ("src-address", f.src), ("comment", f.description),
                        ("disabled", True if not f.enabled else None)))
    o.menu("/ip firewall nat", nat)

    # --- VPN ----------------------------------------------------------------------------------------
    vpn = data.get("vpn") or {}
    for kind, path in (("wireguard", "/interface wireguard"), ("amneziawg", "/interface amneziawg")):
        if not vpn.get(kind):
            continue
        c = WgConfig.from_yaml(vpn.get(kind))
        o.menu(path, [line("set", ("disabled", not c.enabled), ("private-key", sec(c.private_key)),
                           ("address", c.addresses), ("dns", c.dns), ("mtu", c.mtu), ("mode", c.mode),
                           ("nat", c.nat), ("killswitch", c.killswitch))])
        o.menu(path + " peers", [line("set", ("public-key", c.peer_public_key), ("preshared-key", sec(c.preshared_key)),
                                      ("endpoint", c.endpoint), ("allowed-address", c.allowed_ips),
                                      ("persistent-keepalive", c.keepalive))])
    if vpn.get("l2tp"):
        c = L2tpConfig.from_yaml(vpn.get("l2tp"))
        o.menu("/interface l2tp-client", [line("set", ("disabled", not c.enabled), ("connect-to", c.server),
                                               ("ipsec-secret", sec(c.psk)), ("user", c.username),
                                               ("password", sec(c.password)), ("mode", c.mode),
                                               ("networks", c.networks), ("nat", c.nat), ("killswitch", c.killswitch),
                                               ("mtu", c.mtu))])

    # --- маршрутизация ------------------------------------------------------------------------------
    if data.get("routing"):
        rt = RoutingConfig.model_validate(data["routing"])
        ospf = rt.ospf
        o.menu("/routing ospf instance", [line("set", ("disabled", not ospf.enabled), ("router-id", rt.router_id),
                                               ("redistribute", ospf.redistribute),
                                               ("originate-default", ospf.default_route),
                                               ("passive-default", ospf.passive_default))])
        o.menu("/routing ospf network", [line("add", ("network", n.network), ("area", n.area)) for n in ospf.networks])
        o.menu("/routing ospf interface", [line("add", ("interface", i.name), ("cost", i.cost),
                                                ("network-type", i.network_type), ("passive", i.passive),
                                                ("hello-interval", i.hello), ("dead-interval", i.dead),
                                                ("priority", i.priority), ("authentication-key", sec(i.auth_key)),
                                                ("neighbor", i.neighbor)) for i in ospf.interfaces])
        bgp = rt.bgp
        o.menu("/routing bgp instance", [line("set", ("disabled", not bgp.enabled), ("as", bgp.asn),
                                              ("router-id", rt.router_id), ("redistribute", bgp.redistribute))])
        o.menu("/routing bgp network", [line("add", ("network", n)) for n in bgp.networks])
        peers = []
        for p in bgp.neighbors:
            d = p.model_dump()
            peers.append(line("add", ("remote-address", d.get("address")), ("remote-as", d.get("remote_as")),
                              ("comment", d.get("description")), ("tcp-md5-key", sec(d.get("password"))),
                              ("multihop", d.get("multihop")), ("update-source", d.get("update_source")),
                              ("disabled", True if d.get("enabled") is False else None)))
        o.menu("/routing bgp peer", peers)

    # --- файловый сервер ------------------------------------------------------------------------------
    if data.get("files"):
        fs = FilesConfig.model_validate(data["files"])
        o.menu("/ip smb", [line("set", ("enabled", fs.enabled), ("workgroup", fs.workgroup),
                                ("netbios-name", fs.netbios_name), ("comment", fs.server_string),
                                ("segments", fs.segments or "all"), ("min-protocol", fs.min_protocol),
                                ("netbios", fs.netbios))])
        o.menu("/ip smb groups", [line("add", ("name", g.name), ("comment", g.description)) for g in fs.groups])
        o.menu("/ip smb users", [line("add", ("name", u.name), ("full-name", u.full_name), ("groups", u.groups),
                                      ("disabled", True if not u.enabled else None)) for u in fs.users])
        o.menu("/ip smb shares", [line("add", ("name", s.name), ("volume", s.volume if s.volume != "data" else None),
                                       ("directory", s.folder), ("read-users", s.read_users),
                                       ("write-users", s.write_users), ("guest", s.guest), ("comment", s.comment),
                                       ("recycle", s.recycle), ("browseable", s.browseable), ("macos", s.macos),
                                       ("disabled", True if not s.enabled else None)) for s in fs.shares])

    # --- время, мониторинг, QoS, планировщик ----------------------------------------------------------
    if data.get("ntp"):
        o.menu("/system ntp client", [line("set", ("enabled", ntp.enabled), ("servers", ntp.servers))])
        o.menu("/system ntp server", [line("set", ("enabled", ntp.serve_lan), ("orphan", ntp.orphan))])
    if data.get("monitoring"):
        m = MonitoringConfig.model_validate(data["monitoring"])
        o.menu("/snmp", [line("set", ("enabled", m.snmp.enabled), ("version", m.snmp.version),
                              ("community", sec(m.snmp.community)), ("user", m.snmp.user),
                              ("auth-password", sec(m.snmp.auth_password)), ("priv-password", sec(m.snmp.priv_password)),
                              ("contact", m.snmp.contact), ("location", m.snmp.location), ("allowed", m.snmp.allowed))])
        o.menu("/system monitoring", [line("set", ("ping-targets", m.ping_targets),
                                           ("prometheus", m.prometheus.enabled),
                                           ("prometheus-token", sec(m.prometheus.token)),
                                           ("prometheus-allowed", m.prometheus.allowed),
                                           ("zabbix-agent", m.zabbix.enabled), ("zabbix-server", m.zabbix.server),
                                           ("zabbix-server-active", m.zabbix.server_active),
                                           ("zabbix-hostname", m.zabbix.hostname))])
    if data.get("qos"):
        qc = QosConfig.model_validate(data["qos"])
        o.menu("/queue settings", [line("set", ("enabled", qc.enabled),
                                        ("wan-limit", _limit(qc.wan_up, qc.wan_down) if qc.wan_up or qc.wan_down else None),
                                        ("voice-priority", qc.voice), ("sip-ports", qc.sip_ports),
                                        ("rtp-ports", qc.rtp_ports))])
        names = {s.id: s.name for s in segs}
        o.menu("/queue segment", [line("set", ("max-limit", _limit(x.up, x.down)), find=f"lan={names.get(x.lan, x.lan)}")
                                  for x in qc.segments])
        o.menu("/queue simple", [line("add", ("name", d.name), ("target", d.ip), ("max-limit", _limit(d.up, d.down)),
                                      ("disabled", True if not d.enabled else None)) for d in qc.devices])
    sched = []
    for t in (data.get("scheduler") or {}).get("tasks") or []:
        t = Task.model_validate(t)
        s, a = t.schedule, t.action
        if s.kind == "daily":
            when = [("start-time", s.time), ("interval", "1d")]
        elif s.kind == "weekly":
            when = [("start-time", s.time), ("days", ",".join(["mon", "tue", "wed", "thu", "fri", "sat", "sun"][d] for d in s.days))]
        elif s.kind == "interval":
            when = [("interval", f"{s.every}m")]
        elif s.kind == "once":
            when = [("start-date", s.at.split("T")[0]), ("start-time", s.at.split("T")[1])]
        else:
            when = [("cron", s.cron)]
        act = [("on-event", a.type), ("mac", a.mac), ("lan", a.lan), ("target", a.target), ("device", a.device)]
        if a.type in ("lan_segment", "firewall_rule", "port_forward", "vpn", "qos_device"):
            act.append(("set-enabled", a.enabled))
        if a.type in ("wan_renew", "multiwan_primary"):
            act.append(("wan", a.wan))
        sched.append(line("add", ("name", t.name), *when, *act, ("disabled", True if not t.enabled else None)))
    o.menu("/system scheduler", sched)

    if users:
        o.menu("/user", [line("add", ("name", u["name"]), ("group", u["role"])) for u in users if u["name"] != "admin"])
    return "\n".join(o.lines) + "\n"


def export_current(show_sensitive: bool = False) -> str:
    from app.core import auth
    from app.core.config import settings
    from app.core.store import store
    try:
        users = auth.list_users()
    except Exception:  # noqa: BLE001
        users = None
    return export_text(store.load(), show_sensitive=show_sensitive, version=settings.version, users=users)
