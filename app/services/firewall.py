"""
Фаервол и NAT (nftables).

Свою таблицу `inet outpost_gate_pro` роутер генерирует целиком и применяет
атомарно (`nft -f`): либо применяется вся, либо ничего. Чужие таблицы
(Docker, системные) не трогаются.

Порядок в каждой цепочке:
  1. служебное: ответы (established), мусор (invalid), loopback
  2. ПРАВИЛА ПОЛЬЗОВАТЕЛЯ — сверху вниз, первое совпавшее решает
  3. системные правила: LAN, VPN, IPsec, управление, kill switch
  4. политика по умолчанию (input с WAN и forward — drop)

  input   — с WAN: только ответы, ICMP, DHCP и (по галочке) управление;
            OSPF (протокол 89) на интерфейсах OSPF, BGP (TCP 179) от своих соседей;
            мониторинг (Prometheus, SNMP, Zabbix agent) — от адресов из настроек;
            из VPN: всё (site-to-site) или только ответы (режим NAT)
  forward — LAN → WAN (если нет kill switch), LAN → VPN; WAN → LAN закрыто
  NAT     — masquerade в WAN; в VPN — по настройке туннеля; проброс портов (DNAT)
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass

from app.models.firewall import FirewallRule, PortForward, port_set

TABLE = "outpost_gate_pro"
LEGACY_TABLES = ("outpost_gate_lite",)   # Pro начинался как копия Lite — её таблица удаляется
I = " " * 8


class FirewallError(Exception):
    pass


@dataclass
class VpnRules:
    iface: str            # wg0 / awg0 / l2tp0
    nat: bool             # masquerade LAN за адресом туннеля
    killswitch: bool      # LAN → WAN напрямую запрещено (весь трафик только в туннель)
    inbound: bool         # из туннеля можно заходить в LAN и на роутер (site-to-site)
    ipsec_server: str | None = None   # L2TP/IPsec: впустить с WAN IKE, ESP и L2TP от этого сервера


@dataclass
class GreRules:
    ifaces: list[str]        # gre1 …: доверенная сеть «роутер — роутер» (транзит с LAN в обе стороны)
    remotes: list[str]       # вторые роутеры: впустить от них GRE (протокол 47)

    def __bool__(self) -> bool:
        return bool(self.ifaces)


@dataclass
class RoutingRules:
    ospf_ifaces: list[str]   # где OSPF ищет соседей: пропустить протокол 89
    bgp_peers: list[str]     # соседи BGP: пропустить TCP 179 от них

    def __bool__(self) -> bool:
        return bool(self.ospf_ifaces or self.bgp_peers)


def management_ports() -> list[int]:
    """Веб/API и SSH-доступ к CLI роутера; в режиме host — и SSH самого сервера (HOST_SSH_PORT)."""
    ports = {int(os.getenv("API_PORT", "8000")), int(os.getenv("CLI_SSH_PORT", "22"))}
    host_ssh = os.getenv("HOST_SSH_PORT", "")
    if host_ssh.isdigit():
        ports.add(int(host_ssh))
    return sorted(ports)


# мониторинг: [(протокол, порт, источники, комментарий)] — см. exporters.firewall_rules()
MonitorRules = list


def render_monitor(monitor) -> str:
    out = ""
    for proto, port, sources, comment in monitor or ():
        out += f'{I}ip saddr {{ {", ".join(sources)} }} {proto} dport {port} accept   # {comment}\n'
    return out


# --- правила пользователя -> nft ------------------------------------------------------
def render_rule(rule: FirewallRule, rid: int, ifaces: dict[str, str | None]) -> str:
    """Одна строка nft; если зона сейчас недоступна (VPN выключен) — закомментированная."""
    parts = []
    for zone, key in ((rule.in_zone, "iifname"), (rule.out_zone, "oifname")):
        if zone != "any":
            iface = ifaces.get(zone)
            if not iface:
                return f"{I}# rule:{rid} пропущено — зона {zone} сейчас не активна\n"
            parts.append(f"{key} {ifset(iface)}")
    if rule.src:
        parts.append(f"ip saddr {rule.src}")
    if rule.dst:
        parts.append(f"ip daddr {rule.dst}")
    if rule.protocol == "icmp":
        parts.append("ip protocol icmp")
    elif rule.protocol in ("tcp", "udp"):
        if rule.src_ports:
            parts.append(f"{rule.protocol} sport {port_set(rule.src_ports)}")
        if rule.dst_ports:
            parts.append(f"{rule.protocol} dport {port_set(rule.dst_ports)}")
        if not rule.src_ports and not rule.dst_ports:
            parts.append(f"meta l4proto {rule.protocol}")
    parts += ["counter", rule.action, f'comment "rule:{rid}"']
    return I + " ".join(parts) + "\n"


def ifset(names) -> str:
    """'br-lan' -> "br-lan"; ['br-lan', 'br-lan2'] -> { "br-lan", "br-lan2" }"""
    if isinstance(names, str):
        names = [names]
    names = list(names)
    if len(names) == 1:
        return f'"{names[0]}"'
    return "{ " + ", ".join(f'"{n}"' for n in names) + " }"


def render_forward(fwd: PortForward, fid: int, wan) -> str:
    proto = "{ tcp, udp }" if fwd.protocol == "tcp+udp" else fwd.protocol
    src = f"ip saddr {fwd.src} " if fwd.src else ""
    target = fwd.to_ip + (f":{fwd.to_port}" if fwd.to_port else "")
    return (f'{I}iifname {ifset(wan)} {src}meta l4proto {proto} th dport {fwd.wan_port} '
            f'counter dnat ip to {target} comment "fwd:{fid}"\n')


def render_multiwan(wans: list[str]) -> str:
    """Два провайдера: метка соединения = канал, через который оно вышло или пришло.
    Пакеты из LAN с этой меткой маршрутизируются в «свой» канал (ip rule fwmark, см. multiwan.py)."""
    if len(wans) < 2:
        return ""
    from app.services.multiwan import MARKS
    marks = list(MARKS.values())
    pre = "".join(f'{I}iifname "{w}" ct state new ct mark set {hex(m)}   # пришло через {w}\n'
                  for w, m in zip(wans, marks))
    post = "".join(f'{I}ct mark 0 oifname "{w}" ct mark set {hex(m)}   # ушло через {w}\n'
                   for w, m in zip(wans, marks))
    all_marks = ", ".join(hex(m) for m in marks[:len(wans)])
    return f"""
    chain multiwan_pre {{
        type filter hook prerouting priority mangle; policy accept;
{pre}{I}iifname != {ifset(wans)} ct mark {{ {all_marks} }} meta mark set ct mark
    }}

    chain multiwan_post {{
        type filter hook postrouting priority mangle; policy accept;
{post}    }}
"""


def render_qos(qos: tuple[str, str] | None) -> str:
    """Приоритет голосу: SIP и RTP получают DSCP EF — по нему их узнают очереди QoS (см. qos.py)."""
    if not qos:
        return ""
    ports = f"{{ {qos[0]}, {qos[1]} }}"
    return f"""
    chain qos_mark {{
        type filter hook forward priority mangle; policy accept;
{I}udp dport {ports} ip dscp set ef   # SIP и RTP — голос
{I}udp sport {ports} ip dscp set ef
    }}
"""


# --- весь ruleset ---------------------------------------------------------------------
def render_routing(routing: RoutingRules | None, lan) -> str:
    """OSPF и BGP: до правил «из туннеля только ответы» и «с WAN всё запрещено»."""
    if not routing:
        return ""
    out = ""
    lans = [lan] if isinstance(lan, str) else list(lan)
    for iface in routing.ospf_ifaces:
        if iface not in lans:   # из LAN и так разрешено всё
            out += f'{I}iifname "{iface}" ip protocol 89 accept   # OSPF\n'
    if routing.bgp_peers:
        peers = ", ".join(routing.bgp_peers)
        out += f'{I}ip saddr {{ {peers} }} tcp dport 179 accept   # BGP от соседей\n'
    return out


def ruleset(wan: str, lan, wan_management: bool, vpn: VpnRules | None = None,
            rules: list[tuple[int, FirewallRule]] = (), forwards: list[tuple[int, PortForward]] = (),
            routing: RoutingRules | None = None, links: list[tuple[str, str]] = (),
            monitor: MonitorRules | None = None, qos: tuple[str, str] | None = None,
            gre: GreRules | None = None) -> str:
    """wan — интерфейс WAN или список (два провайдера); lan — мост или список мостов сегментов;
    links — разрешённый транзит между сегментами [(мост-откуда, мост-куда)];
    gre — туннели GRE «роутер — роутер»."""
    lans = [lan] if isinstance(lan, str) else list(lan)
    lan = ifset(lans)
    wans = [wan] if isinstance(wan, str) else list(wan)
    wan = ifset(wans)
    ifaces = {"wan": wans, "lan": lans, "vpn": vpn.iface if vpn else None}
    user_in = "".join(render_rule(r, rid, ifaces) for rid, r in rules if r.enabled and r.chain == "input")
    user_fwd = "".join(render_rule(r, rid, ifaces) for rid, r in rules if r.enabled and r.chain == "forward")
    active_fwd = [(fid, f) for fid, f in forwards if f.enabled]
    dnat = "".join(render_forward(f, fid, wans) for fid, f in active_fwd)

    mgmt = ", ".join(str(p) for p in management_ports())
    mgmt_rule = f'{I}tcp dport {{ {mgmt} }} accept   # управление с WAN (веб, SSH)\n' if wan_management else ""
    input_vpn = f'{I}iifname "{vpn.iface}" drop            # из туннеля — только ответы\n' \
        if vpn and not vpn.inbound else ""
    ipsec_rules = ""
    if vpn and vpn.ipsec_server:
        srv = vpn.ipsec_server
        ipsec_rules = (f'{I}ip saddr {srv} udp dport {{ 500, 4500 }} accept   # IKE от сервера L2TP/IPsec\n'
                       f'{I}ip saddr {srv} ip protocol esp accept\n'
                       f'{I}ip saddr {srv} udp dport 1701 accept           # L2TP (внутри IPsec)\n')

    gre_in = ""
    if gre:
        remotes = ", ".join(gre.remotes)
        gre_in = f'{I}ip protocol 47 ip saddr {{ {remotes} }} accept   # GRE от вторых роутеров\n'
    forward = ""
    if vpn:
        forward += (f'{I}oifname "{vpn.iface}" tcp flags syn tcp option maxseg size set rt mtu\n'
                    f'{I}iifname "{vpn.iface}" tcp flags syn tcp option maxseg size set rt mtu\n')
    if gre:
        g = ifset(gre.ifaces)
        forward += (f'{I}oifname {g} tcp flags syn tcp option maxseg size set rt mtu\n'
                    f'{I}iifname {g} tcp flags syn tcp option maxseg size set rt mtu\n')
    forward += f'{I}ct state established,related accept\n{I}ct state invalid drop\n'
    forward += user_fwd and f"{I}# --- правила пользователя ---\n{user_fwd}{I}# --- системные ---\n"
    if active_fwd:
        forward += f'{I}ct status dnat accept               # проброс портов\n'
    if vpn and vpn.killswitch:
        forward += f'{I}# kill switch: LAN → WAN напрямую запрещено, только через туннель\n'
    else:
        forward += f'{I}iifname {lan} oifname {wan} accept\n'
    if vpn:
        forward += f'{I}iifname {lan} oifname "{vpn.iface}" accept\n'
        if vpn.inbound:
            forward += f'{I}iifname "{vpn.iface}" oifname {lan} accept   # центр видит устройства LAN\n'
    for a, b in links:
        forward += f'{I}iifname "{a}" oifname "{b}" accept   # транзит между сегментами LAN\n'
    if gre:
        g = ifset(gre.ifaces)
        forward += (f'{I}iifname {lan} oifname {g} accept   # LAN → второй роутер (GRE)\n'
                    f'{I}iifname {g} oifname {lan} accept   # второй роутер → LAN (GRE)\n'
                    f'{I}iifname {g} oifname {g} accept     # транзит между туннелями GRE\n')

    post = f'{I}oifname {wan} masquerade\n'
    if vpn and vpn.nat:
        post += f'{I}oifname "{vpn.iface}" masquerade\n'

    user_in_block = user_in and f"{I}# --- правила пользователя ---\n{user_in}{I}# --- системные ---\n"
    legacy = "".join(f"add table inet {t}\ndelete table inet {t}\n" for t in LEGACY_TABLES)
    return f"""# сгенерировано OutpostGate Pro — не редактировать вручную
{legacy}add table inet {TABLE}
delete table inet {TABLE}

table inet {TABLE} {{
    chain input {{
        type filter hook input priority filter; policy accept;
        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept
{user_in_block}{gre_in}{render_routing(routing, lans)}{render_monitor(monitor)}{input_vpn}        iifname != {wan} accept            # LAN — без ограничений
        ip protocol icmp accept
        udp sport 67 udp dport 68 accept     # ответы DHCP-сервера провайдера
{ipsec_rules}{mgmt_rule}        drop                                 # всё остальное с WAN
    }}

    chain forward {{
        type filter hook forward priority filter; policy drop;
{forward}    }}

    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
{dnat}    }}

    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
{post}    }}
{render_multiwan(wans)}{render_qos(qos)}}}
"""


def system_rules(wan: str | None, wan_management: bool, vpn: VpnRules | None,
                 routing: RoutingRules | None = None, links_named: list[tuple[str, str]] = (),
                 monitor: MonitorRules | None = None, gre: GreRules | None = None) -> dict[str, list[str]]:
    """То же, что делают системные правила, — человеческим языком (для веб-интерфейса)."""
    mgmt = ", ".join(str(p) for p in management_ports())
    inp = ["Ответы на соединения, начатые роутером, — разрешены",
           "Из LAN — разрешено всё"]
    if vpn:
        inp.append(f"Из VPN ({vpn.iface}) — " + ("разрешено всё (site-to-site)" if vpn.inbound
                                                 else "только ответы (режим NAT)"))
    if gre:
        inp.append(f"GRE от {', '.join(gre.remotes)} — разрешён; из туннелей {', '.join(gre.ifaces)} — всё")
    if routing and routing.ospf_ifaces:
        inp.append(f"OSPF на {', '.join(routing.ospf_ifaces)} — разрешён")
    if routing and routing.bgp_peers:
        inp.append(f"BGP от соседей {', '.join(routing.bgp_peers)} (TCP 179) — разрешён")
    for proto, port, sources, comment in monitor or ():
        inp.append(f"{comment} ({proto.upper()} {port}) от {', '.join(sources)} — разрешён")
    wan = ", ".join(wan) if isinstance(wan, (list, tuple)) else wan
    inp.append(f"С WAN ({wan}): ping и DHCP" + (f", управление (порты {mgmt})" if wan_management else ""))
    if vpn and vpn.ipsec_server:
        inp.append(f"С WAN от сервера L2TP {vpn.ipsec_server}: IKE, ESP, L2TP")
    inp.append("Всё остальное с WAN — запрещено")

    fwd = ["Ответы на разрешённые соединения — разрешены"]
    fwd.append("LAN → WAN — " + ("запрещено (kill switch)" if vpn and vpn.killswitch else "разрешено"))
    if vpn:
        fwd.append(f"LAN → VPN ({vpn.iface}) — разрешено")
        if vpn.inbound:
            fwd.append(f"VPN → LAN — разрешено (site-to-site)")
    for a, b in links_named:
        fwd.append(f"{a} → {b} — разрешено")
    if gre:
        fwd.append(f"LAN ↔ GRE ({', '.join(gre.ifaces)}) — разрешено в обе стороны")
    fwd.append("WAN → LAN — запрещено (кроме проброса портов)")

    nat = [f"Masquerade в WAN ({wan})"]
    if vpn and vpn.nat:
        nat.append(f"Masquerade в VPN ({vpn.iface})")
    return {"input": inp, "forward": fwd, "nat": nat}


# --- применение -----------------------------------------------------------------------
def _nft(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["nft", *args], input=stdin, capture_output=True, text=True, timeout=10)
    except FileNotFoundError as e:
        raise FirewallError("нет программы nft (пакет nftables)") from e


def apply_text(text: str) -> None:
    r = _nft(["-f", "-"], stdin=text)
    if r.returncode != 0:
        raise FirewallError(f"nft: {r.stderr.strip()}")


def apply(wan: str, lan, wan_management: bool, vpn: VpnRules | None = None,
          rules=(), forwards=(), routing: RoutingRules | None = None, links=(), monitor=None, qos=None,
          gre: GreRules | None = None) -> None:
    apply_text(ruleset(wan, lan, wan_management, vpn, rules, forwards, routing, links, monitor, qos, gre))
    print(f"[firewall] применён: WAN={wan} LAN={lan} управление с WAN={'да' if wan_management else 'нет'}"
          + (f" VPN={vpn.iface} NAT={'да' if vpn.nat else 'нет'} kill switch={'да' if vpn.killswitch else 'нет'}"
             if vpn else "")
          + f" правил: {len(rules)}, пробросов: {len(forwards)}")


def context(lan_cfg=None):
    """(wan, мосты LAN, wan_management, vpn, rules, forwards, routing, links, monitor) или None, если LAN выключен.
    wan — строка (один провайдер) или список (два)."""
    from app.services import firewall_rules, lan, routing, vpn, wan   # здесь, чтобы не было циклического импорта
    segs = lan.segments()
    if lan_cfg is not None:
        segs = [lan_cfg if s.id == lan_cfg.id else s for s in segs]
    active = [s for s in segs if s.enabled]
    wan_if = lan.wan_interface()
    if not (active and wan_if):
        return None
    try:
        wans = wan.active_interfaces()
    except Exception:  # noqa: BLE001
        wans = []
    if len(wans) > 1:
        wan_if = wans
    return (wan_if, [s.bridge for s in active], segs[0].wan_management, vpn.firewall_rules(),
            firewall_rules.rules(), firewall_rules.forwards(), routing_rules(), segment_links(active), monitor_rules(),
            qos_ports(), gre_rules())


def segment_links(active) -> list[tuple[str, str]]:
    by_id = {s.id: s for s in active}
    return [(s.bridge, by_id[t].bridge) for s in active for t in s.forward_to if t in by_id]


def segment_links_named(active) -> list[tuple[str, str]]:
    by_id = {s.id: s for s in active}
    return [(s.name, by_id[t].name) for s in active for t in s.forward_to if t in by_id]


def routing_rules() -> RoutingRules | None:
    from app.services import routing
    try:
        r = RoutingRules(routing.ospf_interfaces(), routing.bgp_peers())
    except Exception as e:  # ошибка в настройках маршрутизации не должна ломать фаервол
        print(f"[firewall] WARNING: маршрутизация: {e}")
        return None
    return r or None


def gre_rules() -> GreRules | None:
    from app.services import gre
    try:
        return gre.firewall_rules()
    except Exception as e:  # noqa: BLE001
        print(f"[firewall] WARNING: GRE: {e}")
        return None


def qos_ports() -> tuple[str, str] | None:
    from app.services import qos
    return qos.firewall_ports()


def monitor_rules() -> MonitorRules:
    from app.services import exporters
    return exporters.firewall_rules()


def refresh(lan_cfg=None) -> None:
    """Собрать правила из текущего состояния LAN, WAN, VPN и правил пользователя и применить.

    lan_cfg — новые настройки LAN, если они применяются прямо сейчас и ещё не сохранены.
    """
    from app.services import lan
    ctx = context(lan_cfg)
    if not ctx or not any(lan.load_state(s.id).get("address") for s in lan.segments() if s.enabled):
        remove()   # фаервол работает вместе с LAN
        return
    apply(*ctx)


def remove() -> None:
    try:
        for t in LEGACY_TABLES:
            _nft(["delete", "table", "inet", t])
        _nft(["delete", "table", "inet", TABLE])
    except FirewallError:
        pass


def is_active() -> bool:
    try:
        return _nft(["list", "table", "inet", TABLE]).returncode == 0
    except FirewallError:
        return False


def counters() -> dict[str, tuple[int, int]]:
    """{'rule:3': (пакеты, байты), 'fwd:1': (...)} из живой таблицы."""
    try:
        r = _nft(["-j", "list", "table", "inet", TABLE])
    except FirewallError:
        return {}
    if r.returncode != 0:
        return {}
    out = {}
    try:
        for item in json.loads(r.stdout).get("nftables", []):
            rule = item.get("rule")
            if not rule or not rule.get("comment"):
                continue
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    c = expr["counter"]
                    out[rule["comment"]] = (c.get("packets", 0), c.get("bytes", 0))
    except (ValueError, AttributeError):
        return {}
    return out
