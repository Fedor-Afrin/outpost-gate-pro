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
class RoutingRules:
    ospf_ifaces: list[str]   # где OSPF ищет соседей: пропустить протокол 89
    bgp_peers: list[str]     # соседи BGP: пропустить TCP 179 от них

    def __bool__(self) -> bool:
        return bool(self.ospf_ifaces or self.bgp_peers)


def management_ports() -> list[int]:
    """Веб/API и SSH-доступ к CLI роутера."""
    return sorted({int(os.getenv("API_PORT", "8000")), int(os.getenv("CLI_SSH_PORT", "22"))})


# --- правила пользователя -> nft ------------------------------------------------------
def render_rule(rule: FirewallRule, rid: int, ifaces: dict[str, str | None]) -> str:
    """Одна строка nft; если зона сейчас недоступна (VPN выключен) — закомментированная."""
    parts = []
    for zone, key in ((rule.in_zone, "iifname"), (rule.out_zone, "oifname")):
        if zone != "any":
            iface = ifaces.get(zone)
            if not iface:
                return f"{I}# rule:{rid} пропущено — зона {zone} сейчас не активна\n"
            parts.append(f'{key} "{iface}"')
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


def render_forward(fwd: PortForward, fid: int, wan: str) -> str:
    proto = "{ tcp, udp }" if fwd.protocol == "tcp+udp" else fwd.protocol
    src = f"ip saddr {fwd.src} " if fwd.src else ""
    target = fwd.to_ip + (f":{fwd.to_port}" if fwd.to_port else "")
    return (f'{I}iifname "{wan}" {src}meta l4proto {proto} th dport {fwd.wan_port} '
            f'counter dnat ip to {target} comment "fwd:{fid}"\n')


# --- весь ruleset ---------------------------------------------------------------------
def render_routing(routing: RoutingRules | None, lan: str) -> str:
    """OSPF и BGP: до правил «из туннеля только ответы» и «с WAN всё запрещено»."""
    if not routing:
        return ""
    out = ""
    for iface in routing.ospf_ifaces:
        if iface != lan:   # из LAN и так разрешено всё
            out += f'{I}iifname "{iface}" ip protocol 89 accept   # OSPF\n'
    if routing.bgp_peers:
        peers = ", ".join(routing.bgp_peers)
        out += f'{I}ip saddr {{ {peers} }} tcp dport 179 accept   # BGP от соседей\n'
    return out


def ruleset(wan: str, lan: str, wan_management: bool, vpn: VpnRules | None = None,
            rules: list[tuple[int, FirewallRule]] = (), forwards: list[tuple[int, PortForward]] = (),
            routing: RoutingRules | None = None) -> str:
    ifaces = {"wan": wan, "lan": lan, "vpn": vpn.iface if vpn else None}
    user_in = "".join(render_rule(r, rid, ifaces) for rid, r in rules if r.enabled and r.chain == "input")
    user_fwd = "".join(render_rule(r, rid, ifaces) for rid, r in rules if r.enabled and r.chain == "forward")
    active_fwd = [(fid, f) for fid, f in forwards if f.enabled]
    dnat = "".join(render_forward(f, fid, wan) for fid, f in active_fwd)

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

    forward = ""
    if vpn:
        forward += (f'{I}oifname "{vpn.iface}" tcp flags syn tcp option maxseg size set rt mtu\n'
                    f'{I}iifname "{vpn.iface}" tcp flags syn tcp option maxseg size set rt mtu\n')
    forward += f'{I}ct state established,related accept\n{I}ct state invalid drop\n'
    forward += user_fwd and f"{I}# --- правила пользователя ---\n{user_fwd}{I}# --- системные ---\n"
    if active_fwd:
        forward += f'{I}ct status dnat accept               # проброс портов\n'
    if vpn and vpn.killswitch:
        forward += f'{I}# kill switch: LAN → WAN напрямую запрещено, только через туннель\n'
    else:
        forward += f'{I}iifname "{lan}" oifname "{wan}" accept\n'
    if vpn:
        forward += f'{I}iifname "{lan}" oifname "{vpn.iface}" accept\n'
        if vpn.inbound:
            forward += f'{I}iifname "{vpn.iface}" oifname "{lan}" accept   # центр видит устройства LAN\n'

    post = f'{I}oifname "{wan}" masquerade\n'
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
{user_in_block}{render_routing(routing, lan)}{input_vpn}        iifname != "{wan}" accept            # LAN — без ограничений
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
}}
"""


def system_rules(wan: str | None, wan_management: bool, vpn: VpnRules | None,
                 routing: RoutingRules | None = None) -> dict[str, list[str]]:
    """То же, что делают системные правила, — человеческим языком (для веб-интерфейса)."""
    mgmt = ", ".join(str(p) for p in management_ports())
    inp = ["Ответы на соединения, начатые роутером, — разрешены",
           "Из LAN — разрешено всё"]
    if vpn:
        inp.append(f"Из VPN ({vpn.iface}) — " + ("разрешено всё (site-to-site)" if vpn.inbound
                                                 else "только ответы (режим NAT)"))
    if routing and routing.ospf_ifaces:
        inp.append(f"OSPF на {', '.join(routing.ospf_ifaces)} — разрешён")
    if routing and routing.bgp_peers:
        inp.append(f"BGP от соседей {', '.join(routing.bgp_peers)} (TCP 179) — разрешён")
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


def apply(wan: str, lan: str, wan_management: bool, vpn: VpnRules | None = None,
          rules=(), forwards=(), routing: RoutingRules | None = None) -> None:
    apply_text(ruleset(wan, lan, wan_management, vpn, rules, forwards, routing))
    print(f"[firewall] применён: WAN={wan} LAN={lan} управление с WAN={'да' if wan_management else 'нет'}"
          + (f" VPN={vpn.iface} NAT={'да' if vpn.nat else 'нет'} kill switch={'да' if vpn.killswitch else 'нет'}"
             if vpn else "")
          + f" правил: {len(rules)}, пробросов: {len(forwards)}")


def context(lan_cfg=None):
    """(wan, lan, wan_management, vpn, rules, forwards, routing) или None, если LAN выключен."""
    from app.services import firewall_rules, lan, routing, vpn   # здесь, чтобы не было циклического импорта
    cfg = lan_cfg or lan.get_config()
    wan_if = lan.wan_interface()
    if not (cfg.enabled and wan_if):
        return None
    return (wan_if, lan.BRIDGE, cfg.wan_management, vpn.firewall_rules(),
            firewall_rules.rules(), firewall_rules.forwards(), routing_rules())


def routing_rules() -> RoutingRules | None:
    from app.services import routing
    try:
        r = RoutingRules(routing.ospf_interfaces(), routing.bgp_peers())
    except Exception as e:  # ошибка в настройках маршрутизации не должна ломать фаервол
        print(f"[firewall] WARNING: маршрутизация: {e}")
        return None
    return r or None


def refresh(lan_cfg=None) -> None:
    """Собрать правила из текущего состояния LAN, WAN, VPN и правил пользователя и применить.

    lan_cfg — новые настройки LAN, если они применяются прямо сейчас и ещё не сохранены.
    """
    from app.services import lan
    ctx = context(lan_cfg)
    if not ctx or not lan.load_state().get("address"):
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
