"""
Команды CLI в стиле MikroTik RouterOS: дерево меню, разбор строки, вывод, автодополнение.

  [admin@office] > /ip address print
  [admin@office] > /ip addr pr detail                 # сокращения, как в RouterOS
  [admin@office] > /ip address
  [admin@office] /ip address> add address=192.168.88.1/24 interface=eth1
  [admin@office] /ip address> set 0 comment="LAN"
  [admin@office] /ip address> ..
  [admin@office] /ip> /ping 8.8.8.8 count=3

Каждая команда — вызов того же REST API, что и у веб-интерфейса (ping, traceroute,
ip-scan запускаются прямо на роутере). Номера строк, как в RouterOS, — из последнего print.
"""
from __future__ import annotations

import asyncio
import getpass
import ipaddress
import os
import shlex
import urllib.parse
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable

from app.cli.api import ApiError


class CliError(Exception):
    pass


class Quit(Exception):
    pass


@dataclass
class Cmd:
    fn: Callable
    help: str
    params: tuple[str, ...] = ()
    values: dict = field(default_factory=dict)     # параметр -> варианты для Tab (список или функция ctx)


@dataclass
class Menu:
    help: str
    children: dict = field(default_factory=dict)


@dataclass
class Ctx:
    api: object
    out: Callable[[str], None] = print
    user: str = "admin"
    role: str = "full"
    confirm: Callable[[str], bool] = lambda q: input(q).strip().lower() in ("y", "yes", "д", "да")
    secret: Callable[[str], str] = getpass.getpass
    shell: Callable[[], None] | None = None
    numbers: dict = field(default_factory=dict)     # меню -> [объект строки 0, строки 1, ...]
    detail: bool = False                            # print detail
    sleep: Callable[[float], None] = time.sleep


# --- вывод -------------------------------------------------------------------------------------------
def fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return str(n)


def fmt_bps(n) -> str:
    n = float(n or 0) * 8
    for unit in ("bps", "kbps", "Mbps", "Gbps"):
        if n < 1000 or unit == "Gbps":
            return f"{n:.0f}{unit}" if unit == "bps" else f"{n:.1f}{unit}"
        n /= 1000
    return str(n)


def fmt_uptime(sec) -> str:
    if sec is None:
        return "-"
    sec = int(sec)
    d, h, m, s = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60, sec % 60
    return (f"{d}d" if d else "") + f"{h}h{m}m{s}s"


def _cell(v) -> str:
    if v is None or v == "":
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return ",".join(map(str, v))
    return str(v)


def table(ctx: Ctx, cols: list[str], rows: list[list], flags: list[str] | None = None,
          legend: str | None = None, numbered: bool = True) -> None:
    """Таблица как в RouterOS; при `print detail` — строки «ключ=значение»."""
    flags = flags or [""] * len(rows)
    cells = [[_cell(c) for c in r] for r in rows]
    if legend:
        ctx.out(f"Flags: {legend}")
    if ctx.detail:
        nw = len(str(max(len(rows) - 1, 0)))
        for i, (flag, r) in enumerate(zip(flags, cells)):
            pairs = " ".join(f'{c}={shlex.quote(v) if " " in v else v}' for c, v in zip(cols, r) if v)
            ctx.out(f"{i:>{nw}} {flag:<2} {pairs}".rstrip())
        return
    fw = max([len(f) for f in flags] + [0])
    widths = [max([len(h)] + [len(r[i]) for r in cells]) for i, h in enumerate(cols)]
    nw = len(str(max(len(rows) - 1, 0))) if numbered else 0

    def line(num, flag, values):
        prefix = (f"{num:>{nw}} " if numbered else "") + (f"{flag:<{fw}} " if fw else "")
        return (prefix + "  ".join(v.ljust(widths[i]) for i, v in enumerate(values))).rstrip()

    ctx.out(line("#" if numbered else "", "", [c.upper() for c in cols]))
    for i, (flag, r) in enumerate(zip(flags, cells)):
        ctx.out(line(i, flag, r))


def kv(ctx: Ctx, pairs: list[tuple[str, object]]) -> None:
    """«ключ: значение» с выравниванием, как /system resource print."""
    pairs = [(k, v) for k, v in pairs if v is not None]
    w = max((len(k) for k, _ in pairs), default=0)
    for k, v in pairs:
        ctx.out(f"{k:>{w}}: {_cell(v)}")


# --- аргументы ----------------------------------------------------------------------------------------
def split_args(tokens: list[str]) -> tuple[list[str], dict[str, str]]:
    pos, named = [], {}
    for t in tokens:
        if "=" in t and not t.startswith("="):
            k, v = t.split("=", 1)
            named[k] = v
        else:
            pos.append(t)
    return pos, named


def expand_params(cmd: Cmd, named: dict) -> dict:
    """Сокращения параметров, как в RouterOS: addr= -> address=, если вариант один."""
    if not cmd.params:
        return named
    out = {}
    for k, v in named.items():
        if k in cmd.params or k == "numbers":
            out[k] = v
            continue
        matches = [p for p in cmd.params if p.startswith(k)]
        if len(matches) == 1:
            out[matches[0]] = v
        elif matches:
            raise CliError(f"ambiguous value of {k}, more than one possible value: {', '.join(matches)}")
        else:
            raise CliError(f"expected end of command (unknown parameter {k})")
    return out


def yes(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.lower() in ("yes", "true", "1", "on", "да")


def pick(ctx: Ctx, menu: str, pos: list[str], named: dict) -> list:
    """'0,2' или numbers=0,2 -> объекты строк из последнего print этого меню."""
    raw = named.get("numbers") or ",".join(p for p in pos if p not in ("detail",))
    if not raw:
        raise CliError("укажите номер(а) строк из print, например: remove 0,2")
    items = ctx.numbers.get(menu)
    if items is None:
        raise CliError(f"сначала выполните print в {menu}")
    out = []
    for part in raw.split(","):
        part = part.strip()
        if "-" in part and part.replace("-", "").isdigit():          # диапазон 0-3
            a, b = (int(x) for x in part.split("-", 1))
            idx = list(range(a, b + 1))
        elif part.isdigit():
            idx = [int(part)]
        else:
            raise CliError(f"no such item ({part})")
        for i in idx:
            if i >= len(items):
                raise CliError(f"no such item ({i})")
            out.append(items[i])
    return out


def require(named: dict, *names: str) -> None:
    missing = [n for n in names if not named.get(n)]
    if missing:
        raise CliError("missing value(s) of argument(s) " + ", ".join(missing))


def _not_dynamic(items: list[dict]) -> None:
    if any(i.get("id") is None for i in items):
        raise CliError("failure: dynamic item can not be changed (он не из конфигурации)")


# --- значения для Tab ----------------------------------------------------------------------------------
def iface_names(ctx: Ctx) -> list[str]:
    try:
        return ctx.api.get("/api/tools/interfaces")["interfaces"]
    except Exception:
        return []


YESNO = ["yes", "no"]
ZONE_LISTS = ["WAN", "LAN", "VPN", "all"]
IFACE = {"interface": iface_names}


# --- /interface ---------------------------------------------------------------------------------------
def interface_print(ctx, pos, named):
    items = ctx.api.get("/api/interfaces")
    lan = _lan_roles(ctx)
    ctx.numbers["/interface"] = items
    table(ctx, ["name", "type", "mac-address", "mtu", "address", "rx", "tx"],
          [[i["name"], lan.get(i["name"], _iface_type(i["name"])), i.get("mac"), i.get("mtu"),
            i.get("addresses", []), fmt_bytes(i.get("rx_bytes")), fmt_bytes(i.get("tx_bytes"))] for i in items],
          flags=["R" if i.get("running") else "X" for i in items], legend="R - running, X - no link")


def _iface_type(name: str) -> str:
    if name == "lo":
        return "loopback"
    if name.startswith("br"):
        return "bridge"
    if name.startswith(("wg", "awg")):
        return "wireguard"
    if name.startswith(("l2tp", "ppp")):
        return "l2tp-out"
    return "ether"


def _lan_roles(ctx) -> dict[str, str]:
    try:
        return {p["name"]: f'ether ({p["role"].upper()})' for p in ctx.api.get("/api/lan")["ports"]
                if p["role"] in ("wan", "lan")}
    except Exception:
        return {}


def monitor_traffic(ctx, pos, named):
    name = named.get("interface") or (pos[0] if pos else None)
    if not name:
        raise CliError("monitor-traffic eth0  (Ctrl-C — стоп)")
    once = yes(named.get("once"))
    prev = None
    try:
        while True:
            cur = next((i for i in ctx.api.get("/api/interfaces") if i["name"] == name), None)
            if not cur:
                raise CliError(f"no such item ({name})")
            now = time.monotonic()
            if prev:
                dt = now - prev[0]
                ctx.out(f"  name: {name}   rx-bits-per-second: {fmt_bps((cur['rx_bytes'] - prev[1]) / dt):>10}"
                        f"   tx-bits-per-second: {fmt_bps((cur['tx_bytes'] - prev[2]) / dt):>10}")
                if once:
                    return
            prev = (now, cur["rx_bytes"], cur["tx_bytes"])
            ctx.sleep(1)
    except KeyboardInterrupt:
        pass


def _segments(ctx) -> list[dict]:
    lan = ctx.api.get("/api/lan")
    return lan.get("segments") or [{"config": {**lan["config"], "id": "lan1", "name": "LAN"}, "bridge": "br-lan",
                                    "active": lan["active"],
                                    "ports": [p["name"] for p in lan["ports"] if p["role"] == "lan"]}]


def bridge_print(ctx, pos, named):
    segs = _segments(ctx)
    table(ctx, ["name", "segment", "address", "ports", "domain"],
          [[s["bridge"], s["config"].get("name"), s["config"]["address"], s.get("ports", []),
            s["config"].get("domain")] for s in segs],
          flags=["R" if s["active"] else "X" for s in segs], legend="R - running, X - disabled")


def vlan_print(ctx, pos, named):
    """/interface vlan print — VLAN сегментов LAN и VLAN провайдера на WAN."""
    rows, flags = [], []
    w = ctx.api.get("/api/wan")
    if w["config"].get("vlan_id"):
        base = w["config"]["interface"]
        rows.append([w.get("interface") or f'{base}.{w["config"]["vlan_id"]}', w["config"]["vlan_id"], base, "WAN"])
        flags.append("R" if w.get("interface") else "")
    for sg in _segments(ctx):
        c = sg["config"]
        for p in c.get("trunk_ports") or []:
            rows.append([f'{p}.{c["vlan_id"]}', c["vlan_id"], p, f'{c.get("name")} ({sg["bridge"]})'])
            flags.append("R" if sg["active"] else "X")
    table(ctx, ["name", "vlan-id", "interface", "segment"], rows, flags=flags, legend="R - running, X - disabled")


def bridge_port_print(ctx, pos, named):
    lan = ctx.api.get("/api/lan")
    bridges = {s["config"].get("id", "lan1"): s["bridge"] for s in _segments(ctx)}
    ports = [p for p in lan["ports"] if p["role"] == "lan"]
    table(ctx, ["interface", "bridge", "mac-address"],
          [[p["name"], bridges.get(p.get("segment") or "lan1", "br-lan"), p.get("mac")] for p in ports],
          flags=["" if p["link_up"] else "I" for p in ports], legend="I - inactive (нет линка)")


def _vpn_status(ctx, kind):
    st = ctx.api.get(f"/api/vpn/{kind}")
    c = st["config"]
    hs = st.get("latest_handshake")
    return st, c, (f"{int(time.time() - hs)}s" if hs else None)


def wireguard_print(ctx, pos, named):
    rows, flags = [], []
    for kind, iface in (("wireguard", "wg0"), ("amneziawg", "awg0")):
        st, c, _ = _vpn_status(ctx, kind)
        rows.append([iface, kind, c["mtu"], c.get("addresses"), st.get("public_key")])
        flags.append(("R" if st.get("active") else "") + ("" if c["enabled"] else "X"))
    table(ctx, ["name", "type", "mtu", "address", "public-key"], rows, flags=flags, legend="X - disabled, R - running")


def wireguard_peers_print(ctx, pos, named):
    rows = []
    for kind, iface in (("wireguard", "wg0"), ("amneziawg", "awg0")):
        st, c, hs = _vpn_status(ctx, kind)
        if c.get("peer_public_key"):
            rows.append([iface, c.get("endpoint"), c.get("allowed_ips"), hs, fmt_bytes(st.get("rx_bytes")),
                         fmt_bytes(st.get("tx_bytes"))])
    table(ctx, ["interface", "endpoint", "allowed-address", "last-handshake", "rx", "tx"], rows)


def l2tp_client_print(ctx, pos, named):
    st = ctx.api.get("/api/vpn/l2tp")
    c = st["config"]
    table(ctx, ["name", "connect-to", "user", "use-ipsec", "local-address", "remote-address"],
          [["l2tp0", c.get("server"), c.get("username"), "yes", st.get("local_ip"), st.get("remote_ip")]],
          flags=[("R" if st.get("connected") else "") + ("" if c["enabled"] else "X")],
          legend="X - disabled, R - running")


# --- /ip address, /ip route: общие print / set / enable / disable / remove / comment ---------------------------
def _crud(base: str, menu: str, fields: dict[str, str]):
    """Команды set/enable/disable/remove/comment для меню с id. fields: параметр CLI -> поле API."""
    def set_(ctx, pos, named):
        items = pick(ctx, menu, pos, named)
        _not_dynamic(items)
        body = {api: named[cli] for cli, api in fields.items() if cli in named}
        if "distance" in body:
            body["distance"] = int(body["distance"])
        if "disabled" in named:
            body["disabled"] = yes(named["disabled"])
        if not body:
            raise CliError("нечего менять: укажите параметры, например set 0 comment=...")
        for i in items:
            ctx.api.patch(f"{base}/{i['id']}", body)

    def toggle(disabled):
        def fn(ctx, pos, named):
            items = pick(ctx, menu, pos, named)
            _not_dynamic(items)
            for i in items:
                ctx.api.patch(f"{base}/{i['id']}", {"disabled": disabled})
        return fn

    def remove(ctx, pos, named):
        items = pick(ctx, menu, pos, named)
        _not_dynamic(items)
        for i in items:
            ctx.api.delete(f"{base}/{i['id']}")

    def comment(ctx, pos, named):
        items = pick(ctx, menu, pos, named)
        _not_dynamic(items)
        for i in items:
            ctx.api.patch(f"{base}/{i['id']}", {"comment": named.get("comment", "")})

    n = ("numbers",)
    return {
        "set": Cmd(set_, "изменить: set 0 параметр=значение", n + tuple(fields) + ("disabled",),
                   {"disabled": YESNO, **{k: v for k, v in IFACE.items() if k in fields}}),
        "enable": Cmd(toggle(False), "включить: enable 0", n),
        "disable": Cmd(toggle(True), "выключить: disable 0", n),
        "remove": Cmd(remove, "удалить: remove 0,2", n),
        "comment": Cmd(comment, 'комментарий: comment 0 comment="текст"', n + ("comment",)),
    }


def address_print(ctx, pos, named):
    items = ctx.api.get("/api/ip/addresses")
    ctx.numbers["/ip address"] = items
    table(ctx, ["address", "network", "interface", "comment"],
          [[i["address"], i["network"], i["interface"], i.get("comment")] for i in items],
          flags=[("X" if i["disabled"] else "") + ("I" if i["invalid"] else "") + ("D" if i["dynamic"] else "")
                 for i in items], legend="X - disabled, I - invalid, D - dynamic")


def address_add(ctx, pos, named):
    require(named, "address", "interface")
    ctx.api.post("/api/ip/addresses", {"address": named["address"], "interface": named["interface"],
                                       "comment": named.get("comment"), "disabled": yes(named.get("disabled"))})


def route_print(ctx, pos, named):
    items = ctx.api.get("/api/ip/routes")
    ctx.numbers["/ip route"] = items
    table(ctx, ["dst-address", "gateway", "distance", "interface", "comment"],
          [[i["dst_address"], i["gateway"], i["distance"], i.get("interface"), i.get("comment")] for i in items],
          flags=[("X" if i["disabled"] else "") + ("D" if i["dynamic"] else "") + ("A" if i["active"] else "")
                 + ("C" if i["connected"] else "") + ("S" if i["static"] else "")
                 + ("o" if i.get("ospf") else "") + ("b" if i.get("bgp") else "") for i in items],
          legend="X - disabled, D - dynamic, A - active, C - connected, S - static, o - ospf, b - bgp")


def route_add(ctx, pos, named):
    require(named, "gateway")
    body = {"dst_address": named.get("dst-address", "0.0.0.0/0"), "gateway": named["gateway"],
            "comment": named.get("comment"), "disabled": yes(named.get("disabled"))}
    if named.get("distance"):
        body["distance"] = int(named["distance"])
    ctx.api.post("/api/ip/routes", body)


# --- /interface gre ----------------------------------------------------------------------------------------
GRE_FIELDS = {"name": "name", "remote-address": "remote", "local-address": "local", "underlay": "underlay",
              "address": "address", "routes": "routes", "mtu": "mtu", "ttl": "ttl", "ospf": "ospf",
              "ospf-area": "ospf_area", "ospf-cost": "ospf_cost", "comment": "comment", "disabled": "enabled"}


def _gre_body(named: dict, base: dict | None = None) -> dict:
    t = dict(base or {})
    for cli, api in GRE_FIELDS.items():
        if cli not in named:
            continue
        v = named[cli]
        if api == "enabled":
            t["enabled"] = not yes(v)
        elif api == "ospf":
            t["ospf"] = yes(v)
        elif api in ("mtu", "ttl", "ospf_cost"):
            t[api] = int(v) if v not in ("", None) else None
        elif api == "routes":
            t["routes"] = [x for x in v.replace(" ", ",").split(",") if x]
        else:
            t[api] = v or None
    return {k: v for k, v in t.items() if v is not None}


def gre_print(ctx, pos, named):
    d = ctx.api.get("/api/gre")
    items = d["config"]["tunnels"]
    st = {s["name"]: s for s in d["tunnels"]}
    ctx.numbers["/interface gre"] = items
    table(ctx, ["name", "local-address", "remote-address", "underlay", "address", "routes", "ospf", "mtu"],
          [[t["name"], t.get("local") or "auto", t["remote"], t.get("underlay"), t["address"], t.get("routes") or None,
            t.get("ospf_area") if t.get("ospf") else None, t.get("mtu")] for t in items],
          flags=[("X" if not t["enabled"] else "R" if st.get(t["name"], {}).get("up") else "")
                 for t in items], legend="X - disabled, R - running")
    for w in d.get("warnings") or []:
        ctx.out(f"# {w}")


def _gre_put(ctx, tunnels: list[dict]) -> None:
    ctx.api.put("/api/gre", {"tunnels": tunnels})


def gre_add(ctx, pos, named):
    require(named, "remote-address", "address")
    tunnels = ctx.api.get("/api/gre")["config"]["tunnels"]
    if "name" not in named:
        used = {t["name"] for t in tunnels}
        named = {**named, "name": next(f"gre{i}" for i in range(1, 100) if f"gre{i}" not in used)}
    _gre_put(ctx, tunnels + [_gre_body(named, {"enabled": True})])


def _gre_change(fn):
    def run(ctx, pos, named):
        picked = {t["name"] for t in pick(ctx, "/interface gre", pos, named)}
        tunnels = ctx.api.get("/api/gre")["config"]["tunnels"]
        _gre_put(ctx, [x for t in tunnels for x in ([fn(t, named)] if t["name"] in picked else [t]) if x])
    return run


gre_set = _gre_change(lambda t, named: _gre_body({k: v for k, v in named.items() if k != "name"}, t))
gre_enable = _gre_change(lambda t, named: {**t, "enabled": True})
gre_disable = _gre_change(lambda t, named: {**t, "enabled": False})
gre_remove = _gre_change(lambda t, named: None)


# --- /ip arp, /ip neighbor -------------------------------------------------------------------------------
def arp_print(ctx, pos, named):
    items = ctx.api.get("/api/tools/neighbors")
    table(ctx, ["address", "mac-address", "interface", "host-name", "vendor", "status"],
          [[n["ip"], n.get("mac"), n.get("interface"), n.get("name"), n.get("vendor"), (n.get("state") or "").lower()]
           for n in items],
          flags=["D" if n.get("mac") else "I" for n in items], legend="D - dynamic, I - incomplete")


# --- /ip dhcp-server, pool, dhcp-client ----------------------------------------------------------------------
def _dhcp(ctx) -> dict:
    return ctx.api.get("/api/dhcp")


def dhcp_print(ctx, pos, named):
    segs = _dhcp(ctx)["segments"]
    table(ctx, ["name", "interface", "address-pool", "lease-time"],
          [[f'dhcp-{s["id"]}', s["bridge"], f'pool-{s["id"]}', s["settings"]["lease_time"]] for s in segs],
          flags=["" if s["enabled"] and s["settings"]["dhcp_enabled"] else "X" for s in segs], legend="X - disabled")


def dhcp_network_print(ctx, pos, named):
    segs = _dhcp(ctx)["segments"]
    rows = []
    for s in segs:
        o = s["settings"]["dhcp_options"]
        ip = s["address"].split("/")[0]
        dns = o.get("dns_servers") or ([ip] if s["dns_enabled"] else ["(провайдер)"])
        rows.append([s["network"], ip, dns, s.get("domain"), o.get("ntp_servers") or None])
    table(ctx, ["address", "gateway", "dns-server", "domain", "ntp-server"], rows)


def pool_print(ctx, pos, named):
    segs = _dhcp(ctx)["segments"]
    table(ctx, ["name", "ranges"],
          [[f'pool-{s["id"]}', f'{s["settings"]["pool_start"]}-{s["settings"]["pool_end"]}'] for s in segs])


def lease_print(ctx, pos, named):
    d = _dhcp(ctx)
    leases = {l["mac"]: l for l in d["leases"]}
    rows, flags, items = [], [], []
    static = [x for seg in d["segments"] for x in seg["static_leases"]]
    for s in static:                                                  # закреплённые — первыми
        l = leases.pop(s["mac"], {})
        rows.append([s["ip"], s["mac"], s.get("name") or l.get("hostname"), l.get("vendor"),
                     "bound" if l else "waiting"])
        flags.append("S")
        items.append({"kind": "static", "mac": s["mac"], "ip": s["ip"], "name": s.get("name")})
    for l in leases.values():
        rows.append([l["ip"], l["mac"], l.get("hostname"), l.get("vendor"), "bound"])
        flags.append("D")
        items.append({"kind": "dynamic", "mac": l["mac"], "ip": l["ip"], "name": l.get("hostname")})
    ctx.numbers["/ip dhcp-server lease"] = items
    table(ctx, ["address", "mac-address", "host-name", "vendor", "status"], rows, flags=flags,
          legend="S - static (закреплён), D - dynamic")


def lease_make_static(ctx, pos, named):
    for i in pick(ctx, "/ip dhcp-server lease", pos, named):
        if i["kind"] == "dynamic":
            ctx.api.post("/api/lan/static-leases", {"mac": i["mac"], "ip": i["ip"], "name": i["name"]})


def lease_add(ctx, pos, named):
    require(named, "mac-address", "address")
    ctx.api.post("/api/lan/static-leases", {"mac": named["mac-address"], "ip": named["address"],
                                            "name": named.get("comment") or named.get("host-name")})


def lease_set(ctx, pos, named):
    for i in pick(ctx, "/ip dhcp-server lease", pos, named):
        if i["kind"] != "static":
            raise CliError(f"{i['ip']}: сначала make-static")
        ctx.api.put(f"/api/lan/static-leases/{i['mac']}", {
            "mac": i["mac"], "ip": named.get("address", i["ip"]),
            "name": named.get("comment", named.get("host-name", i["name"]))})


def lease_remove(ctx, pos, named):
    for i in pick(ctx, "/ip dhcp-server lease", pos, named):
        if i["kind"] != "static":
            raise CliError(f"{i['ip']}: динамическая аренда — удалить можно только закреплённую")
        ctx.api.delete(f"/api/lan/static-leases/{i['mac']}")


def dhcp_client_print(ctx, pos, named):
    w = ctx.api.get("/api/wan")
    mode = w["config"]["mode"]
    table(ctx, ["interface", "use-peer-dns", "add-default-route", "status", "address", "gateway"],
          [[w["interface"], "yes", "yes", w["dhcp_state"] if mode == "dhcp" else "-", w["addresses"], w["gateway"]]],
          flags=["" if mode == "dhcp" else "X"], legend="X - disabled (WAN не в режиме DHCP)")


def dhcp_client_renew(ctx, pos, named):
    ctx.api.post("/api/wan/renew")


# --- /ip firewall ----------------------------------------------------------------------------------------------
ZONE_OUT = {"any": "", "wan": "WAN", "lan": "LAN", "vpn": "VPN"}
ZONE_IN = {"wan": "wan", "lan": "lan", "vpn": "vpn", "all": "any", "any": "any", "": "any"}
RULE_FIELDS = ("chain", "action", "protocol", "src-address", "dst-address", "src-port", "dst-port",
               "in-interface-list", "out-interface-list", "comment", "disabled")
RULE_VALUES = {"chain": ["input", "forward"], "action": ["accept", "drop", "reject"],
               "protocol": ["tcp", "udp", "icmp"], "in-interface-list": ZONE_LISTS,
               "out-interface-list": ZONE_LISTS, "disabled": YESNO}


def _rule_body(r: dict) -> dict:
    return {k: r.get(k) for k in ("chain", "enabled", "action", "in_zone", "out_zone", "src", "dst", "protocol",
                                  "src_ports", "dst_ports", "description")}


def _rule_from_args(named: dict, base: dict | None = None) -> dict:
    body = dict(base or {"chain": "input", "enabled": True, "action": "accept", "in_zone": "any",
                         "out_zone": "any", "protocol": "all"})
    m = {"chain": "chain", "action": "action", "protocol": "protocol", "src-address": "src", "dst-address": "dst",
         "src-port": "src_ports", "dst-port": "dst_ports", "comment": "description"}
    for cli, api in m.items():
        if cli in named:
            body[api] = named[cli] or None
    for cli, api in (("in-interface-list", "in_zone"), ("out-interface-list", "out_zone")):
        if cli in named:
            zone = ZONE_IN.get(named[cli].lower())
            if not zone:
                raise CliError(f"{cli}: WAN, LAN, VPN или all")
            body[api] = zone
    if "disabled" in named:
        body["enabled"] = not yes(named["disabled"])
    if body.get("protocol") in (None, "", "all") and (body.get("src_ports") or body.get("dst_ports")):
        raise CliError("порты задаются вместе с protocol=tcp или protocol=udp")
    if not body.get("protocol"):
        body["protocol"] = "all"
    return body


def filter_print(ctx, pos, named):
    fw = ctx.api.get("/api/firewall")
    rules = fw["rules"]
    ctx.numbers["/ip firewall filter"] = rules
    table(ctx, ["chain", "action", "in-list", "out-list", "src-address", "dst-address", "protocol", "dst-port",
                "packets", "comment"],
          [[r["chain"], r["action"], ZONE_OUT[r["in_zone"]], ZONE_OUT[r["out_zone"]], r.get("src"), r.get("dst"),
            "" if r["protocol"] == "all" else r["protocol"], r.get("dst_ports"), r["packets"], r.get("description")]
           for r in rules],
          flags=["X" if not r["enabled"] else "" for r in rules], legend="X - disabled")
    ctx.out(";;; системные правила (после ваших):")
    for chain in ("input", "forward"):
        for line in fw["system"][chain]:
            ctx.out(f"    {chain}: {line}")


def filter_add(ctx, pos, named):
    ctx.api.post("/api/firewall/rules", _rule_from_args(named))


def filter_set(ctx, pos, named):
    for r in pick(ctx, "/ip firewall filter", pos, named):
        ctx.api.put(f"/api/firewall/rules/{r['id']}", _rule_from_args(named, _rule_body(r)))


def _filter_toggle(enabled: bool):
    def fn(ctx, pos, named):
        for r in pick(ctx, "/ip firewall filter", pos, named):
            ctx.api.put(f"/api/firewall/rules/{r['id']}", {**_rule_body(r), "enabled": enabled})
    return fn


def filter_remove(ctx, pos, named):
    for r in pick(ctx, "/ip firewall filter", pos, named):
        ctx.api.delete(f"/api/firewall/rules/{r['id']}")


def filter_move(ctx, pos, named):
    """move 3 1 — поставить правило 3 на место правила 1 (внутри своей цепочки)."""
    if len(pos) < 2 and "destination" not in named:
        raise CliError("move <номер> <куда>, например: move 3 0")
    rule = pick(ctx, "/ip firewall filter", pos[:1], {})[0]
    dest = pick(ctx, "/ip firewall filter", [named.get("destination", pos[-1])], {})[0]
    if rule["chain"] != dest["chain"]:
        raise CliError("двигать можно только внутри своей цепочки (input или forward)")
    same = [r["id"] for r in ctx.numbers["/ip firewall filter"] if r["chain"] == rule["chain"]]
    steps = same.index(dest["id"]) - same.index(rule["id"])
    for _ in range(abs(steps)):
        ctx.api.post(f"/api/firewall/rules/{rule['id']}/move", {"direction": "down" if steps > 0 else "up"})


NAT_FIELDS = ("chain", "action", "protocol", "dst-port", "to-addresses", "to-ports", "src-address",
              "in-interface-list", "comment", "disabled")


def _nat_from_args(named: dict, base: dict | None = None) -> dict:
    body = dict(base or {"enabled": True, "protocol": "tcp"})
    if named.get("chain", "dstnat") != "dstnat" or named.get("action", "dst-nat") != "dst-nat":
        raise CliError("поддерживается проброс портов: chain=dstnat action=dst-nat (srcnat делается автоматически)")
    for cli, api in (("protocol", "protocol"), ("dst-port", "wan_port"), ("to-addresses", "to_ip"),
                     ("src-address", "src"), ("comment", "description")):
        if cli in named:
            body[api] = named[cli] or None
    if "to-ports" in named:
        body["to_port"] = int(named["to-ports"]) if named["to-ports"] else None
    if "in-interface-list" in named:
        v = (named["in-interface-list"] or "wan").lower().replace(" ", "")
        zones = {"wan": "wan", "vpn": "vpn", "wan,vpn": "any", "vpn,wan": "any", "all": "any", "any": "any"}
        if v not in zones:
            raise CliError("in-interface-list: WAN, VPN или WAN,VPN")
        body["from_zone"] = zones[v]
    if "disabled" in named:
        body["enabled"] = not yes(named["disabled"])
    if body.get("protocol") in ("tcp,udp", "udp,tcp"):
        body["protocol"] = "tcp+udp"
    return body


def _nat_body(f: dict) -> dict:
    return {k: f.get(k) for k in ("enabled", "protocol", "wan_port", "to_ip", "to_port", "src", "description",
                                  "from_zone") if k in f}


def nat_print(ctx, pos, named):
    fw = ctx.api.get("/api/firewall")
    fwd = fw["forwards"]
    ctx.numbers["/ip firewall nat"] = fwd
    table(ctx, ["chain", "action", "protocol", "in-interface-list", "dst-port", "to-addresses", "to-ports",
                "src-address", "packets", "comment"],
          [["dstnat", "dst-nat", f["protocol"], {"wan": "WAN", "vpn": "VPN", "any": "WAN,VPN"}[f.get("from_zone", "wan")],
            f["wan_port"], f["to_ip"], f.get("to_port"), f.get("src"), f["packets"], f.get("description")] for f in fwd],
          flags=["X" if not f["enabled"] else "" for f in fwd], legend="X - disabled")
    for line in fw["system"]["nat"]:
        ctx.out(f";;; srcnat: {line}")


def nat_add(ctx, pos, named):
    require(named, "dst-port", "to-addresses")
    ctx.api.post("/api/firewall/forwards", _nat_from_args(named))


def nat_set(ctx, pos, named):
    for f in pick(ctx, "/ip firewall nat", pos, named):
        ctx.api.put(f"/api/firewall/forwards/{f['id']}", _nat_from_args(named, _nat_body(f)))


def _nat_toggle(enabled: bool):
    def fn(ctx, pos, named):
        for f in pick(ctx, "/ip firewall nat", pos, named):
            ctx.api.put(f"/api/firewall/forwards/{f['id']}", {**_nat_body(f), "enabled": enabled})
    return fn


def nat_remove(ctx, pos, named):
    for f in pick(ctx, "/ip firewall nat", pos, named):
        ctx.api.delete(f"/api/firewall/forwards/{f['id']}")


# --- /ip dns, /ip service ---------------------------------------------------------------------------------------
def dns_print(ctx, pos, named):
    d = ctx.api.get("/api/dns")
    c = d["config"]
    kv(ctx, [("servers", c["forwarders"] or "auto"), ("dynamic-servers", d["forwarders"]),
             ("allow-remote-requests", d["running"]), ("listen", d["listen"] or "-"),
             ("forward-only", c["forward_only"]), ("dnssec", c["dnssec"]),
             ("cache-size", f'{c["cache_mb"]}MiB'), ("zones", [z["name"] for z in d["zones"]])])


def dns_set(ctx, pos, named):
    d = ctx.api.get("/api/dns")
    c = d["config"]
    if "servers" in named:
        c["forwarders"] = [x for x in named["servers"].split(",") if x.strip()]
    if "forward-only" in named:
        c["forward_only"] = yes(named["forward-only"])
    if "dnssec" in named:
        c["dnssec"] = yes(named["dnssec"])
    if "cache-size" in named:
        c["cache_mb"] = int(named["cache-size"].lower().rstrip("mib").rstrip("m") or 64)
    ctx.api.put("/api/dns", c)


DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "NS", "CAA"]


def _zone_of(zones: list[dict], fqdn: str) -> tuple[dict, str]:
    """pbx.office.lan -> (зона office.lan, имя pbx); самая длинная подходящая зона."""
    fqdn = fqdn.rstrip(".").lower()
    best = None
    for z in zones:
        if fqdn == z["name"] or fqdn.endswith("." + z["name"]):
            if best is None or len(z["name"]) > len(best["name"]):
                best = z
    if not best:
        raise CliError(f"нет зоны для {fqdn}: создайте её во вкладке DNS")
    rel = "@" if fqdn == best["name"] else fqdn[: -len(best["name"]) - 1]
    return best, rel


def dns_static_print(ctx, pos, named):
    d = ctx.api.get("/api/dns")
    items, rows, flags = [], [], []
    for z in d["config"]["zones"]:
        for r in z["records"]:
            items.append((z["name"], r))
            fq = z["name"] if r["name"] == "@" else f'{r["name"]}.{z["name"]}'
            val = r["value"] if r["type"] not in ("MX", "SRV") else \
                f'{r.get("priority")} ' + (f'{r.get("weight")} {r.get("port")} ' if r["type"] == "SRV" else "") + r["value"]
            rows.append([fq, r["type"], val, r.get("ttl") or z["ttl"], r.get("comment")])
            flags.append("")
    for a in d["auto_names"]:
        fq = f'{a["name"]}.{a["zone"]}'
        rows.append([fq, a["type"], a["value"], "", a["source"]])
        flags.append("D")
    ctx.numbers["/ip dns static"] = items + [None] * (len(rows) - len(items))
    table(ctx, ["name", "type", "address", "ttl", "comment"], rows, flags=flags,
          legend="D - dynamic (из DHCP, router, PTR)")


def dns_static_add(ctx, pos, named):
    require(named, "name")
    d = ctx.api.get("/api/dns")
    c = d["config"]
    zone, rel = _zone_of(c["zones"], named["name"])
    rtype = named.get("type", "A").upper()
    value = named.get("address") or named.get("cname") or named.get("text") or named.get("value") \
        or named.get("mx-exchange") or named.get("srv-target") or named.get("ns")
    if not value:
        raise CliError("укажите значение: address=, cname=, text=, mx-exchange=, srv-target= или value=")
    rec = {"name": rel, "type": rtype, "value": value}
    for k, f in (("ttl", "ttl"), ("mx-preference", "priority"), ("srv-priority", "priority"),
                 ("srv-weight", "weight"), ("srv-port", "port")):
        if k in named:
            rec[f] = int(named[k])
    if named.get("comment"):
        rec["comment"] = named["comment"]
    zone["records"].append(rec)
    ctx.api.put("/api/dns", c)


def dns_static_remove(ctx, pos, named):
    picked = pick(ctx, "/ip dns static", pos, named)
    if any(p is None for p in picked):
        raise CliError("failure: dynamic item can not be changed (имя добавлено из DHCP)")
    c = ctx.api.get("/api/dns")["config"]
    for zname, rec in picked:
        z = next(x for x in c["zones"] if x["name"] == zname)
        z["records"] = [r for r in z["records"] if r != rec]
    ctx.api.put("/api/dns", c)


def service_print(ctx, pos, named):
    wan_open = ctx.api.get("/api/lan")["config"]["wan_management"]
    api_port, ssh_port = os.getenv("API_PORT", "8000"), os.getenv("CLI_SSH_PORT", "22")
    table(ctx, ["name", "port", "available-from"],
          [["www", api_port, "LAN, VPN" + (", WAN" if wan_open else "")],
           ["ssh", ssh_port, "LAN, VPN" + (", WAN" if wan_open else "")]],
          legend=None)
    ctx.out(";;; доступ с WAN включается в веб-интерфейсе: LAN -> «Разрешить управление со стороны WAN»")


# --- /wan, /lan, /vpn ----------------------------------------------------------------------------------------------
def wan_print(ctx, pos, named):
    w = ctx.api.get("/api/wan")
    kv(ctx, [("interface", w["interface"]), ("mode", w["config"]["mode"]), ("link", w["link_up"]),
             ("address", w["addresses"]), ("gateway", w["gateway"]), ("dns", w["dns"]),
             ("dhcp-status", w["dhcp_state"]), ("mac-address", w.get("mac"))])


def wan_set(ctx, pos, named):
    cfg = ctx.api.get("/api/wan")["config"]
    if "dns" in named:
        cfg["dns"] = [d for d in named.pop("dns").split(",") if d]
    for key in ("interface", "mode", "address", "gateway"):
        if key in named:
            cfg[key] = named[key] or None
    ctx.api.put("/api/wan", cfg)


def lan_print(ctx, pos, named):
    l = ctx.api.get("/api/lan")
    c = l["config"]
    kv(ctx, [("enabled", c["enabled"]), ("running", l["active"]), ("address", c["address"]),
             ("ports", [f'{p["name"]}{"" if p["link_up"] else "(no-link)"}' for p in l["ports"] if p["role"] == "lan"]),
             ("dhcp-server", c["dhcp_enabled"]), ("pool", f'{c["pool_start"]}-{c["pool_end"]}'),
             ("lease-time", c["lease_time"]), ("wan-management", c["wan_management"]),
             ("clients", len(l["leases"]))])


VPN_NAMES = {"wireguard": "WireGuard", "amneziawg": "AmneziaWG", "l2tp": "L2TP/IPsec"}


def vpn_print(ctx, pos, named):
    kind = ctx.api.get("/api/vpn")["enabled"]
    if not kind:
        ctx.out("туннель выключен (включается в веб-интерфейсе: VPN)")
        return
    st = ctx.api.get(f"/api/vpn/{kind}")
    c = st["config"]
    hs = st.get("latest_handshake")
    kv(ctx, [("type", VPN_NAMES[kind]), ("connected", st.get("connected")),
             ("server", c.get("endpoint") or c.get("server")), ("server-ip", st.get("endpoint_ip")),
             ("mode", "full (весь трафик)" if c["mode"] == "full" else "split (сети компании)"),
             ("kill-switch", c["killswitch"] and c["mode"] == "full"), ("nat", c["nat"]),
             ("last-handshake", f"{int(time.time() - hs)}s ago" if hs else None),
             ("ipsec", st.get("ipsec_up") if kind == "l2tp" else None),
             ("rx", fmt_bytes(st.get("rx_bytes"))), ("tx", fmt_bytes(st.get("tx_bytes"))),
             ("public-key", st.get("public_key"))])


# --- /system, /user, /password, /log ---------------------------------------------------------------------------------
def resource_print(ctx, pos, named):
    r = ctx.api.get("/api/system/resource")
    kv(ctx, [("uptime", fmt_uptime(r["uptime"])), ("version", r["version"]), ("mode", r["mode"]),
             ("board-name", r.get("model")), ("architecture-name", r["arch"]), ("cpu-count", r["cpu_count"]),
             ("cpu-load", f'{r["cpu_percent"]}%' if r["cpu_percent"] is not None else None),
             ("free-memory", fmt_bytes(r["memory"]["total"] - r["memory"]["used"])),
             ("total-memory", fmt_bytes(r["memory"]["total"])),
             ("free-hdd-space", fmt_bytes(r["disk"]["total"] - r["disk"]["used"])),
             ("total-hdd-space", fmt_bytes(r["disk"]["total"])),
             ("temperature", f'{r["temperature"]}C' if r.get("temperature") is not None else None),
             ("kernel", r["kernel"])])


def identity_print(ctx, pos, named):
    kv(ctx, [("name", ctx.api.get("/api/system/resource")["identity"])])


def identity_set(ctx, pos, named):
    require(named, "name")
    ctx.api.put("/api/system/identity", {"identity": named["name"]})


def clock_print(ctx, pos, named):
    t = ctx.api.get("/api/system/resource")["time"]          # 2026-11-10T20:46:00+02:00
    kv(ctx, [("time", t[11:19]), ("date", t[:10]), ("gmt-offset", t[19:] or "+00:00")])


def routerboard_print(ctx, pos, named):
    r = ctx.api.get("/api/system/resource")
    kv(ctx, [("routerboard", "no"), ("model", r.get("model")), ("architecture", r["arch"]),
             ("firmware", f'OutpostGate Pro {r["version"]}'), ("kernel", r["kernel"])])


def package_print(ctx, pos, named):
    r = ctx.api.get("/api/system/resource")
    table(ctx, ["name", "version"], [["outpost-gate-pro", r["version"]]])


def system_reboot(ctx, pos, named):
    if ctx.confirm("Reboot, yes? [y/N]: "):
        ctx.out(ctx.api.post("/api/system/restart").get("message", "перезапуск"))
        raise Quit()


def system_shell(ctx, pos, named):
    if ctx.role != "full":
        raise CliError("not enough permissions (нужна роль full)")
    if not ctx.shell:
        raise CliError("shell недоступен в этом режиме")
    ctx.shell()


def user_print(ctx, pos, named):
    users = ctx.api.get("/api/system/users")
    ctx.numbers["/user"] = users
    table(ctx, ["name", "group", "password"],
          [[u["name"], u["role"], "не задан" if not u.get("has_password", True)
            else "сменит при входе" if u.get("must_change") else "задан"] for u in users])


def user_add(ctx, pos, named):
    require(named, "name")
    password = named.get("password") or ctx.secret("password: ")
    ctx.api.post("/api/system/users", {"name": named["name"], "password": password,
                                       "role": named.get("group", "full")})


def user_set(ctx, pos, named):
    for u in pick(ctx, "/user", pos, named):
        body = {}
        if "group" in named:
            body["role"] = named["group"]
        if "password" in named:
            body["password"] = named["password"]
        ctx.api.put(f"/api/system/users/{u['name']}", body)


def user_remove(ctx, pos, named):
    for u in pick(ctx, "/user", pos, named):
        ctx.api.delete(f"/api/system/users/{u['name']}")


def password(ctx, pos, named):
    old = named.get("old-password")
    if old is None:
        old = ctx.secret("old-password: ")
    new = named.get("new-password") or ctx.secret("new-password: ")
    confirm = named.get("confirm-new-password") or ctx.secret("confirm-new-password: ")
    if new != confirm:
        raise CliError("failure: new passwords do not match (пароли не совпадают)")
    ctx.api.post("/api/auth/password", {"old": old, "new": new})
    ctx.out("пароль изменён — остальные сессии завершены")


def log_print(ctx, pos, named):
    items = list(reversed(ctx.api.get("/api/system/audit?limit=" + str(int(named.get("count", 50))))))
    for e in items:
        t = e["time"].replace("T", " ")[:19]
        ctx.out(f"{t} {e['user']:<10} {e['method']:<8} {e['path']} {'' if e['status'] < 400 else '[' + str(e['status']) + ']'}")


def export(ctx, pos, named):
    """Как в RouterOS: команды; show-sensitive — с ключами и паролями; format=yaml — router.yaml целиком."""
    if (named.get("format") or "").lower() == "yaml":
        ctx.out(ctx.api.call("GET", "/api/system/backup", raw=True).rstrip())
        return
    show = "show-sensitive" in pos or yes(named.get("show-sensitive"))
    ctx.out(ctx.api.call("GET", f"/api/system/export?show_sensitive={'true' if show else 'false'}", raw=True).rstrip())


# --- диагностика (на самом роутере) ----------------------------------------------------------------------------------
def _run_live(ctx, cmd: list[str]) -> None:
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        raise CliError(f"нет программы {cmd[0]}")
    try:
        for line in proc.stdout:
            ctx.out(line.rstrip())
    except KeyboardInterrupt:          # Ctrl-C — прервать, как в RouterOS
        proc.terminate()
    finally:
        proc.wait()


def _host(pos, named) -> str:
    host = named.get("address") or (pos[0] if pos else "")
    if not host or host.startswith("-") or not all(c.isalnum() or c in ".-:" for c in host):
        raise CliError("укажите адрес: ping 8.8.8.8")
    return host


def _iface(named) -> str | None:
    iface = named.get("interface")
    if iface and (iface.startswith("-") or not all(c.isalnum() or c in "._-@" for c in iface)):
        raise CliError("неверный интерфейс")
    return iface


def _resolved(ctx, host: str, family: int | None = None) -> str:
    """Имя -> адрес через DNS роутера (видны локальные имена: samba, samba.office.lan)."""
    from app.services import tools
    try:
        ip, via = tools.resolve_sync(host, family)
    except tools.ToolError as e:
        raise CliError(f"failure: {e}") from e
    if ip != host:
        ctx.out(f"{host} -> {ip} ({via})")
    return ip


def ping(ctx, pos, named):
    host = _host(pos, named)
    count = int(named.get("count", 4))
    family = 6 if ":" in host else 4
    ip = _resolved(ctx, host, family)
    cmd = ["ping", f"-{family}", "-n", "-c", str(max(1, min(count, 1000)))]
    if iface := _iface(named):
        cmd += ["-I", iface]
    _run_live(ctx, cmd + [ip])


def traceroute(ctx, pos, named):
    host = _host(pos, named)
    ip = _resolved(ctx, host)
    cmd = ["traceroute", "-I", "-n", "-q", "1", "-w", "2", "-m", str(int(named.get("max-hops", 30)))]
    if iface := _iface(named):
        cmd += ["-i", iface]
    _run_live(ctx, cmd + [ip])


def dns_lookup(ctx, pos, named):
    name = named.get("name") or (pos[0] if pos else "")
    if not name:
        raise CliError("dns-lookup name=example.com")
    r = ctx.api.get(f"/api/tools/dns?host={urllib.parse.quote(name)}")
    if r.get("error"):
        raise CliError(f"failure: {r['host']}: {r['error']}" + (f" [{r['server']}]" if r.get("server") else ""))
    table(ctx, ["name", "address", "server", "time"],
          [[r["host"], a, r.get("server"), f"{r['time_ms']}ms" if r.get("time_ms") is not None else None]
           for a in r["addresses"]], numbered=False)


def resolve_cmd(ctx, pos, named):
    """:resolve samba — как в RouterOS: адрес имени через DNS роутера."""
    name = named.get("domain-name") or (pos[0] if pos else "")
    if not name:
        raise CliError(":resolve domain-name=samba.office.lan")
    from app.services import tools
    try:
        ip, _ = tools.resolve_sync(tools.check_host(name))
    except tools.ToolError as e:
        raise CliError(f"failure: {e}") from e
    ctx.out(ip)


def ip_scan(ctx, pos, named):
    """/tool ip-scan address-range=192.168.88.0/24 interface=br-lan — как в RouterOS (ping + ARP)."""
    from app.services import tools
    params = {"network": named.get("address-range") or (pos[0] if pos else None), "interface": named.get("interface")}

    async def run():
        rows = []
        async for ev in tools.scan(params):
            if ev["type"] == "info":
                ctx.out(ev["text"])
            elif ev["type"] == "row":
                rows.append(ev["row"])
        return rows

    try:
        rows = asyncio.run(run())
    except tools.ToolError as e:
        raise CliError(str(e)) from e
    except KeyboardInterrupt:
        return
    table(ctx, ["address", "mac-address", "host-name", "vendor", "time"],
          [[r["ip"], r.get("mac"), r.get("name"), r.get("vendor"), f'{r["ping_ms"]}ms' if r.get("ping_ms") else "arp"]
           for r in rows], numbered=False)


def quit_cmd(ctx, pos, named):
    raise Quit()


# --- /routing: OSPF и BGP (FRRouting) ---------------------------------------------------------------------------
ORIGINATE = {"never": "none", "if-installed": "if-installed", "always": "always"}
ORIGINATE_BACK = {v: k for k, v in ORIGINATE.items()}


def _rt(ctx) -> dict:
    import copy
    return copy.deepcopy(ctx.api.get("/api/routing"))   # правим копию, отправляем целиком


def _rt_put(ctx, cfg: dict) -> dict:
    return ctx.api.put("/api/routing", cfg)


def _csv(v: str | None) -> list[str]:
    return [x.strip() for x in (v or "").split(",") if x.strip()]


def _int(v, name: str):
    if v is None or v == "":
        return None
    try:
        return int(v)
    except ValueError:
        raise CliError(f"value of {name} must be number") from None


def _opt(v):
    return None if v in (None, "", "none") else v


def ospf_instance_print(ctx, pos, named):
    d = _rt(ctx)
    c, o = d["config"], d["config"]["ospf"]
    table(ctx, ["name", "router-id", "redistribute", "originate-default", "networks", "neighbors"],
          [["default", d.get("router_id") or c.get("router_id") or "auto", o["redistribute"],
            ORIGINATE_BACK[o["default_route"]], len(o["networks"]),
            sum(n["state"].startswith("Full") for n in d["ospf_neighbors"])]],
          flags=["X" if not o["enabled"] else ""], legend="X - disabled")


def ospf_instance_set(ctx, pos, named):
    cfg = _rt(ctx)["config"]
    o = cfg["ospf"]
    if "disabled" in named:
        o["enabled"] = not yes(named["disabled"])
    if "router-id" in named:
        cfg["router_id"] = _opt(named["router-id"])
    if "redistribute" in named:
        o["redistribute"] = _csv(named["redistribute"])
    if "originate-default" in named:
        if named["originate-default"] not in ORIGINATE:
            raise CliError("originate-default: never, if-installed или always")
        o["default_route"] = ORIGINATE[named["originate-default"]]
    if "passive-default" in named:
        o["passive_default"] = yes(named["passive-default"])
    _rt_put(ctx, cfg)


def _ospf_toggle(on: bool):
    def fn(ctx, pos, named):
        cfg = _rt(ctx)["config"]
        cfg["ospf"]["enabled"] = on
        _rt_put(ctx, cfg)
    return fn


def ospf_network_print(ctx, pos, named):
    nets = _rt(ctx)["config"]["ospf"]["networks"]
    ctx.numbers["/routing ospf network"] = nets
    table(ctx, ["network", "area"], [[n["network"], "backbone" if n["area"] == "0.0.0.0" else n["area"]] for n in nets])


def ospf_network_add(ctx, pos, named):
    require(named, "network")
    cfg = _rt(ctx)["config"]
    area = named.get("area", "0.0.0.0")
    cfg["ospf"]["networks"].append({"network": named["network"], "area": "0.0.0.0" if area == "backbone" else area})
    _rt_put(ctx, cfg)


def ospf_network_remove(ctx, pos, named):
    items = pick(ctx, "/routing ospf network", pos, named)
    cfg = _rt(ctx)["config"]
    drop = {i["network"] for i in items}
    cfg["ospf"]["networks"] = [n for n in cfg["ospf"]["networks"] if n["network"] not in drop]
    _rt_put(ctx, cfg)


OSPF_IF_FIELDS = ("interface", "cost", "network-type", "passive", "hello-interval", "dead-interval",
                  "priority", "authentication-key", "neighbor")
OSPF_IF_VALUES = {**IFACE, "network-type": ["auto", "point-to-point", "broadcast", "non-broadcast"],
                  "passive": YESNO}


def _ospf_if_apply(item: dict, named: dict) -> dict:
    m = {"interface": "name", "network-type": "network_type", "authentication-key": "auth_key", "neighbor": "neighbor"}
    for k, f in m.items():
        if k in named:
            item[f] = _opt(named[k])
    for k, f in (("cost", "cost"), ("hello-interval", "hello"), ("dead-interval", "dead"), ("priority", "priority")):
        if k in named:
            item[f] = _int(named[k], k)
    if "passive" in named:
        item["passive"] = yes(named["passive"])
    item.setdefault("network_type", "auto")
    item["hello"] = item.get("hello") or 10
    item["dead"] = item.get("dead") or 40
    return item


def ospf_interface_print(ctx, pos, named):
    items = _rt(ctx)["config"]["ospf"]["interfaces"]
    ctx.numbers["/routing ospf interface"] = items
    table(ctx, ["interface", "cost", "network-type", "hello", "dead", "auth", "neighbor"],
          [[i["name"], i.get("cost") or "auto", i["network_type"], i["hello"], i["dead"],
            "md5" if i.get("auth_key") else "", i.get("neighbor")] for i in items],
          flags=["P" if i.get("passive") else "" for i in items], legend="P - passive")


def ospf_interface_add(ctx, pos, named):
    require(named, "interface")
    cfg = _rt(ctx)["config"]
    cfg["ospf"]["interfaces"].append(_ospf_if_apply({}, named))
    _rt_put(ctx, cfg)


def ospf_interface_set(ctx, pos, named):
    items = pick(ctx, "/routing ospf interface", pos, named)
    cfg = _rt(ctx)["config"]
    names = {i["name"] for i in items}
    cfg["ospf"]["interfaces"] = [_ospf_if_apply(i, named) if i["name"] in names else i
                                 for i in cfg["ospf"]["interfaces"]]
    _rt_put(ctx, cfg)


def ospf_interface_remove(ctx, pos, named):
    items = pick(ctx, "/routing ospf interface", pos, named)
    cfg = _rt(ctx)["config"]
    names = {i["name"] for i in items}
    cfg["ospf"]["interfaces"] = [i for i in cfg["ospf"]["interfaces"] if i["name"] not in names]
    _rt_put(ctx, cfg)


def ospf_neighbor_print(ctx, pos, named):
    nb = _rt(ctx)["ospf_neighbors"]
    table(ctx, ["router-id", "address", "interface", "state", "priority", "uptime"],
          [[n["router_id"], n.get("address"), n.get("interface"), n["state"], n.get("priority"), n.get("uptime")]
           for n in nb], numbered=True)


def bgp_instance_print(ctx, pos, named):
    d = _rt(ctx)
    c, b = d["config"], d["config"]["bgp"]
    table(ctx, ["name", "as", "router-id", "redistribute", "networks", "peers", "established"],
          [["default", b["asn"], d.get("router_id") or c.get("router_id") or "auto", b["redistribute"],
            b["networks"], len(b["neighbors"]), sum(p["state"] == "Established" for p in d["bgp_peers"])]],
          flags=["X" if not b["enabled"] else ""], legend="X - disabled")


def bgp_instance_set(ctx, pos, named):
    cfg = _rt(ctx)["config"]
    b = cfg["bgp"]
    if "disabled" in named:
        b["enabled"] = not yes(named["disabled"])
    if "as" in named:
        b["asn"] = _int(named["as"], "as")
    if "router-id" in named:
        cfg["router_id"] = _opt(named["router-id"])
    if "redistribute" in named:
        b["redistribute"] = _csv(named["redistribute"])
    _rt_put(ctx, cfg)


def _bgp_toggle(on: bool):
    def fn(ctx, pos, named):
        cfg = _rt(ctx)["config"]
        cfg["bgp"]["enabled"] = on
        _rt_put(ctx, cfg)
    return fn


def bgp_network_print(ctx, pos, named):
    nets = _rt(ctx)["config"]["bgp"]["networks"]
    ctx.numbers["/routing bgp network"] = nets
    table(ctx, ["network"], [[n] for n in nets])


def bgp_network_add(ctx, pos, named):
    require(named, "network")
    cfg = _rt(ctx)["config"]
    cfg["bgp"]["networks"].append(named["network"])
    _rt_put(ctx, cfg)


def bgp_network_remove(ctx, pos, named):
    drop = set(pick(ctx, "/routing bgp network", pos, named))
    cfg = _rt(ctx)["config"]
    cfg["bgp"]["networks"] = [n for n in cfg["bgp"]["networks"] if n not in drop]
    _rt_put(ctx, cfg)


PEER_FIELDS = ("remote-address", "remote-as", "comment", "tcp-md5-key", "multihop", "update-source",
               "keepalive-time", "hold-time", "in-prefixes", "out-prefixes", "disabled")


def _peer_apply(p: dict, named: dict) -> dict:
    for k, f in (("remote-address", "address"), ("comment", "description"), ("tcp-md5-key", "password"),
                 ("update-source", "update_source")):
        if k in named:
            p[f] = _opt(named[k])
    for k, f in (("remote-as", "remote_as"), ("multihop", "multihop"), ("keepalive-time", "keepalive"),
                 ("hold-time", "hold")):
        if k in named:
            p[f] = _int(named[k], k)
    for k, f in (("in-prefixes", "prefix_in"), ("out-prefixes", "prefix_out")):
        if k in named:
            p[f] = _csv(named[k])
    if "disabled" in named:
        p["enabled"] = not yes(named["disabled"])
    p.setdefault("keepalive", 60)
    p.setdefault("hold", 180)
    return p


def bgp_peer_print(ctx, pos, named):
    d = _rt(ctx)
    peers = d["config"]["bgp"]["neighbors"]
    state = {p["address"]: p for p in d["bgp_peers"]}
    ctx.numbers["/routing bgp peer"] = peers
    table(ctx, ["remote-address", "remote-as", "comment", "state", "uptime", "prefixes"],
          [[p["address"], p["remote_as"], p.get("description"), state.get(p["address"], {}).get("state"),
            state.get(p["address"], {}).get("uptime"), state.get(p["address"], {}).get("prefixes_received")]
           for p in peers],
          flags=[("X" if not p.get("enabled", True) else "")
                 + ("E" if state.get(p["address"], {}).get("state") == "Established" else "") for p in peers],
          legend="X - disabled, E - established")


def bgp_peer_add(ctx, pos, named):
    require(named, "remote-address", "remote-as")
    cfg = _rt(ctx)["config"]
    cfg["bgp"]["neighbors"].append(_peer_apply({"enabled": True}, named))
    _rt_put(ctx, cfg)


def _peer_change(fn):
    def run(ctx, pos, named):
        items = pick(ctx, "/routing bgp peer", pos, named)
        cfg = _rt(ctx)["config"]
        addrs = {i["address"] for i in items}
        cfg["bgp"]["neighbors"] = [x for n in cfg["bgp"]["neighbors"]
                                   for x in ([fn(n, named)] if n["address"] in addrs else [n]) if x is not None]
        _rt_put(ctx, cfg)
    return run


bgp_peer_set = _peer_change(lambda p, named: _peer_apply(p, named))
bgp_peer_remove = _peer_change(lambda p, named: None)
bgp_peer_enable = _peer_change(lambda p, named: {**p, "enabled": True})
bgp_peer_disable = _peer_change(lambda p, named: {**p, "enabled": False})


def routing_route_print(ctx, pos, named):
    routes = _rt(ctx)["routes"]
    table(ctx, ["dst-address", "gateway", "interface", "distance", "metric"],
          [[r["prefix"], r.get("nexthop"), r.get("interface"), r.get("distance"), r.get("metric")] for r in routes],
          flags=[("A" if r["selected"] else "") + ("o" if r["protocol"] == "ospf" else "b") for r in routes],
          legend="A - active, o - ospf, b - bgp")


# --- /ip smb: файловый сервер Samba -----------------------------------------------------------
def _smb(ctx) -> dict:
    import copy
    return copy.deepcopy(ctx.api.get("/api/files"))


def _smb_put(ctx, cfg: dict) -> None:
    ctx.api.put("/api/files", cfg)


def smb_print(ctx, pos, named):
    d = _smb(ctx)
    c = d["config"]
    kv(ctx, [("enabled", c["enabled"]), ("running", d["running"]), ("workgroup", c["workgroup"]),
             ("netbios-name", d["netbios_name"]), ("interfaces", d["listen"] or "-"),
             ("segments", c["segments"] or "all"), ("min-protocol", c["min_protocol"]), ("netbios", c["netbios"]),
             ("shares", len(c["shares"])), ("users", len(c["users"])), ("sessions", len(d["sessions"]))])


def smb_set(ctx, pos, named):
    c = _smb(ctx)["config"]
    if "enabled" in named:
        c["enabled"] = yes(named["enabled"])
    for k, f in (("workgroup", "workgroup"), ("netbios-name", "netbios_name"), ("comment", "server_string"),
                 ("min-protocol", "min_protocol")):
        if k in named:
            c[f] = named[k] or None
    if "segments" in named:
        c["segments"] = [x for x in named["segments"].split(",") if x and x != "all"]
    if "netbios" in named:
        c["netbios"] = yes(named["netbios"])
    _smb_put(ctx, c)


def _who(value: str | None) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def smb_shares_print(ctx, pos, named):
    shares = _smb(ctx)["config"]["shares"]
    ctx.numbers["/ip smb shares"] = shares
    table(ctx, ["name", "directory", "read-users", "write-users", "guest", "recycle"],
          [[s["name"], f'{s["volume"]}:/{s["folder"]}', s["read_users"] or None, s["write_users"] or None,
            s["guest"], s["recycle"]] for s in shares],
          flags=["" if s["enabled"] else "X" for s in shares], legend="X - disabled")


def _share_apply(s: dict, named: dict) -> dict:
    if "name" in named:
        s["name"] = named["name"]
    if "directory" in named:
        vol, _, folder = named["directory"].partition(":")
        s["volume"], s["folder"] = (vol, folder.lstrip("/")) if folder else ("data", vol.lstrip("/"))
    for k, f in (("read-users", "read_users"), ("write-users", "write_users")):
        if k in named:
            s[f] = _who(named[k])
    if "guest" in named:
        s["guest"] = named["guest"]
    if "comment" in named:
        s["comment"] = named["comment"] or None
    for k, f in (("recycle", "recycle"), ("browseable", "browseable"), ("macos", "macos")):
        if k in named:
            s[f] = yes(named[k])
    if "disabled" in named:
        s["enabled"] = not yes(named["disabled"])
    return s


def smb_shares_add(ctx, pos, named):
    require(named, "name")
    c = _smb(ctx)["config"]
    s = _share_apply({"volume": "data", "folder": named["name"].lower(), "enabled": True, "browseable": True,
                      "guest": "none", "read_users": [], "write_users": [], "recycle": True, "macos": False,
                      "hide_dot_files": True}, named)
    c["shares"].append(s)
    _smb_put(ctx, c)


def _share_change(fn):
    def run(ctx, pos, named):
        items = pick(ctx, "/ip smb shares", pos, named)
        c = _smb(ctx)["config"]
        names = {i["name"] for i in items}
        c["shares"] = [x for s in c["shares"] for x in ([fn(s, named)] if s["name"] in names else [s]) if x]
        _smb_put(ctx, c)
    return run


smb_shares_set = _share_change(lambda s, n: _share_apply(s, n))
smb_shares_remove = _share_change(lambda s, n: None)
smb_shares_enable = _share_change(lambda s, n: {**s, "enabled": True})
smb_shares_disable = _share_change(lambda s, n: {**s, "enabled": False})


def smb_users_print(ctx, pos, named):
    d = _smb(ctx)
    users = d["config"]["users"]
    nopw = set(d["users_without_password"])
    ctx.numbers["/ip smb users"] = users
    table(ctx, ["name", "full-name", "groups", "password"],
          [[u["name"], u.get("full_name"), u["groups"] or None, "not set" if u["name"] in nopw else "set"] for u in users],
          flags=["" if u["enabled"] else "X" for u in users], legend="X - disabled")


def smb_users_add(ctx, pos, named):
    require(named, "name")
    password = named.get("password") or ctx.secret("password: ")
    ctx.api.post("/api/files/users", {"name": named["name"], "password": password,
                                      "full_name": named.get("full-name") or None, "groups": _who(named.get("groups"))})


def smb_users_set(ctx, pos, named):
    items = pick(ctx, "/ip smb users", pos, named)
    if "password" in named:
        for u in items:
            ctx.api.put(f'/api/files/users/{u["name"]}/password', {"password": named["password"]})
    rest = {k: v for k, v in named.items() if k not in ("password", "numbers")}
    if not rest:
        return
    c = _smb(ctx)["config"]
    names = {i["name"] for i in items}
    for u in c["users"]:
        if u["name"] in names:
            if "full-name" in rest:
                u["full_name"] = rest["full-name"] or None
            if "groups" in rest:
                u["groups"] = _who(rest["groups"])
            if "disabled" in rest:
                u["enabled"] = not yes(rest["disabled"])
    _smb_put(ctx, c)


def _user_change(fn, remove: bool = False):
    def run(ctx, pos, named):
        items = pick(ctx, "/ip smb users", pos, named)
        c = _smb(ctx)["config"]
        names = {i["name"] for i in items}
        if remove:
            c["users"] = [u for u in c["users"] if u["name"] not in names]
            for s in c["shares"]:           # и права на папки
                s["read_users"] = [w for w in s["read_users"] if w not in names]
                s["write_users"] = [w for w in s["write_users"] if w not in names]
        else:
            c["users"] = [fn(u) if u["name"] in names else u for u in c["users"]]
        _smb_put(ctx, c)
    return run


smb_users_remove = _user_change(None, remove=True)
smb_users_enable = _user_change(lambda u: {**u, "enabled": True})
smb_users_disable = _user_change(lambda u: {**u, "enabled": False})


def smb_groups_print(ctx, pos, named):
    c = _smb(ctx)["config"]
    ctx.numbers["/ip smb groups"] = c["groups"]
    table(ctx, ["name", "comment", "members"],
          [[g["name"], g.get("description"), [u["name"] for u in c["users"] if g["name"] in u["groups"]] or None]
           for g in c["groups"]])


def smb_groups_add(ctx, pos, named):
    require(named, "name")
    c = _smb(ctx)["config"]
    c["groups"].append({"name": named["name"], "description": named.get("comment") or None})
    _smb_put(ctx, c)


def smb_groups_remove(ctx, pos, named):
    items = pick(ctx, "/ip smb groups", pos, named)
    c = _smb(ctx)["config"]
    names = {i["name"] for i in items}
    c["groups"] = [g for g in c["groups"] if g["name"] not in names]
    for u in c["users"]:
        u["groups"] = [g for g in u["groups"] if g not in names]
    for s in c["shares"]:
        s["read_users"] = [w for w in s["read_users"] if not (w.startswith("@") and w[1:] in names)]
        s["write_users"] = [w for w in s["write_users"] if not (w.startswith("@") and w[1:] in names)]
    _smb_put(ctx, c)


def smb_sessions_print(ctx, pos, named):
    ss = _smb(ctx)["sessions"]
    table(ctx, ["user", "machine", "protocol", "shares", "open-files"],
          [[s["user"], s["machine"], s.get("protocol"), s.get("share"), s["open_files"]] for s in ss], numbered=True)


def smb_disks_print(ctx, pos, named):
    d = _smb(ctx)
    if not d["disks_allowed"]:
        ctx.out("диски доступны только в режиме host")
        return
    devs = d["devices"]
    table(ctx, ["device", "size", "fs", "label", "uuid", "volume"],
          [[x["path"], x["size"], x.get("fstype"), x.get("label"), x.get("uuid"), x.get("mounted_as")] for x in devs],
          flags=[("S" if x["system"] else "") + ("M" if x.get("mounted_as") else "") for x in devs],
          legend="S - system (сервер), M - mounted")


# --- мониторинг (/tool torch, /snmp, /system monitoring) ---------------------------------------------------------
def _bps(v) -> str:
    if v is None:
        return "-"
    bits = float(v) * 8
    for unit in ("bps", "kbps", "Mbps", "Gbps"):
        if bits < 1000 or unit == "Gbps":
            return f"{bits:.0f}{unit}" if unit == "bps" else f"{bits:.1f}{unit}"
        bits /= 1000
    return str(bits)


def torch(ctx, pos, named):
    """Кто сейчас качает: клиенты LAN по скорости (учёт в nftables)."""
    d = ctx.api.get("/api/monitor")
    if not d.get("accounting"):
        ctx.out("учёт трафика клиентов недоступен" + (f": {d['accounting_error']}" if d.get("accounting_error") else ""))
        return
    rows = sorted(d.get("clients") or [], key=lambda c: -((c["rx_rate"] or 0) + (c["tx_rate"] or 0)))
    seg = named.get("segment")
    if seg:
        rows = [c for c in rows if c["segment"].lower() == seg.lower()]
    table(ctx, ["address", "name", "segment", "rx-rate", "tx-rate", "rx-total", "tx-total"],
          [[c["ip"], c["name"] or "", c["segment"], _bps(c["rx_rate"]), _bps(c["tx_rate"]),
            fmt_bytes(c["rx_bytes"]), fmt_bytes(c["tx_bytes"])] for c in rows[:int(named.get("count") or 20)]])


def _mon(ctx) -> dict:
    import copy
    return copy.deepcopy(ctx.api.get("/api/monitor/settings"))


def snmp_print(ctx, pos, named):
    d = _mon(ctx)
    s, st = d["config"]["snmp"], d["snmp"]
    kv(ctx, [("enabled", s["enabled"]), ("running", st["running"]), ("version", s["version"]),
             ("community", s["community"] if s["version"] == "v2c" else None),
             ("user", s.get("user") if s["version"] == "v3" else None),
             ("contact", s.get("contact") or ""), ("location", s.get("location") or ""),
             ("allowed", ",".join(s["allowed"]) or "LAN"), ("error", st.get("error"))])


def snmp_set(ctx, pos, named):
    cfg = _mon(ctx)["config"]
    s = cfg["snmp"]
    if "enabled" in named:
        s["enabled"] = yes(named["enabled"])
    for k, f in (("version", "version"), ("community", "community"), ("user", "user"), ("contact", "contact"),
                 ("location", "location"), ("auth-password", "auth_password"), ("priv-password", "priv_password")):
        if k in named:
            s[f] = named[k]
    if "allowed" in named:
        s["allowed"] = [x for x in named["allowed"].split(",") if x]
    ctx.api.put("/api/monitor/settings", cfg)


def monitoring_print(ctx, pos, named):
    d = _mon(ctx)
    c = d["config"]
    snap = ctx.api.get("/api/monitor")
    kv(ctx, [("collector", "running" if snap.get("time") else "starting"),
             ("client-accounting", bool(snap.get("accounting"))),
             ("ping-targets", ",".join(c["ping_targets"]) or "-"),
             ("prometheus", c["prometheus"]["enabled"]),
             ("prometheus-url", "http://<router>:8000/metrics" if c["prometheus"]["enabled"] else None),
             ("prometheus-token", "yes" if c["prometheus"].get("token") else "no"),
             ("snmp", c["snmp"]["enabled"]), ("snmp-running", d["snmp"]["running"]),
             ("zabbix-agent", c["zabbix"]["enabled"]), ("zabbix-running", d["zabbix"]["running"]),
             ("zabbix-flavor", d["zabbix"].get("flavor")),
             ("zabbix-server", ",".join(c["zabbix"]["server"]) or None),
             ("lan-networks", ",".join(d["lan_networks"]) or "-")])


# --- два WAN, NTP, Wake-on-LAN ------------------------------------------------------------------------------------
def multiwan_print(ctx, pos, named):
    d = ctx.api.get("/api/wan/multiwan")
    c = d["config"]
    kv(ctx, [("wan2", "enabled" if d["enabled"] else "disabled"), ("mode", c["mode"]),
             ("primary", c["primary"] if c["mode"] == "failover" else None),
             ("weights", f'{c["weight1"]}:{c["weight2"]}' if c["mode"] == "balance" else None),
             ("check-targets", ",".join(c["check_targets"])), ("interval", f'{c["interval"]}s'),
             ("fail-after", c["fail_after"]), ("recover-after", c["recover_after"])])
    ctx.out("")
    rows = [w for w in d["wans"] if w["enabled"]]
    table(ctx, ["name", "interface", "address", "gateway", "check", "rtt"],
          [[w["name"], w["interface"] or "", w["address"] or "", w["gateway"] or "",
            {True: "up", False: "down", None: "-"}[w["healthy"]], f'{w["rtt"]}ms' if w["rtt"] is not None else ""]
           for w in rows], flags=["A" if w["active"] else "" for w in rows], legend="A - active (трафик идёт через этот WAN)")


def multiwan_set(ctx, pos, named):
    c = ctx.api.get("/api/wan/multiwan")["config"]
    for k, f in (("mode", "mode"), ("primary", "primary")):
        if k in named:
            c[f] = named[k]
    for k, f in (("weight1", "weight1"), ("weight2", "weight2"), ("interval", "interval"),
                 ("fail-after", "fail_after"), ("recover-after", "recover_after")):
        if k in named:
            c[f] = int(named[k])
    if "check-targets" in named:
        c["check_targets"] = [x for x in named["check-targets"].split(",") if x]
    ctx.api.put("/api/wan/multiwan", c)


def wan2_print(ctx, pos, named):
    d = ctx.api.get("/api/wan/wan2")
    c = d["config"]
    kv(ctx, [("enabled", c.get("enabled", False)), ("interface", c["interface"] or "-"), ("mode", c["mode"]),
             ("address", ", ".join(d["addresses"]) or "-"), ("gateway", d["gateway"] or "-"),
             ("dns", ",".join(d["dns"]) or "-"), ("vlan-id", c.get("vlan_id")), ("status", d.get("dhcp_state") or "-")])


def wan2_set(ctx, pos, named):
    c = dict(ctx.api.get("/api/wan/wan2")["config"])
    if "enabled" in named:
        c["enabled"] = yes(named["enabled"])
    for k in ("interface", "mode", "address", "gateway"):
        if k in named:
            c[k] = named[k] or None
    if "dns" in named:
        c["dns"] = [x for x in named["dns"].split(",") if x]
    if "vlan-id" in named:
        c["vlan_id"] = int(named["vlan-id"]) if named["vlan-id"] else None
    ctx.api.put("/api/wan/wan2", c)


def ntp_client_print(ctx, pos, named):
    d = ctx.api.get("/api/system/ntp")
    c = d["config"]
    kv(ctx, [("enabled", c["enabled"]), ("servers", ",".join(c["servers"]) or "-"),
             ("status", "synchronized" if d["synced"] else ("running" if d["running"] else "stopped")),
             ("stratum", d.get("stratum")), ("reference", d.get("reference")),
             ("offset", f'{d["offset"] * 1000:.3f}ms' if d.get("offset") is not None else None),
             ("set-system-clock", d["clock_control"]), ("error", d.get("error"))])
    if d.get("sources"):
        ctx.out("")
        table(ctx, ["address", "stratum", "reach", "offset"],
              [[x["address"], x["stratum"], oct(x["reach"] or 0)[2:], f'{(x["offset"] or 0) * 1000:.3f}ms'] for x in d["sources"]],
              flags=[x["state"] for x in d["sources"]], legend="* - выбран, + - используется, ? - нет ответа")


def _ntp_put(ctx, **changes):
    c = dict(ctx.api.get("/api/system/ntp")["config"])
    c.update(changes)
    ctx.api.put("/api/system/ntp", c)


def ntp_client_set(ctx, pos, named):
    ch = {}
    if "enabled" in named:
        ch["enabled"] = yes(named["enabled"])
    if "servers" in named:
        ch["servers"] = [x for x in named["servers"].split(",") if x]
    _ntp_put(ctx, **ch)


def ntp_server_print(ctx, pos, named):
    d = ctx.api.get("/api/system/ntp")
    c = d["config"]
    kv(ctx, [("enabled", c["serve_lan"]), ("orphan", c["orphan"]), ("networks", ",".join(d["serving"]) or "-")])


def ntp_server_set(ctx, pos, named):
    ch = {}
    if "enabled" in named:
        ch["serve_lan"] = yes(named["enabled"])
    if "orphan" in named:
        ch["orphan"] = yes(named["orphan"])
    _ntp_put(ctx, **ch)


def wol_cmd(ctx, pos, named):
    mac = named.get("mac") or (pos[0] if pos else None)
    if not mac:
        raise CliError("укажите mac=3c:52:82:aa:bb:cc")
    r = ctx.api.post("/api/tools/wol", {"mac": mac, "lan": named.get("interface")})
    sent = (r or {}).get("sent") or []
    ctx.out(f"magic packet sent to {(r or {}).get('mac', mac)}" + (f" via {', '.join(x['bridge'] for x in sent)}" if sent else ""))


def clock_set(ctx, pos, named):
    require(named, "time-zone-name")
    _ntp_put(ctx, timezone=named["time-zone-name"])


# --- планировщик и очереди (/system scheduler, /queue) ----------------------------------------------------------
DAY_NAMES = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _interval_min(text: str) -> int:
    t = text.strip().lower()
    mult = {"m": 1, "h": 60, "d": 1440}
    if t[-1:] in mult and t[:-1].isdigit():
        return int(t[:-1]) * mult[t[-1]]
    if t.isdigit():
        return int(t)
    raise CliError(f"interval: например 15m, 1h или 1d, а не '{text}'")


def _schedule_from(named: dict, base: dict | None = None) -> dict:
    s = dict(base or {"kind": "daily", "time": "08:00"})
    if "cron" in named:
        return {"kind": "cron", "cron": named["cron"]}
    t = named.get("start-time", s.get("time", "08:00"))
    if "start-date" in named:
        return {"kind": "once", "at": f"{named['start-date']}T{t}"}
    if "days" in named:
        days = [DAY_NAMES.index(d.strip()[:3].lower()) for d in named["days"].split(",") if d.strip()[:3].lower() in DAY_NAMES]
        return {"kind": "weekly", "time": t, "days": days}
    if "interval" in named:
        m = _interval_min(named["interval"])
        return {"kind": "daily", "time": t} if m == 1440 else {"kind": "interval", "every": m}
    if "start-time" in named:
        s.update(time=t, kind=s.get("kind") if s.get("kind") in ("daily", "weekly") else "daily")
    return s


def _action_from(named: dict, base: dict | None = None) -> dict:
    a = dict(base or {})
    if "on-event" in named:
        a = {"type": named["on-event"]}
    for k, f in (("mac", "mac"), ("lan", "lan"), ("device", "device"), ("wan", "wan")):
        if k in named:
            a[f] = named[k]
    if "target" in named:
        a["target"] = int(named["target"])
    if "set-enabled" in named:
        a["enabled"] = yes(named["set-enabled"])
    return a


def scheduler_print(ctx, pos, named):
    d = ctx.api.get("/api/scheduler")
    tasks = d["tasks"]
    ctx.numbers["/system scheduler"] = tasks
    ctx.out(f"time-zone: {d['timezone']}")
    table(ctx, ["name", "schedule", "next-run", "last-run"],
          [[t["name"], t["description"], (t["next_run"] or "").replace("T", " "),
            ("" if t["last_run"] is None else ("ok " if t["last_ok"] else "fail ") + t["last_run"][:16].replace("T", " "))]
           for t in tasks], flags=["" if t["enabled"] else "X" for t in tasks], legend="X - disabled")


def scheduler_add(ctx, pos, named):
    require(named, "name", "on-event")
    body = {"name": named["name"], "enabled": not yes(named.get("disabled")),
            "schedule": _schedule_from(named), "action": _action_from(named)}
    ctx.api.post("/api/scheduler/tasks", body)


def _task_body(t: dict) -> dict:
    return {k: t[k] for k in ("name", "enabled", "schedule", "action")}


def scheduler_set(ctx, pos, named):
    for t in pick(ctx, "/system scheduler", pos, named):
        body = _task_body(t)
        if "name" in named:
            body["name"] = named["name"]
        if "disabled" in named:
            body["enabled"] = not yes(named["disabled"])
        if any(k in named for k in ("cron", "start-time", "start-date", "days", "interval")):
            body["schedule"] = _schedule_from(named, t["schedule"])
        body["action"] = _action_from(named, t["action"])
        ctx.api.put(f"/api/scheduler/tasks/{t['id']}", body)


def _scheduler_toggle(on: bool):
    def fn(ctx, pos, named):
        for t in pick(ctx, "/system scheduler", pos, named):
            ctx.api.put(f"/api/scheduler/tasks/{t['id']}", {**_task_body(t), "enabled": on})
    return fn


def scheduler_remove(ctx, pos, named):
    for t in pick(ctx, "/system scheduler", pos, named):
        ctx.api.delete(f"/api/scheduler/tasks/{t['id']}")


def scheduler_run(ctx, pos, named):
    for t in pick(ctx, "/system scheduler", pos, named):
        r = ctx.api.post(f"/api/scheduler/tasks/{t['id']}/run") or {}
        ctx.out(f"{t['name']}: {'ok' if r.get('ok') else 'fail'} — {r.get('message', '')}")


def parse_rate(text: str) -> float | None:
    """'10M' -> 10.0 Мбит/с, '512k' -> 0.512, '1G' -> 1000, '0' -> без ограничения."""
    t = (text or "").strip().lower().removesuffix("bps")
    if t in ("", "0", "unlimited"):
        return None
    mult = {"k": 0.001, "m": 1.0, "g": 1000.0}
    try:
        return round(float(t[:-1]) * mult[t[-1]], 3) if t[-1] in mult else float(t) / 1_000_000
    except (ValueError, KeyError):
        raise CliError(f"скорость: например 10M, 512k или 1G, а не '{text}'")


def parse_limit(text: str) -> tuple[float | None, float | None]:
    """max-limit=отдача/загрузка, как в RouterOS."""
    up, _, down = text.partition("/")
    return parse_rate(up), parse_rate(down or up)


def _fmt_rate(v) -> str:
    if not v:
        return "unlimited"
    return f"{v:g}M" if v >= 1 else f"{v * 1000:g}k"


def _qos(ctx) -> dict:
    import copy
    return copy.deepcopy(ctx.api.get("/api/qos"))


def queue_settings_print(ctx, pos, named):
    d = _qos(ctx)
    c = d["config"]
    kv(ctx, [("enabled", c["enabled"]), ("active", d["active"]),
             ("wan-limit", f'{_fmt_rate(c.get("wan_up"))}/{_fmt_rate(c.get("wan_down"))}'),
             ("voice-priority", c["voice"]), ("sip-ports", c["sip_ports"]), ("rtp-ports", c["rtp_ports"]),
             ("error", d.get("error"))])


def queue_settings_set(ctx, pos, named):
    c = _qos(ctx)["config"]
    if "enabled" in named:
        c["enabled"] = yes(named["enabled"])
    if "wan-limit" in named:
        c["wan_up"], c["wan_down"] = parse_limit(named["wan-limit"])
    if "voice-priority" in named:
        c["voice"] = yes(named["voice-priority"])
    for k, f in (("sip-ports", "sip_ports"), ("rtp-ports", "rtp_ports")):
        if k in named:
            c[f] = named[k]
    ctx.api.put("/api/qos", c)


def queue_segment_print(ctx, pos, named):
    d = _qos(ctx)
    lim = {x["lan"]: x for x in d["config"]["segments"]}
    table(ctx, ["segment", "network", "max-limit"],
          [[s["name"], s["network"], f'{_fmt_rate((lim.get(s["id"]) or {}).get("up"))}/{_fmt_rate((lim.get(s["id"]) or {}).get("down"))}']
           for s in d["segments"]])


def queue_segment_set(ctx, pos, named):
    require(named, "lan", "max-limit")
    d = _qos(ctx)
    seg = next((s for s in d["segments"] if named["lan"] in (s["id"], s["name"])), None)
    if not seg:
        raise CliError(f"нет сегмента {named['lan']}")
    up, down = parse_limit(named["max-limit"])
    c = d["config"]
    c["segments"] = [x for x in c["segments"] if x["lan"] != seg["id"]]
    if up or down:
        c["segments"].append({"lan": seg["id"], "up": up, "down": down})
    ctx.api.put("/api/qos", c)


def queue_simple_print(ctx, pos, named):
    d = _qos(ctx)
    devs = d["config"]["devices"]
    ctx.numbers["/queue simple"] = devs
    table(ctx, ["name", "target", "max-limit"],
          [[x.get("name") or "", x["ip"], f'{_fmt_rate(x.get("up"))}/{_fmt_rate(x.get("down"))}'] for x in devs],
          flags=["" if x["enabled"] else "X" for x in devs], legend="X - disabled")


def queue_simple_add(ctx, pos, named):
    require(named, "target", "max-limit")
    c = _qos(ctx)["config"]
    up, down = parse_limit(named["max-limit"])
    c["devices"].append({"ip": named["target"], "name": named.get("name"), "up": up, "down": down,
                         "enabled": not yes(named.get("disabled"))})
    ctx.api.put("/api/qos", c)


def _queue_edit(fn):
    def run(ctx, pos, named):
        picked = {x["ip"] for x in pick(ctx, "/queue simple", pos, named)}
        c = _qos(ctx)["config"]
        c["devices"] = [d for d in (fn(x, named) if x["ip"] in picked else x for x in c["devices"]) if d]
        ctx.api.put("/api/qos", c)
    return run


def _qs_set(x, named):
    if "max-limit" in named:
        x["up"], x["down"] = parse_limit(named["max-limit"])
    if "name" in named:
        x["name"] = named["name"] or None
    if "target" in named:
        x["ip"] = named["target"]
    if "disabled" in named:
        x["enabled"] = not yes(named["disabled"])
    return x


# --- дерево меню ------------------------------------------------------------------------------------------------------
P = "показать"


def pr(fn):
    return Cmd(fn, P, ("detail",))


ROOT = Menu("OutpostGate Pro", {
    "interface": Menu("интерфейсы", {
        "print": pr(interface_print),
        "monitor-traffic": Cmd(monitor_traffic, "скорость интерфейса: monitor-traffic eth0 (Ctrl-C — стоп)",
                               ("interface", "once"), {**IFACE, "once": YESNO}),
        "ethernet": Menu("физические порты", {"print": pr(interface_print)}),
        "bridge": Menu("мосты сегментов LAN", {"print": pr(bridge_print), "port": Menu("порты моста", {"print": pr(bridge_port_print)})}),
        "vlan": Menu("VLAN 802.1Q (настройка — во вкладках LAN и WAN)", {"print": pr(vlan_print)}),
        "wireguard": Menu("WireGuard / AmneziaWG", {"print": pr(wireguard_print),
                                                    "peers": Menu("сервер", {"print": pr(wireguard_peers_print)})}),
        "l2tp-client": Menu("L2TP/IPsec", {"print": pr(l2tp_client_print)}),
        "gre": Menu("туннели GRE «роутер — роутер» (поверх AmneziaWG / WireGuard / WAN)", {
            "print": pr(gre_print),
            "add": Cmd(gre_add, "add remote-address=10.8.1.3 local-address=10.8.1.2 underlay=awg0 "
                                "address=172.16.0.1/30 routes=192.168.20.0/24 [ospf=yes]",
                       tuple(GRE_FIELDS), {"disabled": YESNO, "ospf": YESNO, "underlay": iface_names}),
            "set": Cmd(gre_set, "изменить: set 0 routes=192.168.20.0/24,192.168.21.0/24",
                       ("numbers",) + tuple(k for k in GRE_FIELDS if k != "name"),
                       {"disabled": YESNO, "ospf": YESNO}),
            "enable": Cmd(gre_enable, "включить: enable 0", ("numbers",)),
            "disable": Cmd(gre_disable, "выключить: disable 0", ("numbers",)),
            "remove": Cmd(gre_remove, "удалить: remove 0", ("numbers",)),
        }),
    }),
    "ip": Menu("IP", {
        "multiwan": Menu("два провайдера: резерв или балансировка", {
            "print": Cmd(multiwan_print, P),
            "set": Cmd(multiwan_set, "set mode=failover primary=wan1 | mode=balance weight1=2 weight2=1",
                       ("mode", "primary", "weight1", "weight2", "check-targets", "interval", "fail-after", "recover-after"),
                       {"mode": ["failover", "balance"], "primary": ["wan1", "wan2"]}),
        }),
        "wan2": Menu("второй провайдер", {
            "print": Cmd(wan2_print, P),
            "set": Cmd(wan2_set, "set enabled=yes interface=eth2 mode=dhcp | mode=static address=... gateway=...",
                       ("enabled", "interface", "mode", "address", "gateway", "dns", "vlan-id"),
                       {"enabled": YESNO, "mode": ["dhcp", "static", "none"]}),
        }),
        "address": Menu("IP-адреса", {
            "print": pr(address_print),
            "add": Cmd(address_add, "добавить: add address=10.0.0.1/24 interface=eth2",
                       ("address", "interface", "comment", "disabled"), {**IFACE, "disabled": YESNO}),
            **_crud("/api/ip/addresses", "/ip address", {"address": "address", "interface": "interface",
                                                          "comment": "comment"}),
        }),
        "route": Menu("маршруты", {
            "print": pr(route_print),
            "add": Cmd(route_add, "добавить: add dst-address=10.0.0.0/8 gateway=192.168.88.254",
                       ("dst-address", "gateway", "distance", "comment", "disabled"), {"disabled": YESNO}),
            **_crud("/api/ip/routes", "/ip route", {"dst-address": "dst_address", "gateway": "gateway",
                                                     "distance": "distance", "comment": "comment"}),
        }),
        "arp": Menu("таблица ARP", {"print": pr(arp_print)}),
        "neighbor": Menu("соседи (ARP)", {"print": pr(arp_print)}),
        "pool": Menu("пулы адресов", {"print": pr(pool_print)}),
        "dhcp-server": Menu("DHCP-сервер", {
            "print": pr(dhcp_print),
            "network": Menu("сети DHCP", {"print": pr(dhcp_network_print)}),
            "lease": Menu("аренды и закреплённые адреса", {
                "print": pr(lease_print),
                "make-static": Cmd(lease_make_static, "закрепить: make-static 3", ("numbers",)),
                "add": Cmd(lease_add, "закрепить вручную: add mac-address=... address=...",
                           ("mac-address", "address", "comment")),
                "set": Cmd(lease_set, "изменить: set 0 address=... comment=...", ("numbers", "address", "comment")),
                "remove": Cmd(lease_remove, "открепить: remove 0", ("numbers",)),
            }),
        }),
        "dhcp-client": Menu("DHCP-клиент WAN", {"print": pr(dhcp_client_print),
                                                 "renew": Cmd(dhcp_client_renew, "обновить аренду")}),
        "smb": Menu("файловый сервер Samba", {
            "print": Cmd(smb_print, P),
            "set": Cmd(smb_set, "set enabled=yes workgroup=WORKGROUP segments=lan1,lan2 netbios=no",
                       ("enabled", "workgroup", "netbios-name", "comment", "segments", "min-protocol", "netbios"),
                       {"enabled": YESNO, "netbios": YESNO, "min-protocol": ["SMB2_10", "SMB3"]}),
            "shares": Menu("общие папки", {
                "print": pr(smb_shares_print),
                "add": Cmd(smb_shares_add, "add name=Documents directory=data:/docs write-users=@acc read-users=boris",
                           ("name", "directory", "read-users", "write-users", "guest", "comment", "recycle", "browseable",
                            "macos", "disabled"),
                           {"guest": ["none", "read", "write"], "recycle": YESNO, "browseable": YESNO, "macos": YESNO,
                            "disabled": YESNO}),
                "set": Cmd(smb_shares_set, "изменить: set 0 write-users=@acc,anna",
                           ("numbers", "name", "directory", "read-users", "write-users", "guest", "comment", "recycle",
                            "browseable", "macos", "disabled"),
                           {"guest": ["none", "read", "write"], "recycle": YESNO, "browseable": YESNO, "macos": YESNO,
                            "disabled": YESNO}),
                "enable": Cmd(smb_shares_enable, "включить", ("numbers",)),
                "disable": Cmd(smb_shares_disable, "выключить", ("numbers",)),
                "remove": Cmd(smb_shares_remove, "удалить (файлы остаются)", ("numbers",)),
            }),
            "users": Menu("пользователи файлового сервера", {
                "print": pr(smb_users_print),
                "add": Cmd(smb_users_add, "add name=anna groups=acc full-name=\"Anna K\" (пароль спросит)",
                           ("name", "password", "full-name", "groups")),
                "set": Cmd(smb_users_set, "set 0 password=... | groups=acc,sales | disabled=yes",
                           ("numbers", "password", "full-name", "groups", "disabled"), {"disabled": YESNO}),
                "enable": Cmd(smb_users_enable, "включить", ("numbers",)),
                "disable": Cmd(smb_users_disable, "выключить", ("numbers",)),
                "remove": Cmd(smb_users_remove, "удалить", ("numbers",)),
            }),
            "groups": Menu("группы", {
                "print": pr(smb_groups_print),
                "add": Cmd(smb_groups_add, "add name=acc comment=Бухгалтерия", ("name", "comment")),
                "remove": Cmd(smb_groups_remove, "удалить", ("numbers",)),
            }),
            "sessions": Menu("кто подключён", {"print": pr(smb_sessions_print)}),
            "disks": Menu("диски сервера (режим host)", {"print": pr(smb_disks_print)}),
        }),
        "dns": Menu("DNS-сервер (BIND)", {
            "print": Cmd(dns_print, P),
            "set": Cmd(dns_set, "set servers=1.1.1.1,8.8.8.8 forward-only=no dnssec=no cache-size=64MiB",
                       ("servers", "forward-only", "dnssec", "cache-size"),
                       {"forward-only": YESNO, "dnssec": YESNO}),
            "static": Menu("записи зон", {
                "print": pr(dns_static_print),
                "add": Cmd(dns_static_add, "add name=pbx.office.lan address=192.168.88.5 | type=CNAME cname=pbx",
                           ("name", "type", "address", "cname", "text", "value", "mx-exchange", "mx-preference",
                            "srv-target", "srv-priority", "srv-weight", "srv-port", "ns", "ttl", "comment"),
                           {"type": DNS_TYPES}),
                "remove": Cmd(dns_static_remove, "удалить: remove 0", ("numbers",)),
            }),
        }),
        "service": Menu("службы управления", {"print": pr(service_print)}),
        "firewall": Menu("фаервол", {
            "filter": Menu("правила", {
                "print": pr(filter_print),
                "add": Cmd(filter_add, "add chain=input protocol=tcp dst-port=22 src-address=... action=accept",
                           RULE_FIELDS, RULE_VALUES),
                "set": Cmd(filter_set, "изменить: set 0 параметр=значение", ("numbers",) + RULE_FIELDS, RULE_VALUES),
                "enable": Cmd(_filter_toggle(True), "включить", ("numbers",)),
                "disable": Cmd(_filter_toggle(False), "выключить", ("numbers",)),
                "remove": Cmd(filter_remove, "удалить", ("numbers",)),
                "move": Cmd(filter_move, "порядок: move 3 0", ("numbers", "destination")),
            }),
            "nat": Menu("проброс портов", {
                "print": pr(nat_print),
                "add": Cmd(nat_add, "add chain=dstnat action=dst-nat protocol=tcp dst-port=8080 "
                                    "to-addresses=192.168.88.20 to-ports=80", NAT_FIELDS,
                           {"chain": ["dstnat"], "action": ["dst-nat"], "protocol": ["tcp", "udp", "tcp,udp"],
                            "in-interface-list": ["WAN", "VPN", "WAN,VPN"], "disabled": YESNO}),
                "set": Cmd(nat_set, "изменить: set 0 параметр=значение", ("numbers",) + NAT_FIELDS),
                "enable": Cmd(_nat_toggle(True), "включить", ("numbers",)),
                "disable": Cmd(_nat_toggle(False), "выключить", ("numbers",)),
                "remove": Cmd(nat_remove, "удалить", ("numbers",)),
            }),
        }),
    }),
    "wan": Menu("WAN", {
        "print": Cmd(wan_print, P),
        "set": Cmd(wan_set, "set mode=dhcp | mode=static address=... gateway=... dns=...",
                   ("mode", "address", "gateway", "dns", "interface"),
                   {"mode": ["dhcp", "static", "none"], **IFACE}),
        "renew": Cmd(dhcp_client_renew, "обновить аренду DHCP"),
    }),
    "lan": Menu("LAN", {"print": Cmd(lan_print, P)}),
    "vpn": Menu("VPN", {"print": Cmd(vpn_print, P)}),
    "routing": Menu("маршрутизация: OSPF и BGP", {
        "ospf": Menu("OSPF", {
            "instance": Menu("настройки OSPF", {
                "print": pr(ospf_instance_print),
                "set": Cmd(ospf_instance_set, "set disabled=no router-id=10.255.0.1 redistribute=connected "
                                              "originate-default=if-installed",
                           ("numbers", "disabled", "router-id", "redistribute", "originate-default", "passive-default"),
                           {"disabled": YESNO, "passive-default": YESNO, "originate-default": list(ORIGINATE),
                            "redistribute": ["connected", "static", "kernel", "bgp"]}),
                "enable": Cmd(_ospf_toggle(True), "включить OSPF"),
                "disable": Cmd(_ospf_toggle(False), "выключить OSPF"),
            }),
            "network": Menu("сети OSPF", {
                "print": pr(ospf_network_print),
                "add": Cmd(ospf_network_add, "add network=192.168.88.0/24 area=backbone", ("network", "area"),
                           {"area": ["backbone"]}),
                "remove": Cmd(ospf_network_remove, "удалить: remove 0", ("numbers",)),
            }),
            "interface": Menu("интерфейсы OSPF", {
                "print": pr(ospf_interface_print),
                "add": Cmd(ospf_interface_add, "add interface=wg0 network-type=point-to-point cost=10",
                           OSPF_IF_FIELDS, OSPF_IF_VALUES),
                "set": Cmd(ospf_interface_set, "изменить: set 0 cost=20", ("numbers",) + OSPF_IF_FIELDS, OSPF_IF_VALUES),
                "remove": Cmd(ospf_interface_remove, "удалить: remove 0", ("numbers",)),
            }),
            "neighbor": Menu("соседи OSPF", {"print": pr(ospf_neighbor_print)}),
        }),
        "bgp": Menu("BGP", {
            "instance": Menu("настройки BGP", {
                "print": pr(bgp_instance_print),
                "set": Cmd(bgp_instance_set, "set disabled=no as=65001 router-id=10.255.0.1 redistribute=connected",
                           ("numbers", "disabled", "as", "router-id", "redistribute"),
                           {"disabled": YESNO, "redistribute": ["connected", "static", "kernel", "ospf"]}),
                "enable": Cmd(_bgp_toggle(True), "включить BGP"),
                "disable": Cmd(_bgp_toggle(False), "выключить BGP"),
            }),
            "network": Menu("объявляемые сети", {
                "print": pr(bgp_network_print),
                "add": Cmd(bgp_network_add, "add network=192.168.88.0/24", ("network",)),
                "remove": Cmd(bgp_network_remove, "удалить: remove 0", ("numbers",)),
            }),
            "peer": Menu("соседи BGP", {
                "print": pr(bgp_peer_print),
                "add": Cmd(bgp_peer_add, "add remote-address=10.8.0.1 remote-as=65000 comment=HQ",
                           PEER_FIELDS, {"disabled": YESNO, "update-source": iface_names}),
                "set": Cmd(bgp_peer_set, "изменить: set 0 tcp-md5-key=...", ("numbers",) + PEER_FIELDS,
                           {"disabled": YESNO, "update-source": iface_names}),
                "enable": Cmd(bgp_peer_enable, "включить", ("numbers",)),
                "disable": Cmd(bgp_peer_disable, "выключить", ("numbers",)),
                "remove": Cmd(bgp_peer_remove, "удалить", ("numbers",)),
            }),
            "session": Menu("состояние сессий", {"print": pr(bgp_peer_print)}),
        }),
        "route": Menu("маршруты от OSPF и BGP", {"print": pr(routing_route_print)}),
    }),
    "system": Menu("система", {
        "resource": Menu("ресурсы", {"print": Cmd(resource_print, P)}),
        "identity": Menu("имя роутера", {"print": Cmd(identity_print, P),
                                          "set": Cmd(identity_set, "set name=...", ("name",))}),
        "clock": Menu("время", {"print": Cmd(clock_print, P),
                                "set": Cmd(clock_set, "set time-zone-name=Asia/Jerusalem", ("time-zone-name",))}),
        "routerboard": Menu("устройство", {"print": Cmd(routerboard_print, P)}),
        "package": Menu("версия", {"print": pr(package_print)}),
        "monitoring": Menu("мониторинг и экспорт (Prometheus, SNMP, Zabbix)", {"print": Cmd(monitoring_print, P)}),
        "scheduler": Menu("задачи по расписанию", {
            "print": Cmd(scheduler_print, P),
            "add": Cmd(scheduler_add, "add name=wake on-event=wol mac=3c:52:82:aa:bb:cc start-time=08:00 days=mon,tue,wed,thu,fri",
                       ("name", "start-time", "start-date", "interval", "days", "cron", "on-event", "mac", "lan", "target", "device", "set-enabled", "wan", "disabled"),
                       {"on-event": ["wol", "lan_segment", "firewall_rule", "port_forward", "vpn", "qos_device", "backup",
                                     "wan_renew", "multiwan_primary", "restart"],
                        "set-enabled": YESNO, "disabled": YESNO, "wan": ["wan1", "wan2"]}),
            "set": Cmd(scheduler_set, "set 0 start-time=09:00 | interval=15m | cron=\"0 8 * * 1-5\"", ("numbers",) + ("name", "start-time", "start-date", "interval", "days", "cron", "on-event", "mac", "lan", "target", "device", "set-enabled", "wan", "disabled"),
                       {"set-enabled": YESNO, "disabled": YESNO}),
            "enable": Cmd(_scheduler_toggle(True), "включить", ("numbers",)),
            "disable": Cmd(_scheduler_toggle(False), "выключить", ("numbers",)),
            "remove": Cmd(scheduler_remove, "удалить", ("numbers",)),
            "run": Cmd(scheduler_run, "выполнить сейчас: run 0", ("numbers",)),
        }),
        "ntp": Menu("время (chrony)", {
            "client": Menu("синхронизация роутера", {
                "print": Cmd(ntp_client_print, P),
                "set": Cmd(ntp_client_set, "set enabled=yes servers=pool.ntp.org,time.google.com",
                           ("enabled", "servers"), {"enabled": YESNO})}),
            "server": Menu("раздача времени в LAN", {
                "print": Cmd(ntp_server_print, P),
                "set": Cmd(ntp_server_set, "set enabled=yes orphan=no", ("enabled", "orphan"),
                           {"enabled": YESNO, "orphan": YESNO})}),
        }),
        "shell": Cmd(system_shell, "командная строка Linux (bash); назад — exit или Ctrl-D"),
        "reboot": Cmd(system_reboot, "перезапустить сервис роутера"),
    }),
    "user": Menu("пользователи", {
        "print": pr(user_print),
        "add": Cmd(user_add, "add name=ivan group=full|read (пароль спросит)", ("name", "group", "password"),
                   {"group": ["full", "read"]}),
        "set": Cmd(user_set, "set 1 group=read | password=...", ("numbers", "group", "password"),
                   {"group": ["full", "read"]}),
        "remove": Cmd(user_remove, "удалить: remove 1", ("numbers",)),
    }),
    "password": Cmd(password, "сменить свой пароль", ("old-password", "new-password", "confirm-new-password")),
    "log": Menu("журнал действий", {"print": Cmd(log_print, P, ("count",))}),
    "tool": Menu("инструменты", {
        "ping": Cmd(ping, "ping 8.8.8.8 count=4 interface=wg0", ("address", "count", "interface"), IFACE),
        "traceroute": Cmd(traceroute, "traceroute 8.8.8.8", ("address", "max-hops", "interface"), IFACE),
        "ip-scan": Cmd(ip_scan, "устройства в сети: ip-scan address-range=192.168.88.0/24",
                       ("address-range", "interface"), IFACE),
        "dns-lookup": Cmd(dns_lookup, "dns-lookup name=example.com", ("name",)),
        "torch": Cmd(torch, "кто качает: torch segment=LAN count=20", ("segment", "count")),
        "wol": Cmd(wol_cmd, "разбудить компьютер: wol mac=3c:52:82:aa:bb:cc interface=br-lan", ("mac", "interface")),
    }),
    "queue": Menu("QoS: ограничения скорости и приоритет голосу", {
        "settings": Menu("общие настройки", {
            "print": Cmd(queue_settings_print, P),
            "set": Cmd(queue_settings_set, "set enabled=yes wan-limit=50M/200M voice-priority=yes",
                       ("enabled", "wan-limit", "voice-priority", "sip-ports", "rtp-ports"),
                       {"enabled": YESNO, "voice-priority": YESNO}),
        }),
        "segment": Menu("лимиты сегментов LAN", {
            "print": Cmd(queue_segment_print, P),
            "set": Cmd(queue_segment_set, "set lan=Guests max-limit=5M/20M (отдача/загрузка; 0 — без лимита)",
                       ("lan", "max-limit")),
        }),
        "simple": Menu("лимиты устройств", {
            "print": Cmd(queue_simple_print, P),
            "add": Cmd(queue_simple_add, "add name=laptop target=192.168.88.20 max-limit=2M/10M",
                       ("name", "target", "max-limit", "disabled"), {"disabled": YESNO}),
            "set": Cmd(_queue_edit(_qs_set), "set 0 max-limit=5M/20M", ("numbers", "name", "target", "max-limit", "disabled"),
                       {"disabled": YESNO}),
            "enable": Cmd(_queue_edit(lambda x, n: {**x, "enabled": True}), "включить", ("numbers",)),
            "disable": Cmd(_queue_edit(lambda x, n: {**x, "enabled": False}), "выключить", ("numbers",)),
            "remove": Cmd(_queue_edit(lambda x, n: None), "удалить", ("numbers",)),
        }),
    }),
    "snmp": Menu("SNMP-агент", {
        "print": Cmd(snmp_print, P),
        "set": Cmd(snmp_set, "set enabled=yes community=office allowed=10.0.0.5 | version=v3 user=zbx",
                   ("enabled", "version", "community", "user", "auth-password", "priv-password",
                    "contact", "location", "allowed"), {"enabled": YESNO, "version": ["v2c", "v3"]}),
    }),
    "ping": Cmd(ping, "ping 8.8.8.8 count=4 interface=wg0", ("address", "count", "interface"), IFACE),
    "traceroute": Cmd(traceroute, "traceroute 8.8.8.8", ("address", "max-hops", "interface"), IFACE),
    "resolve": Cmd(resolve_cmd, "адрес имени через DNS роутера: :resolve samba | :resolve samba.office.lan",
                   ("domain-name",)),
    "export": Cmd(export, "конфигурация командами (show-sensitive — с секретами; format=yaml — router.yaml)",
                  ("show-sensitive", "format"), {"show-sensitive": YESNO, "format": ["rsc", "yaml"]}),
    "quit": Cmd(quit_cmd, "выйти"),
})
GLOBAL = ("ping", "traceroute", "resolve", "export", "quit", "password")      # работают из любого меню


def node_at(path: list[str]) -> Menu:
    node = ROOT
    for p in path:
        node = node.children[p]
    return node


def path_str(path: list[str]) -> str:
    return "/" + " ".join(path) if path else ""


def _child(node: Menu, word: str, line: str):
    """Точное имя или однозначное сокращение (как в RouterOS); глобальные команды — из любого меню."""
    if word in node.children:
        return word, node.children[word]
    matches = [k for k in node.children if k.startswith(word)]
    if len(matches) > 1:
        raise CliError(f"ambiguous value of {word}, more than one possible value: {', '.join(sorted(matches))}")
    if matches:
        return matches[0], node.children[matches[0]]
    glob = [g for g in GLOBAL if g.startswith(word)]
    if len(glob) == 1:
        return glob[0], ROOT.children[glob[0]]
    raise CliError(f"bad command name {word} (line 1 column {line.find(word) + 1})")


# --- разбор строки ----------------------------------------------------------------------------------------------------
def parse(line: str, cwd: list[str]) -> tuple[list[str], Cmd | None, list[str]]:
    """-> (путь меню, команда или None, аргументы). Без команды — переход в меню."""
    try:
        tokens = shlex.split(line)
    except ValueError as e:
        raise CliError(f"syntax error ({e})") from e
    if tokens and tokens[0].startswith(":") and len(tokens[0]) > 1:   # :resolve, :put — команды RouterOS
        tokens[0] = tokens[0][1:]
    if tokens and tokens[0].startswith("/"):          # абсолютный путь: /ip address  или  /ip/address/print
        path = []
        rest = [p for p in tokens[0].split("/") if p] + tokens[1:]
    else:                                             # относительно текущего меню
        path = list(cwd)
        rest = list(tokens)
    while rest:
        w = rest[0]
        if w == "..":
            path = path[:-1]
            rest.pop(0)
            continue
        name, child = _child(node_at(path), w, line)
        if isinstance(child, Menu):
            path.append(name)
            rest.pop(0)
        else:
            return path, child, rest[1:]
    return path, None, []


def execute(ctx: Ctx, line: str, cwd: list[str]) -> list[str]:
    """Выполнить строку; вернуть новый текущий путь меню."""
    line = line.strip()
    if not line:
        return cwd
    if line in ("?", "help") or line.endswith(" ?"):
        path, cmd, _ = parse(line[:-1].strip(), cwd) if line.endswith(" ?") else (cwd, None, [])
        show_help(ctx, path, cmd)
        return cwd
    path, cmd, args = parse(line, cwd)
    if cmd is None:
        return path
    pos, named = split_args(args)
    named = expand_params(cmd, named)
    ctx.detail = "detail" in pos
    pos = [p for p in pos if p != "detail"]
    try:
        cmd.fn(ctx, pos, named)
    except ApiError as e:
        raise CliError(f"failure: {e}") from e
    finally:
        ctx.detail = False
    return cwd


def show_help(ctx: Ctx, cwd: list[str], cmd: Cmd | None = None) -> None:
    if cmd:
        ctx.out(cmd.help)
        if cmd.params:
            ctx.out("  параметры: " + " ".join(p + "=" for p in cmd.params if p not in ("numbers", "detail")))
        return
    node = node_at(cwd)
    ctx.out(f"{path_str(cwd) or '/'} — {node.help}")
    for name, child in sorted(node.children.items(), key=lambda kv: (isinstance(kv[1], Cmd), kv[0])):
        mark = "/" if isinstance(child, Menu) else " "
        ctx.out(f"  {mark}{name:<16} {child.help}")
    ctx.out("  .. — вверх, / — в корень, Tab — подсказки, сокращения: /ip addr pr, «команда ?» — помощь по команде")


# --- автодополнение ----------------------------------------------------------------------------------------------------
def complete(text: str, cwd: list[str], ctx: Ctx | None = None) -> list[str]:
    """Варианты для последнего слова строки text (как Tab в RouterOS)."""
    parts = text.split(" ")
    last, head = parts[-1], " ".join(parts[:-1])
    if not head and last.startswith("/"):                      # /ip/addr<Tab>
        segs = last[1:].split("/")
        try:
            node = node_at(segs[:-1])
        except KeyError:
            return []
        base = "/" + "/".join(segs[:-1]) + ("/" if len(segs) > 1 else "")
        return [base + n for n in sorted(node.children) if n.startswith(segs[-1])]
    try:
        path, cmd, args = parse(head, cwd) if head else (list(cwd), None, [])
    except CliError:
        return []
    if cmd is None:
        node = node_at(path)
        return [n for n in sorted(node.children) if n.startswith(last)]
    if "=" in last:                                            # значение параметра: interface=e<Tab>
        key, val = last.split("=", 1)
        key = next((p for p in cmd.params if p == key), None) or next(
            (p for p in cmd.params if p.startswith(key)), key)
        options = cmd.values.get(key, [])
        if callable(options):
            options = options(ctx) if ctx else []
        return [f"{key}={o}" for o in options if o.startswith(val)]
    used = {a.split("=", 1)[0] for a in args if "=" in a}
    return [p + ("" if p == "detail" else "=") for p in cmd.params
            if p not in used and p != "numbers" and p.startswith(last)]
