"""
Синтаксис Linux в CLI роутера: ip (iproute2), bridge, ss, nmcli, ping, traceroute.

  * просмотр — настоящими утилитами: ip a, ip -br link, ip r, ip neigh, bridge link, ss -tlnp —
    роутер работает в сети сервера, вывод честный;
  * изменения — через API роутера (router.yaml), как кнопки в вебе: ip addr add / ip route add,
    nmcli con mod / up / down. Прямо в ядро не пишем — при следующем применении роутер стёр бы правку;
  * чего у роутера нет — отказ с подсказкой, как сделать это командой RouterOS.

Строка с «/» в начале — команда RouterOS и здесь: /ip firewall nat print.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import subprocess

from app.cli.commands import CliError, Quit, _run_live

SAFE_ARG = re.compile(r"^[A-Za-z0-9_.:/@%+,=-]+$")
IP_OPTS = {"-4", "-6", "-br", "-brief", "-s", "-stats", "-statistics", "-d", "-details", "-j", "-json",
           "-p", "-pretty", "-c", "-color", "-o", "-oneline", "-h", "-human", "-0", "-a", "-all"}
IP_OBJECTS = {"a": "address", "ad": "address", "addr": "address", "address": "address",
              "r": "route", "ro": "route", "route": "route", "l": "link", "li": "link", "link": "link",
              "n": "neigh", "ne": "neigh", "neigh": "neigh", "neighbor": "neigh", "neighbour": "neigh",
              "ru": "rule", "rule": "rule", "m": "maddress", "maddr": "maddress", "maddress": "maddress",
              "mr": "mroute", "mroute": "mroute", "tunnel": "tunnel", "tun": "tunnel"}
READ_VERBS = {None, "show", "list", "lst", "ls", "sh", "get"}

HELP = """Синтаксис Linux (как на сервере):
  ip a | ip -br a | ip addr show dev br-lan     адреса
  ip r | ip route get 8.8.8.8                    маршруты
  ip link | ip -s link | ip neigh | ip rule      интерфейсы, ARP, правила
  bridge link | bridge vlan                      мосты и VLAN
  ss -tlnp | ss -ulnp                            кто слушает порты
  ping -c 3 samba | traceroute 8.8.8.8           проверка связи (имена — через DNS роутера)
  ip addr add 10.10.0.1/24 dev br-lan           адрес (в конфиг роутера, как /ip address add)
  ip addr del 10.10.0.1/24 dev br-lan
  ip route add 192.168.20.0/24 via 172.16.0.2   маршрут (в конфиг, как /ip route add)
  ip route del 192.168.20.0/24
  nmcli | nmcli d | nmcli c                      устройства и «соединения» (WAN, сегменты LAN, VPN, GRE)
  nmcli c show lan1
  nmcli c mod wan ipv4.method manual ipv4.addresses 203.0.113.10/24 ipv4.gateway 203.0.113.1 ipv4.dns "1.1.1.1 8.8.8.8"
  nmcli c mod lan1 ipv4.addresses 192.168.1.1/24
  nmcli c up amneziawg | nmcli c down lan2
  /…           команда RouterOS (например, /ip firewall nat print)
  routeros     перейти на синтаксис MikroTik · exit — выход"""


# --- общие ---------------------------------------------------------------------------------------------
def _safe(args: list[str]) -> list[str]:
    for a in args:
        if not SAFE_ARG.match(a):
            raise CliError(f"недопустимый аргумент: {a}")
    return args


def _run(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        raise CliError(f"нет программы {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise CliError(f"{cmd[0]}: нет ответа за 15 с")
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0 and not r.stdout:
        raise CliError(out.strip() or f"{cmd[0]}: код {r.returncode}")
    return out.rstrip("\n")


def _print(ctx, text: str) -> None:
    for line in text.splitlines():
        ctx.out(line)


def _table(ctx, head: list[str], rows: list[list]) -> None:
    rows = [[("--" if v in (None, "") else str(v)) for v in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(head)]
    ctx.out("  ".join(h.ljust(w) for h, w in zip(head, widths)).rstrip())
    for r in rows:
        ctx.out("  ".join(v.ljust(w) for v, w in zip(r, widths)).rstrip())


def execute(ctx, line: str) -> None:
    try:
        argv = shlex.split(line)
    except ValueError as e:
        raise CliError(f"кавычки: {e}")
    if not argv:
        return
    cmd, args = argv[0], argv[1:]
    if cmd in ("exit", "quit", "logout"):
        raise Quit()
    if cmd in ("help", "?", "-h", "--help"):
        _print(ctx, HELP)
        return
    fn = {"ip": ip_cmd, "bridge": bridge_cmd, "ss": ss_cmd, "nmcli": nmcli, "ping": ping, "traceroute": traceroute,
          "tracepath": traceroute, "hostname": hostname, "clear": lambda c, a: c.out("\x1b[2J\x1b[H")}.get(cmd)
    if not fn:
        raise CliError(f"{cmd}: команда не поддерживается. help — список, /… — команда RouterOS, "
                       "/system shell — настоящий bash")
    fn(ctx, args)


def hostname(ctx, args):
    if args:
        raise CliError("имя роутера меняется так: /system identity set name=office")
    ctx.out(ctx.api.get("/api/auth/me").get("identity") or "outpost-gate-pro")


# --- ip --------------------------------------------------------------------------------------------------
def _split_ip(args: list[str]) -> tuple[list[str], str | None, list[str]]:
    opts, rest = [], list(args)
    while rest and rest[0].startswith("-"):
        o = rest.pop(0)
        if o not in IP_OPTS:
            raise CliError(f"ip: ключ {o} не поддерживается (можно: {' '.join(sorted(IP_OPTS))})")
        opts.append(o)
    if not rest:
        raise CliError("ip: укажите объект — address, route, link, neigh, rule")
    obj = IP_OBJECTS.get(rest[0])
    if not obj:
        raise CliError(f"ip {rest[0]}: объект не поддерживается (address, route, link, neigh, rule)")
    return opts, obj, rest[1:]


def ip_cmd(ctx, args):
    opts, obj, rest = _split_ip(args)
    verb = rest[0] if rest else None
    if verb in READ_VERBS or (verb and verb not in ("add", "del", "delete", "change", "replace", "set",
                                                       "flush", "append", "prepend", "exec", "save", "restore",
                                                       "attach", "detach", "monitor") and obj != "route"):
        _print(ctx, _run(["ip", *_safe(opts), obj, *_safe(rest)]))
        return
    if obj == "address" and verb == "add":
        return _addr_add(ctx, rest[1:])
    if obj == "address" and verb in ("del", "delete"):
        return _addr_del(ctx, rest[1:])
    if obj == "route" and verb in ("add", "replace", "append"):
        return _route_add(ctx, rest[1:])
    if obj == "route" and verb in ("del", "delete"):
        return _route_del(ctx, rest[1:])
    hints = {"link": "интерфейсы: /interface print; порты в сегментах — /lan, nmcli c mod; выключить сегмент — nmcli c down lan2",
             "neigh": "ARP-таблица только для просмотра: ip neigh",
             "rule": "правила маршрутизации роутер ведёт сам (два WAN, VPN)",
             "address": "ip addr add|del ADDR dev IFACE",
             "route": "ip route add|del NET [via GW] [dev IFACE] [metric N]"}
    raise CliError(f"ip {obj} {verb or ''}: так не умею. {hints.get(obj, '')}".strip())


def _kv(rest: list[str], first_positional: bool = True) -> tuple[str | None, dict]:
    """ip route add NET via GW dev X metric N  ->  (NET, {via, dev, metric})."""
    pos, named, i = None, {}, 0
    keys = {"via", "dev", "metric", "proto", "table", "src", "label", "broadcast", "brd", "scope", "onlink",
            "preference", "pref"}
    while i < len(rest):
        w = rest[i]
        if w in keys:
            if i + 1 >= len(rest):
                raise CliError(f"после {w} нужно значение")
            named[w] = rest[i + 1]
            i += 2
        elif w == "to" and i + 1 < len(rest):
            pos = rest[i + 1]
            i += 2
        elif pos is None and first_positional:
            pos = w
            i += 1
        else:
            raise CliError(f"непонятный параметр: {w}")
    return pos, named


def _addr_add(ctx, rest):
    addr, kv = _kv(rest)
    if not addr or "dev" not in kv:
        raise CliError("ip addr add 10.10.0.1/24 dev br-lan")
    if "/" not in addr:
        raise CliError("укажите маску: 10.10.0.1/24")
    ctx.api.post("/api/ip/addresses", {"address": addr, "interface": kv["dev"], "comment": "ip addr add"})
    ctx.out(f"{addr} dev {kv['dev']} — добавлен в конфигурацию (как /ip address add)")


def _addr_del(ctx, rest):
    addr, kv = _kv(rest)
    if not addr:
        raise CliError("ip addr del 10.10.0.1/24 dev br-lan")
    want = addr if "/" in addr else None
    items = ctx.api.get("/api/ip/addresses")
    found = [a for a in items if (a["address"] == want if want else a["address"].split("/")[0] == addr)
             and ("dev" not in kv or a["interface"] == kv["dev"])]
    if not found:
        raise CliError(f"адреса {addr} нет")
    own = [a for a in found if a.get("id") is not None]
    if not own:
        raise CliError(f"{addr} задан не командой ip/RouterOS, а настройкой сегмента, WAN или VPN — "
                       "меняйте там: nmcli c mod lan1 ipv4.addresses …, nmcli c mod wan …")
    for a in own:
        ctx.api.delete(f"/api/ip/addresses/{a['id']}")
    ctx.out(f"{addr} — удалён из конфигурации")


def _dst(net: str) -> str:
    if net == "default":
        return "0.0.0.0/0"
    try:
        return str(ipaddress.ip_network(net, strict=False))
    except ValueError:
        raise CliError(f"неверная сеть: {net}")


def _route_add(ctx, rest):
    net, kv = _kv(rest)
    if not net or not (kv.get("via") or kv.get("dev")):
        raise CliError("ip route add 192.168.20.0/24 via 172.16.0.2   (или dev gre1)")
    body = {"dst_address": _dst(net), "gateway": kv.get("via") or kv["dev"], "comment": "ip route add"}
    if "metric" in kv:
        try:
            body["distance"] = max(1, min(255, int(kv["metric"])))
        except ValueError:
            raise CliError("metric — число")
    ctx.api.post("/api/ip/routes", body)
    ctx.out(f"{body['dst_address']} via {body['gateway']} — добавлен в конфигурацию (как /ip route add)")


def _route_del(ctx, rest):
    net, kv = _kv(rest)
    if not net:
        raise CliError("ip route del 192.168.20.0/24 [via 172.16.0.2]")
    dst = _dst(net)
    routes = [r for r in ctx.api.get("/api/ip/routes") if r["dst_address"] == dst
              and (not kv.get("via") or r["gateway"] == kv["via"]) and (not kv.get("dev") or r["gateway"] == kv["dev"]
                                                                       or r.get("interface") == kv["dev"])]
    own = [r for r in routes if r.get("id") is not None]
    if not own:
        raise CliError(f"маршрута {dst} нет в конфигурации" + (" — он динамический (WAN, VPN, OSPF, GRE)" if routes else ""))
    for r in own:
        ctx.api.delete(f"/api/ip/routes/{r['id']}")
    ctx.out(f"{dst} — удалён из конфигурации")


# --- bridge, ss, ping, traceroute ---------------------------------------------------------------------
def bridge_cmd(ctx, args):
    rest = [a for a in args if not a.startswith("-")]
    if not rest or rest[0] not in ("link", "fdb", "vlan", "mdb") or (len(rest) > 1 and rest[1] not in READ_VERBS):
        raise CliError("bridge: только просмотр — bridge link | bridge fdb | bridge vlan")
    _print(ctx, _run(["bridge", *_safe(args)]))


def ss_cmd(ctx, args):
    if any(a.startswith("-") and not re.fullmatch(r"-[tulnpaxwse46HOr]+", a) for a in args):
        raise CliError("ss: можно ключи -t -u -l -n -p -a -s -4 -6 и фильтры")
    _print(ctx, _run(["ss", *_safe(args)]))


def _target(ctx, args: list[str], allowed: dict[str, bool]) -> tuple[list[str], str]:
    """Разобрать ключи (allowed: ключ -> нужен ли аргумент) и адрес; имя — через DNS роутера."""
    from app.services import tools
    out, host, i = [], None, 0
    while i < len(args):
        a = args[i]
        if a in allowed:
            if allowed[a]:
                if i + 1 >= len(args):
                    raise CliError(f"после {a} нужно значение")
                out += [a, _safe([args[i + 1]])[0]]
                i += 2
                continue
            out.append(a)
        elif a.startswith("-"):
            raise CliError(f"ключ {a} не поддерживается (можно: {' '.join(allowed)})")
        elif host is None:
            host = a
        else:
            raise CliError(f"лишний аргумент: {a}")
        i += 1
    if not host:
        raise CliError("укажите адрес")
    try:
        ip, via = tools.resolve_sync(tools.check_host(host), 6 if "-6" in out else None)
    except tools.ToolError as e:
        raise CliError(str(e))
    if ip != host:
        ctx.out(f"{host} -> {ip} ({via})")
    return out, ip


def ping(ctx, args):
    opts, ip = _target(ctx, args, {"-c": True, "-I": True, "-i": True, "-W": True, "-s": True, "-t": True,
                                   "-4": False, "-6": False, "-n": False, "-q": False})
    if "-c" not in opts:
        opts += ["-c", "4"]                           # без -c ping не остановится: как в RouterOS — 4 пакета
    if "-i" in opts and float(opts[opts.index("-i") + 1]) < 0.2:
        raise CliError("-i: не меньше 0.2 с")
    _run_live(ctx, ["ping", *opts, ip])


def traceroute(ctx, args):
    opts, ip = _target(ctx, args, {"-n": False, "-I": False, "-T": False, "-U": False, "-m": True, "-i": True,
                                   "-w": True, "-q": True, "-4": False, "-6": False})
    _run_live(ctx, ["traceroute", *opts, ip])


# --- nmcli -------------------------------------------------------------------------------------------------
VPN_KINDS = ("wireguard", "amneziawg", "l2tp")


def _connections(ctx) -> list[dict]:
    """«Соединения» роутера в терминах NetworkManager."""
    out = []
    w = ctx.api.get("/api/wan")
    out.append({"name": "wan", "type": "ethernet", "device": w.get("interface"),
                "state": "activated" if w["config"].get("mode") != "none" or w.get("addresses") else "unmanaged",
                "kind": "wan", "data": w})
    if w.get("multi"):
        w2 = ctx.api.get("/api/wan/wan2")
        out.append({"name": "wan2", "type": "ethernet", "device": w2.get("interface"),
                    "state": "activated" if w2["config"].get("enabled") else "deactivated", "kind": "wan2", "data": w2})
    for s in ctx.api.get("/api/lan/segments"):
        c = s["config"]
        out.append({"name": c["id"], "type": "bridge", "device": s["bridge"],
                    "state": "activated" if c["enabled"] else "deactivated", "kind": "lan", "data": s,
                    "alias": c.get("name")})
    on = ctx.api.get("/api/vpn").get("enabled")
    for k in VPN_KINDS:
        out.append({"name": k, "type": "vpn" if k == "l2tp" else "wireguard", "device": None,
                    "state": "activated" if on == k else "deactivated", "kind": "vpn"})
    try:
        g = ctx.api.get("/api/gre")
        st = {t["name"]: t for t in g["tunnels"]}
        for t in g["config"]["tunnels"]:
            out.append({"name": t["name"], "type": "ip-tunnel", "device": t["name"] if st.get(t["name"], {}).get("exists") else None,
                        "state": "activated" if t["enabled"] else "deactivated", "kind": "gre", "data": t})
    except CliError:
        pass
    return out


def _find(ctx, name: str) -> dict:
    for c in _connections(ctx):
        if name in (c["name"], c.get("alias"), c.get("device")):
            return c
    raise CliError(f"Error: unknown connection '{name}'. Список: nmcli c")


def nmcli(ctx, args):
    args = [a for a in args if a not in ("-p", "--pretty", "-t", "--terse")]
    obj = args[0] if args else "general"
    rest = args[1:]
    if "general".startswith(obj) and obj:
        return _nm_general(ctx)
    if "device".startswith(obj):
        if rest and rest[0] not in ("status", "s", "show"):
            raise CliError("nmcli device: только просмотр (status). Порты — nmcli c mod / LAN в вебе")
        return _nm_devices(ctx)
    if "connection".startswith(obj):
        verb = rest[0] if rest else "show"
        if "show".startswith(verb):
            return _nm_show(ctx, rest[1:])
        if "modify".startswith(verb) or verb == "mod":
            return _nm_modify(ctx, rest[1:])
        if verb in ("up", "down"):
            if len(rest) < 2:
                raise CliError(f"nmcli c {verb} ИМЯ")
            return _nm_updown(ctx, rest[1], verb == "up")
        raise CliError("nmcli connection: show | modify | up | down (add/delete — сегменты LAN в вебе или /lan)")
    raise CliError("nmcli: general | device | connection")


def _nm_general(ctx):
    w = ctx.api.get("/api/wan")
    ok = bool(w.get("gateway"))
    _table(ctx, ["STATE", "CONNECTIVITY", "WAN", "GATEWAY"],
           [["connected" if ok else "disconnected", "full" if ok else "none", w.get("interface"), w.get("gateway")]])


def _nm_devices(ctx):
    conns = {c["device"]: c for c in _connections(ctx) if c["device"]}
    rows = []
    for i in ctx.api.get("/api/interfaces"):
        name = i.get("name")
        if not name or name == "lo" or (name.startswith(("veth", "docker", "br-")) and not name.startswith("br-lan")):
            continue
        c = conns.get(name)
        up = i.get("running") or i.get("state") == "up"
        kind = ("bridge" if name.startswith("br-lan") else "wireguard" if name.startswith(("wg", "awg"))
                else "ip-tunnel" if name.startswith("gre") else "ppp" if name.startswith("ppp") else "ethernet")
        rows.append([name, kind,
                     ("connected" if up else "unavailable") if c else ("connected (externally)" if up else "unmanaged"),
                     c["name"] if c else None])
    _table(ctx, ["DEVICE", "TYPE", "STATE", "CONNECTION"], rows)


def _nm_show(ctx, rest):
    rest = [a for a in rest if a not in ("--active", "-a", "id")]
    conns = _connections(ctx)
    if not rest:
        _table(ctx, ["NAME", "TYPE", "DEVICE", "STATE"],
               [[c["name"], c["type"], c["device"], c["state"]] for c in conns])
        return
    c = _find(ctx, rest[0])
    props = [("connection.id", c["name"]), ("connection.type", c["type"]),
             ("connection.interface-name", c["device"]), ("GENERAL.STATE", c["state"])]
    if c["kind"] in ("wan", "wan2"):
        cfg, d = c["data"]["config"], c["data"]
        method = {"dhcp": "auto", "static": "manual", "none": "disabled"}.get(cfg.get("mode"), cfg.get("mode"))
        props += [("ipv4.method", method), ("ipv4.addresses", cfg.get("address")), ("ipv4.gateway", cfg.get("gateway")),
                  ("ipv4.dns", ",".join(cfg.get("dns") or [])), ("IP4.ADDRESS", ", ".join(d.get("addresses") or [])),
                  ("IP4.GATEWAY", d.get("gateway")), ("IP4.DNS", ", ".join(d.get("dns") or []))]
    elif c["kind"] == "lan":
        cfg = c["data"]["config"]
        props += [("connection.autoconnect", "yes" if cfg["enabled"] else "no"),
                  ("ipv4.method", "shared" if cfg.get("dhcp_enabled") else "manual"),
                  ("ipv4.addresses", cfg["address"]), ("ipv4.dns-search", cfg.get("domain")),
                  ("bridge.ports", ", ".join(c["data"].get("ports") or [])), ("vlan.id", cfg.get("vlan_id")),
                  ("comment", cfg.get("name"))]
    elif c["kind"] == "gre":
        t = c["data"]
        props += [("ip-tunnel.mode", "gre"), ("ip-tunnel.local", t.get("local")), ("ip-tunnel.remote", t["remote"]),
                  ("ip-tunnel.parent", t.get("underlay")), ("ip-tunnel.mtu", t.get("mtu")),
                  ("ipv4.addresses", t["address"]), ("ipv4.routes", ", ".join(t.get("routes") or []))]
    for k, v in props:
        ctx.out(f"{k + ':':<30}{'--' if v in (None, '') else v}")


def _nm_modify(ctx, rest):
    if len(rest) < 3 or len(rest[1:]) % 2:
        raise CliError("nmcli c mod ИМЯ свойство значение [свойство значение …]")
    c = _find(ctx, rest[0])
    pairs = list(zip(rest[1::2], rest[2::2]))
    if c["kind"] in ("wan", "wan2"):
        cfg = dict(c["data"]["config"])
        for k, v in pairs:
            k = k.lstrip("+")
            if k == "ipv4.method":
                m = {"auto": "dhcp", "manual": "static", "disabled": "none"}.get(v)
                if not m:
                    raise CliError("ipv4.method: auto | manual | disabled")
                cfg["mode"] = m
            elif k in ("ipv4.addresses", "ipv4.address"):
                cfg["address"] = v.split(",")[0].strip() or None
            elif k == "ipv4.gateway":
                cfg["gateway"] = v or None
            elif k == "ipv4.dns":
                cfg["dns"] = [x for x in re.split(r"[,\s]+", v) if x]
            else:
                raise CliError(f"{k}: для WAN можно ipv4.method, ipv4.addresses, ipv4.gateway, ipv4.dns")
        ctx.api.put("/api/wan" if c["kind"] == "wan" else "/api/wan/wan2", cfg)
    elif c["kind"] == "lan":
        cfg = dict(c["data"]["config"])
        for k, v in pairs:
            if k in ("ipv4.addresses", "ipv4.address"):
                cfg["address"] = v.split(",")[0].strip()
            elif k == "ipv4.method":
                if v not in ("shared", "manual"):
                    raise CliError("ipv4.method для сегмента: shared (раздавать адреса по DHCP) | manual (без DHCP)")
                cfg["dhcp_enabled"] = v == "shared"
            elif k == "connection.autoconnect":
                cfg["enabled"] = v in ("yes", "true", "1")
            elif k == "ipv4.dns-search":
                cfg["domain"] = v or None
            else:
                raise CliError(f"{k}: для сегмента можно ipv4.addresses, ipv4.method, ipv4.dns-search, connection.autoconnect")
        path = "/api/lan" if cfg["id"] == "lan1" else f"/api/lan/segments/{cfg['id']}"
        ctx.api.put(path, cfg)
    elif c["kind"] == "gre":
        g = ctx.api.get("/api/gre")["config"]["tunnels"]
        t = next(x for x in g if x["name"] == c["name"])
        for k, v in pairs:
            key = {"ip-tunnel.remote": "remote", "ip-tunnel.local": "local", "ip-tunnel.parent": "underlay",
                   "ip-tunnel.mtu": "mtu", "ipv4.addresses": "address", "ipv4.routes": "routes"}.get(k)
            if not key:
                raise CliError(f"{k}: для GRE можно ip-tunnel.remote|local|parent|mtu, ipv4.addresses, ipv4.routes")
            t[key] = int(v) if key == "mtu" else [x for x in re.split(r"[,\s]+", v) if x] if key == "routes" else (v or None)
        ctx.api.put("/api/gre", {"tunnels": g})
    else:
        raise CliError("VPN настраивается в вебе (VPN → импорт конфига) или /interface wireguard; "
                       "здесь — nmcli c up|down")
    ctx.out(f"Connection '{c['name']}' successfully updated.")


def _nm_updown(ctx, name: str, up: bool):
    c = _find(ctx, name)
    if c["kind"] == "lan":
        cfg = {**c["data"]["config"], "enabled": up}
        ctx.api.put("/api/lan" if cfg["id"] == "lan1" else f"/api/lan/segments/{cfg['id']}", cfg)
    elif c["kind"] == "vpn":
        path = "/api/vpn/l2tp" if c["name"] == "l2tp" else f"/api/vpn/{c['name']}"
        cfg = {**ctx.api.get(path)["config"], "enabled": up}
        ctx.api.put(path, cfg)
    elif c["kind"] == "gre":
        g = ctx.api.get("/api/gre")["config"]["tunnels"]
        ctx.api.put("/api/gre", {"tunnels": [{**t, "enabled": up} if t["name"] == c["name"] else t for t in g]})
    elif c["kind"] == "wan2":
        cfg = {**c["data"]["config"], "enabled": up}
        ctx.api.put("/api/wan/wan2", cfg)
    else:
        raise CliError("основной WAN не выключается — иначе пропадёт доступ к роутеру. "
                       "Режим: nmcli c mod wan ipv4.method disabled")
    ctx.out(f"Connection '{c['name']}' successfully {'activated' if up else 'deactivated'}.")
