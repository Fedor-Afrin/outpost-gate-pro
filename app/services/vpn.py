"""
VPN-клиент: WireGuard, AmneziaWG или L2TP/IPsec. Одновременно работает один туннель:
включение одного выключает остальные.

  wireguard  — wg0, модуль ядра хоста, утилита wg
  amneziawg  — awg0, userspace amneziawg-go (модуль ядра не нужен), утилита awg
  l2tp       — l2tp0: strongSwan (IPsec, PSK) + xl2tpd + pppd (логин/пароль)

Маршрутизация одинакова для всех:
  full  — 0.0.0.0/1 и 128.0.0.0/1 через туннель (перекрывают маршрут по умолчанию,
          не удаляя его); до самого сервера — маршрут /32 через шлюз WAN.
  split — через туннель только сети компании, интернет — напрямую.
У WireGuard/AmneziaWG маршруты ставятся сразу, у L2TP — когда PPP поднялся (ppp-hook).

Что роутер сделал, записано в data/vpn.json — так выключение убирает ровно своё.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from app.core.config import settings
from app.core.process import ManagedProcess
from app.core.store import store
from app.models.l2tp import L2tpConfig, L2tpStatus
from app.models.wireguard import WgConfig, WgStatus
from app.services import firewall, netlink, wan

KINDS = ("wireguard", "amneziawg", "l2tp")
IFACES = {"wireguard": "wg0", "amneziawg": "awg0", "l2tp": "l2tp0"}
TOOLS = {"wireguard": "wg", "amneziawg": "awg"}
ROUTE_METRIC = 1
FULL_ROUTES = ["0.0.0.0/1", "128.0.0.0/1"]
HANDSHAKE_OK = 180   # секунд: WireGuard обновляет handshake каждые 2 минуты
APP_HOME = Path(__file__).resolve().parents[2]

_lock = threading.RLock()
_awg = ManagedProcess("amneziawg-go")
_charon = ManagedProcess("charon (IPsec)")
_xl2tpd = ManagedProcess("xl2tpd")


class VpnError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --- состояние и конфиг ---------------------------------------------------------------
def _data(name: str) -> Path:
    return Path(settings.data_dir) / name


def load_state() -> dict:
    try:
        return json.loads(_data("vpn.json").read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    path = _data("vpn.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".vpn.")
    with os.fdopen(fd, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, path)


def _secret_file(name: str, text: str) -> Path:
    path = _data(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, 0o600)                # в файле ключи и пароли
    return path


def get_config(kind: str = "wireguard") -> WgConfig | L2tpConfig:
    section = (store.load().get("vpn") or {}).get(kind)
    return L2tpConfig.from_yaml(section) if kind == "l2tp" else WgConfig.from_yaml(section)


def enabled_kind() -> str | None:
    vpn = store.load().get("vpn") or {}
    return next((k for k in KINDS if (vpn.get(k) or {}).get("enabled")), None)


# --- для других модулей ------------------------------------------------------------------
def firewall_rules() -> firewall.VpnRules | None:
    """Правила VPN для фаервола. Kill switch действует, даже если туннель не поднялся."""
    kind = enabled_kind()
    if not kind:
        return None
    cfg = get_config(kind)
    st = load_state()
    return firewall.VpnRules(
        iface=IFACES[kind],
        nat=cfg.nat,
        killswitch=cfg.killswitch and cfg.mode == "full",
        inbound=not cfg.nat,
        ipsec_server=st.get("endpoint_ip") if kind == "l2tp" and st.get("kind") == "l2tp" else None,
    )


def dns_override() -> list[str]:
    """DNS туннеля важнее DNS провайдера, когда весь трафик идёт в туннель."""
    st = load_state()
    return st.get("dns", []) if st.get("active") and st.get("mode") == "full" else []


def route_networks(cfg) -> list[str]:
    if cfg.mode == "full":
        return FULL_ROUTES
    return cfg.split_networks() if isinstance(cfg, WgConfig) else cfg.networks


# --- утилиты wg / awg / swanctl ------------------------------------------------------------
def _run(cmd: list[str], stdin: str | None = None, what: str | None = None) -> str:
    try:
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=15)
    except FileNotFoundError as e:
        raise VpnError(500, f"нет программы {cmd[0]} — пересоберите образ") from e
    if r.returncode != 0:
        raise VpnError(400, f"{what or cmd[0]}: {(r.stderr or r.stdout).strip()}")
    return r.stdout.strip()


def _tool(kind: str, *args: str, stdin: str | None = None) -> str:
    return _run([TOOLS[kind], *args], stdin=stdin, what=f"{TOOLS[kind]} {args[0]}")


def genkey() -> tuple[str, str]:
    private = _tool("wireguard", "genkey")
    return private, _tool("wireguard", "pubkey", stdin=private + "\n")


OSPF_MULTICAST = ["224.0.0.5/32", "224.0.0.6/32"]   # AllSPFRouters / AllDRouters


def allowed_ips(cfg: WgConfig, iface: str | None = None) -> list[str]:
    """AllowedIPs пира. WireGuard пропускает только адреса из этого списка, поэтому для
    OSPF поверх туннеля в режиме split добавляются его multicast-адреса (hello соседям)."""
    if cfg.mode == "full":
        return ["0.0.0.0/0"]
    nets = list(cfg.split_networks())
    if iface:
        try:
            from app.services import routing   # здесь, чтобы не было циклического импорта
            if iface in routing.ospf_interfaces():
                nets += [m for m in OSPF_MULTICAST if m not in nets]
        except Exception as e:  # маршрутизация не должна мешать туннелю
            print(f"[vpn] WARNING: OSPF multicast: {e}")
        try:                                  # GRE поверх этого туннеля: вторые роутеры должны быть в AllowedIPs
            from app.services import gre
            for t in gre.get_config().tunnels:
                if t.enabled and t.underlay == iface and not any(
                        ipaddress.ip_address(t.remote) in ipaddress.ip_network(n, strict=False) for n in nets):
                    nets.append(f"{t.remote}/32")
        except Exception as e:  # noqa: BLE001
            print(f"[vpn] WARNING: GRE: {e}")
    return nets


def sync_allowed_ips() -> None:
    """Обновить AllowedIPs работающего туннеля без его перезапуска (после смены OSPF)."""
    st = load_state()
    kind = st.get("kind")
    if kind not in ("wireguard", "amneziawg") or not st.get("active"):
        return
    cfg = get_config(kind)
    _tool(kind, "set", st["iface"], "peer", cfg.peer_public_key,
          "allowed-ips", ",".join(allowed_ips(cfg, st["iface"])))


def wg_conf(cfg: WgConfig, endpoint_ip: str, obfuscation: bool = False, iface: str | None = None) -> str:
    """Конфиг для `wg/awg setconf` (без Address/DNS/MTU — их ставит роутер)."""
    _, port = cfg.endpoint_host_port()
    allowed = ", ".join(allowed_ips(cfg, iface))
    lines = ["[Interface]", f"PrivateKey = {cfg.private_key}"]
    if obfuscation:
        lines += [f"{k} = {v}" for k, v in cfg.obfuscation.items()]
    lines += ["", "[Peer]", f"PublicKey = {cfg.peer_public_key}"]
    if cfg.preshared_key:
        lines.append(f"PresharedKey = {cfg.preshared_key}")
    lines += [f"Endpoint = {endpoint_ip}:{port}", f"AllowedIPs = {allowed}"]
    if cfg.keepalive:
        lines.append(f"PersistentKeepalive = {cfg.keepalive}")
    return "\n".join(lines) + "\n"


def resolve_host(host: str) -> str:
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
    except socket.gaierror as e:
        raise VpnError(400, f"не удалось определить адрес сервера {host}: {e}") from e


# --- маршрут до VPN-сервера ---------------------------------------------------------------
def refresh_endpoint_route() -> None:
    """Маршрут /32 до сервера через текущий шлюз WAN. Вызывается и после новой аренды DHCP."""
    with _lock:
        st = load_state()
        if not st.get("endpoint_ip"):
            return
        gw = wan.current_gateway()
        new = [f"{st['endpoint_ip']}/32", gw] if gw else None
        old = st.get("endpoint_route")
        if old and old != new:
            try:
                netlink.route_del(old[0], old[1], None, ROUTE_METRIC)
            except netlink.NetlinkOpError as e:
                print(f"[vpn] WARNING: {e}")
        if new:
            try:
                netlink.route_add(new[0], new[1], None, ROUTE_METRIC)
            except netlink.NetlinkOpError as e:
                print(f"[vpn] WARNING: маршрут до сервера: {e}")
                new = None
        st["endpoint_route"] = new
        save_state(st)


def _check_networks(networks: list[str]) -> None:
    from app.services import lan
    for seg in lan.segments():
        if not seg.enabled:
            continue
        lan_net = seg.network
        for n in networks:
            if ipaddress.ip_network(n).overlaps(lan_net):
                raise VpnError(400, f"сеть {n} пересекается с LAN {lan_net}: у каждого роутера "
                                    f"должна быть своя подсеть LAN")


# --- WireGuard / AmneziaWG ---------------------------------------------------------------------
def _start_amneziawg(iface: str) -> None:
    try:
        _awg.start(["amneziawg-go", "-f", iface], env={**os.environ, "LOG_LEVEL": "error"})
    except FileNotFoundError as e:
        raise VpnError(500, "нет amneziawg-go — пересоберите образ") from e
    for _ in range(50):                  # интерфейс появляется не сразу
        if iface in netlink.link_names():
            return
        if not _awg.running():
            break
        time.sleep(0.1)
    raise VpnError(500, f"amneziawg-go не создал {iface} (нужен /dev/net/tun) — см. docker logs")


def _setup_wg(kind: str, cfg: WgConfig) -> None:
    iface = IFACES[kind]
    if not cfg.private_key:
        raise VpnError(400, "нет PrivateKey: импортируйте конфиг или сгенерируйте ключи")
    _check_networks(cfg.split_networks() + [str(ipaddress.ip_interface(a).network) for a in cfg.addresses])
    host, _ = cfg.endpoint_host_port()
    endpoint_ip = resolve_host(host)

    if kind == "amneziawg":
        _start_amneziawg(iface)
    else:
        netlink.wireguard_create(iface)
    state: dict = {"kind": kind, "iface": iface, "active": False, "mode": cfg.mode,
                   "endpoint_ip": endpoint_ip, "dns": cfg.dns}
    save_state(state)

    conf = _secret_file(f"{iface}.conf", wg_conf(cfg, endpoint_ip, obfuscation=kind == "amneziawg", iface=iface))
    _tool(kind, "setconf", iface, str(conf))
    for a in cfg.addresses:
        netlink.addr_add(iface, a)
    netlink.link_set_mtu(iface, cfg.mtu)
    netlink.link_set_up(iface)
    state["active"] = True
    save_state(state)

    refresh_endpoint_route()             # сначала дорога до сервера, потом весь трафик в туннель
    for dst in route_networks(cfg):
        netlink.route_add(dst, None, iface, ROUTE_METRIC)
    if cfg.mode != "full":
        try:
            sync_allowed_ips()           # адрес туннеля уже есть: OSPF по сетям находит интерфейс
        except VpnError as e:
            print(f"[vpn] WARNING: {e}")
    print(f"[vpn] {kind} {iface} -> {cfg.endpoint} ({endpoint_ip}), режим {cfg.mode}")


# --- L2TP/IPsec ----------------------------------------------------------------------------------
def swanctl_conf(cfg: L2tpConfig, server_ip: str) -> str:
    """IPsec IKEv1, PSK, транспортный режим только для L2TP (udp/1701) — как у MikroTik и Windows."""
    return f"""# сгенерировано OutpostGate Pro
connections {{
    l2tp {{
        version = 1
        remote_addrs = {server_ip}
        proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024
        dpd_delay = 30s
        local {{
            auth = psk
        }}
        remote {{
            auth = psk
        }}
        children {{
            l2tp {{
                mode = transport
                local_ts = dynamic[udp/1701]
                remote_ts = dynamic[udp/1701]
                esp_proposals = aes256-sha256,aes256-sha1,aes128-sha1,3des-sha1
                start_action = start
                dpd_action = restart
                close_action = start
            }}
        }}
    }}
}}

secrets {{
    ike-l2tp {{
        secret = "{cfg.psk}"
    }}
}}
"""


def xl2tpd_conf(server_ip: str, options_file: str) -> str:
    return f"""; сгенерировано OutpostGate Pro
[global]
port = 1701

[lac company]
lns = {server_ip}
pppoptfile = {options_file}
length bit = yes
autodial = yes
redial = yes
redial timeout = 15
max redials = 1000000
"""


def ppp_options(cfg: L2tpConfig) -> str:
    scripts = APP_HOME / "app" / "scripts"
    return f"""# сгенерировано OutpostGate Pro
ifname {IFACES['l2tp']}
name "{cfg.username}"
password "{cfg.password}"
noauth
refuse-eap
noccp
nodefaultroute
usepeerdns
ipcp-accept-local
ipcp-accept-remote
mtu {cfg.mtu}
mru {cfg.mtu}
lcp-echo-interval 30
lcp-echo-failure 4
ip-up-script {scripts / 'ppp-up.sh'}
ip-down-script {scripts / 'ppp-down.sh'}
"""


def _charon_binary() -> str:
    for p in ("/usr/lib/ipsec/charon", "/usr/libexec/ipsec/charon", "/usr/lib/strongswan/charon"):
        if os.path.exists(p):
            return p
    return shutil.which("charon") or "charon"


def _setup_l2tp(cfg: L2tpConfig) -> None:
    if not cfg.psk or not cfg.password:
        raise VpnError(400, "нужны PSK и пароль")
    _check_networks(cfg.networks)
    server_ip = resolve_host(cfg.server)
    save_state({"kind": "l2tp", "iface": IFACES["l2tp"], "active": False, "mode": cfg.mode,
                "endpoint_ip": server_ip, "dns": []})
    refresh_endpoint_route()

    # 1) IPsec: charon + конфиг через swanctl
    swan = _secret_file("swanctl.conf", swanctl_conf(cfg, server_ip))
    try:
        _charon.start([_charon_binary()])
    except FileNotFoundError as e:
        raise VpnError(500, "нет strongSwan (charon) — пересоберите образ") from e
    for _ in range(100):                 # ждём сокет управления vici
        if os.path.exists("/var/run/charon.vici"):
            break
        time.sleep(0.1)
    _run(["swanctl", "--load-all", "--file", str(swan)], what="swanctl")

    # 2) L2TP + PPP: xl2tpd сам дозванивается и переподключается
    opts = _secret_file("options.l2tp", ppp_options(cfg))
    conf = _secret_file("xl2tpd.conf", xl2tpd_conf(server_ip, str(opts)))
    os.makedirs("/var/run/xl2tpd", exist_ok=True)
    try:
        _xl2tpd.start(["xl2tpd", "-D", "-c", str(conf), "-p", "/var/run/xl2tpd.pid",
                       "-C", "/var/run/xl2tpd/l2tp-control"])
    except FileNotFoundError as e:
        raise VpnError(500, "нет xl2tpd — пересоберите образ") from e
    print(f"[vpn] L2TP/IPsec -> {cfg.server} ({server_ip}), режим {cfg.mode}; маршруты — после подъёма PPP")


def ppp_event(event: str, env) -> None:
    """Вызывается из ppp-up.sh / ppp-down.sh (pppd): PPP поднялся или упал."""
    with _lock:
        st = load_state()
        if st.get("kind") != "l2tp":
            return
        iface = env.get("IFNAME", IFACES["l2tp"])
        if event == "up":
            cfg = get_config("l2tp")
            for dst in route_networks(cfg):
                try:
                    netlink.route_add(dst, None, iface, ROUTE_METRIC)
                except netlink.NetlinkOpError as e:
                    print(f"[vpn] WARNING: {e}")
            st.update(active=True, local_ip=env.get("IPLOCAL"), remote_ip=env.get("IPREMOTE"),
                      dns=[d for d in (env.get("DNS1"), env.get("DNS2")) if d])
            print(f"[vpn] L2TP {iface} поднят: {st['local_ip']} <-> {st['remote_ip']}")
        else:
            st.update(active=False, local_ip=None, remote_ip=None, dns=[])
            print(f"[vpn] L2TP {iface} упал — xl2tpd переподключится")
        save_state(st)
    wan.refresh_upstream_dns()


# --- применение -------------------------------------------------------------------------------------
def teardown(state: dict) -> None:
    if state.get("endpoint_route"):
        try:
            netlink.route_del(*state["endpoint_route"], None, ROUTE_METRIC)
        except netlink.NetlinkOpError as e:
            print(f"[vpn] WARNING: {e}")
    _xl2tpd.stop()
    if _charon.running():
        _charon.stop()
    _awg.stop()
    if state.get("iface"):               # только свой интерфейс; с ним уходят его адреса и маршруты
        netlink.link_delete(state["iface"])
    save_state({})


def apply_current() -> None:
    """Привести систему к конфигу: поднять включённый туннель (или ни одного)."""
    with _lock:
        teardown(load_state())
        try:
            kind = enabled_kind()
            if kind == "l2tp":
                _setup_l2tp(get_config("l2tp"))
            elif kind:
                _setup_wg(kind, get_config(kind))
        finally:                         # фаервол и DNS — в любом случае (kill switch!)
            _refresh_neighbours()


def _refresh_neighbours() -> None:
    try:
        firewall.refresh()
    except firewall.FirewallError as e:
        print(f"[vpn] ERROR: фаервол: {e}")
    wan.refresh_upstream_dns()


def _keep_secrets(kind: str, new, old):
    """Пустые секреты в форме = оставить прежние (веб их никогда не показывает)."""
    names = ("psk", "password") if kind == "l2tp" else ("private_key",)
    upd = {n: getattr(old, n) for n in names if not getattr(new, n)}
    return new.model_copy(update=upd) if upd else new


def update(kind: str, new) -> WgStatus | L2tpStatus:
    if kind not in KINDS:
        raise VpnError(404, f"нет такого VPN: {kind}")
    new = _keep_secrets(kind, new, get_config(kind))
    snapshot = json.loads(json.dumps(store.load().get("vpn") or {}))
    with store.transaction() as data:
        vpn = data.get("vpn") or {}
        vpn[kind] = new.to_yaml()
        if new.enabled:                  # одновременно работает один туннель
            for other in KINDS:
                if other != kind and (vpn.get(other) or {}).get("enabled"):
                    vpn[other]["enabled"] = False
        data["vpn"] = vpn
    try:
        apply_current()
    except (netlink.NetlinkOpError, VpnError) as e:
        with store.transaction() as data:
            data["vpn"] = snapshot
        try:
            apply_current()
        except Exception as rollback_err:
            print(f"[vpn] ERROR: откат не удался: {rollback_err}")
        if isinstance(e, VpnError):
            raise
        raise VpnError(400, str(e)) from e
    return status(kind)


def on_wan_changed() -> None:
    refresh_endpoint_route()


def apply_startup() -> None:
    try:
        apply_current()
    except (netlink.NetlinkOpError, VpnError) as e:
        print(f"[vpn] ERROR: {e}")


def stop_all() -> None:
    _xl2tpd.stop()
    if _charon.running():
        _charon.stop()
    _awg.stop()


# --- статус --------------------------------------------------------------------------------------------
def _iface_bytes(iface: str) -> tuple[int, int]:
    base = Path("/sys/class/net") / iface / "statistics"
    try:
        return int((base / "rx_bytes").read_text()), int((base / "tx_bytes").read_text())
    except (OSError, ValueError):
        return 0, 0


def status(kind: str = "wireguard") -> WgStatus | L2tpStatus:
    return _status_l2tp() if kind == "l2tp" else _status_wg(kind)


def _status_wg(kind: str) -> WgStatus:
    cfg = get_config(kind)
    st = load_state()
    iface = IFACES[kind]
    mine = st.get("kind") == kind
    out = WgStatus(
        kind=kind, interface=iface,
        config=cfg.model_copy(update={"private_key": None}),
        private_key_set=bool(cfg.private_key),
        endpoint_ip=st.get("endpoint_ip") if mine else None,
        active=mine and bool(st.get("active")) and iface in netlink.link_names(),
    )
    try:
        if cfg.private_key:
            out.public_key = _tool("wireguard", "pubkey", stdin=cfg.private_key + "\n")
        if out.active:
            lines = _tool(kind, "show", iface, "dump").splitlines()
            if len(lines) > 1:
                peer = lines[1].split("\t")
                handshake = int(peer[4])
                out.latest_handshake = handshake or None
                out.rx_bytes, out.tx_bytes = int(peer[5]), int(peer[6])
                out.connected = bool(handshake) and time.time() - handshake < HANDSHAKE_OK
    except VpnError as e:
        out.error = e.message
    return out


def _status_l2tp() -> L2tpStatus:
    cfg = get_config("l2tp")
    st = load_state()
    mine = st.get("kind") == "l2tp"
    iface = IFACES["l2tp"]
    out = L2tpStatus(
        config=cfg.model_copy(update={"psk": None, "password": None}),
        psk_set=bool(cfg.psk), password_set=bool(cfg.password),
        endpoint_ip=st.get("endpoint_ip") if mine else None,
    )
    if mine:
        out.connected = bool(st.get("active")) and iface in netlink.link_names()
        out.local_ip, out.remote_ip = st.get("local_ip"), st.get("remote_ip")
        out.rx_bytes, out.tx_bytes = _iface_bytes(iface) if out.connected else (0, 0)
        if _charon.running():
            try:
                out.ipsec_up = "ESTABLISHED" in _run(["swanctl", "--list-sas"], what="swanctl")
            except VpnError as e:
                out.error = e.message
        elif cfg.enabled:
            out.error = "IPsec (charon) не запущен — см. docker logs"
    return out
