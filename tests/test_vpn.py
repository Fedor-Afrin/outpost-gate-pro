"""
Тесты VPN → WireGuard без ядра и без утилиты wg: всё системное подменяется.
WAN = eth1 (шлюз 172.18.0.1), LAN включён на br-lan 192.168.1.1/24.
"""
import pytest
import yaml

from app.core.store import ConfigStore
from app.models.wireguard import WgConfig, parse_wg_quick
from app.models.l2tp import L2tpConfig
from app.services import firewall, lan, netlink, vpn, wan

PRIV = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
PUB = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="

CONF = f"""
[Interface]
PrivateKey = {PRIV}
Address = 10.8.0.2/32, fd00::2/128
DNS = 10.8.0.1
MTU = 1380
Jc = 4            # параметры AmneziaWG пока игнорируются

[Peer]
PublicKey = {PUB}
Endpoint = 203.0.113.7:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""


class FakeKernel:
    def __init__(self):
        self.links = {"lo", "eth0", "eth1", "br-lan"}
        self.addrs = set()
        self.routes = [{"dst": "0.0.0.0/0", "gateway": "172.18.0.1", "interface": "eth1", "metric": 0, "proto": 3}]
        self.mtu = {}

    def link_names(self): return set(self.links)
    def link_set_up(self, n): assert n in self.links
    def link_set_mtu(self, n, m): self.mtu[n] = m
    def wireguard_create(self, n): self.links.add(n)
    def link_delete(self, n):
        self.links.discard(n)
        self.addrs = {(i, a) for i, a in self.addrs if i != n}
        self.routes = [r for r in self.routes if r["interface"] != n]
    def kernel_ipv4_routes(self): return [dict(r) for r in self.routes]
    def addr_add(self, n, c): self.addrs.add((n, c))
    def route_add(self, dst, gateway=None, ifname=None, metric=1, proto=4):
        self.routes.append({"dst": dst, "gateway": gateway, "interface": ifname or "eth1",
                            "metric": metric, "proto": proto})
    def route_del(self, dst, gateway=None, ifname=None, metric=1):
        self.routes = [r for r in self.routes if not (r["dst"] == dst and r["gateway"] == gateway)]


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / "router.yaml"
    cfg.write_text(yaml.safe_dump({
        "wan": {"interface": "eth1", "mode": "none"},
        "lan": {"enabled": True, "address": "192.168.1.1/24"},
    }))
    store = ConfigStore(str(cfg), str(tmp_path / "data"))
    (tmp_path / "data").mkdir()
    kernel = FakeKernel()
    for mod in (vpn, lan, wan):
        monkeypatch.setattr(mod, "store", store)
    monkeypatch.setattr(vpn, "_data", lambda name: tmp_path / "data" / name)
    monkeypatch.setattr(lan, "_data", lambda name: tmp_path / "data" / name)
    monkeypatch.setattr(wan, "state_file", lambda: tmp_path / "data" / "wan.json")
    monkeypatch.setattr(wan, "resolv_file", lambda: tmp_path / "data" / "resolv.wan")
    monkeypatch.setattr(wan, "system_nameservers", lambda: ["127.0.0.11"])
    for name in ("link_names", "link_set_up", "link_set_mtu", "wireguard_create", "link_delete",
                 "kernel_ipv4_routes", "addr_add", "route_add", "route_del"):
        monkeypatch.setattr(netlink, name, getattr(kernel, name))
    wg_calls = []
    def fake_tool(kind, *args, stdin=None):
        wg_calls.append((vpn.TOOLS[kind],) + args)
        return PUB if args[0] == "pubkey" else ""
    monkeypatch.setattr(vpn, "_tool", fake_tool)
    def fake_awg_start(iface):
        kernel.links.add(iface)
    monkeypatch.setattr(vpn, "_start_amneziawg", fake_awg_start)
    procs = []
    class FakeProc:
        def __init__(self, name): self.name, self.on = name, False
        def start(self, cmd, env=None): self.on = True; procs.append(cmd[0])
        def stop(self, timeout=5): self.on = False
        def running(self): return self.on
    for name in ("_awg", "_charon", "_xl2tpd"):
        monkeypatch.setattr(vpn, name, FakeProc(name))
    runs = []
    monkeypatch.setattr(vpn, "_run", lambda cmd, stdin=None, what=None: runs.append(cmd) or "")
    monkeypatch.setattr(vpn.os.path, "exists", lambda p: True)
    fw = []
    monkeypatch.setattr(firewall, "refresh", lambda lan_cfg=None: fw.append(vpn.firewall_rules()))
    return store, kernel, wg_calls, fw, procs, runs


def _routes(kernel, iface):
    return sorted(r["dst"] for r in kernel.routes if r["interface"] == iface)


def test_parse_wg_quick():
    c = parse_wg_quick(CONF)
    assert c.private_key == PRIV and c.peer_public_key == PUB
    assert c.addresses == ["10.8.0.2/32"]          # IPv6 пропущен
    assert c.dns == ["10.8.0.1"] and c.mtu == 1380
    assert c.mode == "full" and c.allowed_ips == ["0.0.0.0/0"]
    split = parse_wg_quick(CONF.replace("0.0.0.0/0, ::/0", "10.0.0.0/8, 192.168.10.0/24"))
    assert split.mode == "split" and split.split_networks() == ["10.0.0.0/8", "192.168.10.0/24"]
    with pytest.raises(ValueError):
        parse_wg_quick("[Interface]\nPrivateKey = x")


def test_full_mode(env):
    store, kernel, wg_calls, fw, *_ = env
    cfg = parse_wg_quick(CONF).model_copy(update={"enabled": True})
    st = vpn.update("wireguard", cfg)
    assert ("wg0", "10.8.0.2/32") in kernel.addrs and kernel.mtu["wg0"] == 1380
    assert _routes(kernel, "wg0") == ["0.0.0.0/1", "128.0.0.0/1"]
    ep = [r for r in kernel.routes if r["dst"] == "203.0.113.7/32"]
    assert ep and ep[0]["gateway"] == "172.18.0.1"                  # до сервера — через WAN
    assert ("wg", "setconf", "wg0", "/dev/stdin") in wg_calls
    conf = vpn._data("wg0.conf").read_text()
    assert "AllowedIPs = 0.0.0.0/0" in conf and "Endpoint = 203.0.113.7:51820" in conf
    rules = fw[-1]
    assert rules.killswitch and rules.nat and not rules.inbound
    assert "nameserver 10.8.0.1" in wan.resolv_file().read_text()   # DNS не утекает мимо туннеля
    assert st.public_key == PUB and st.config.private_key is None   # ключ наружу не отдаётся
    assert store.load()["vpn"]["wireguard"]["private-key"] == PRIV


def test_split_site_to_site(env):
    _, kernel, _, fw, *_ = env
    cfg = parse_wg_quick(CONF.replace("0.0.0.0/0, ::/0", "10.0.0.0/8, 192.168.10.0/24"))
    vpn.update("wireguard", cfg.model_copy(update={"enabled": True, "nat": False}))
    assert _routes(kernel, "wg0") == ["10.0.0.0/8", "192.168.10.0/24"]
    rules = fw[-1]
    assert not rules.killswitch and not rules.nat and rules.inbound   # центр видит устройства LAN
    assert "nameserver 10.8.0.1" not in wan.resolv_file().read_text() # DNS туннеля только в full
    assert "AllowedIPs = 10.0.0.0/8, 192.168.10.0/24" in vpn._data("wg0.conf").read_text()


def test_disable_cleans_up(env):
    _, kernel, _, fw, *_ = env
    vpn.update("wireguard", parse_wg_quick(CONF).model_copy(update={"enabled": True}))
    vpn.update("wireguard", vpn.get_config().model_copy(update={"enabled": False, "private_key": None}))
    assert "wg0" not in kernel.links
    assert not [r for r in kernel.routes if r["dst"] == "203.0.113.7/32"]
    assert fw[-1] is None                                           # kill switch снят
    assert vpn.get_config().private_key == PRIV                     # пустой ключ = прежний


def test_lan_overlap_rejected_and_rolled_back(env):
    store, kernel, *_ = env
    bad = parse_wg_quick(CONF.replace("0.0.0.0/0, ::/0", "192.168.1.0/24"))
    with pytest.raises(vpn.VpnError, match="пересекается"):
        vpn.update("wireguard", bad.model_copy(update={"enabled": True}))
    assert "wg0" not in kernel.links
    assert not vpn.get_config().enabled


def test_endpoint_route_follows_wan_gateway(env):
    _, kernel, *_ = env
    vpn.update("wireguard", parse_wg_quick(CONF).model_copy(update={"enabled": True}))
    kernel.routes[0]["gateway"] = "172.18.0.254"                    # новая аренда DHCP
    vpn.refresh_endpoint_route()
    ep = [r for r in kernel.routes if r["dst"] == "203.0.113.7/32"]
    assert len(ep) == 1 and ep[0]["gateway"] == "172.18.0.254"


def test_validation():
    with pytest.raises(ValueError, match="не хватает"):
        WgConfig(enabled=True, addresses=["10.8.0.2/32"])
    with pytest.raises(ValueError, match="ключ"):
        WgConfig(peer_public_key="short")
    with pytest.raises(ValueError, match="Endpoint"):
        WgConfig(endpoint="vpn.example.com")
    with pytest.raises(ValueError, match="split"):
        WgConfig(enabled=True, addresses=["10.8.0.2/32"], peer_public_key=PUB,
                 endpoint="1.2.3.4:51820", mode="split", allowed_ips=["0.0.0.0/0"])


def test_firewall_with_killswitch_has_no_lan_to_wan():
    rs = firewall.ruleset("eth1", "br-lan", True, firewall.VpnRules("wg0", True, True, False))
    assert 'iifname "br-lan" oifname "eth1" accept' not in rs
    assert 'iifname "br-lan" oifname "wg0" accept' in rs and 'oifname "wg0" masquerade' in rs
    assert "maxseg size set rt mtu" in rs


AWG_CONF = CONF.replace("Jc = 4            # параметры AmneziaWG пока игнорируются",
                        "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 68\nH1 = 1234567\nH2 = 2234567\nH3 = 3\nH4 = 4\n"
                        "I1 = <b 0xc200#tag>")


def test_amneziawg(env):
    _, kernel, wg_calls, fw, *_ = env
    cfg = parse_wg_quick(AWG_CONF)
    assert cfg.obfuscation["Jc"] == "4" and cfg.obfuscation["I1"] == "<b 0xc200#tag>"  # # внутри I1 сохранён
    vpn.update("amneziawg", cfg.model_copy(update={"enabled": True}))
    assert "awg0" in kernel.links and _routes(kernel, "awg0") == ["0.0.0.0/1", "128.0.0.0/1"]
    assert ("awg", "setconf", "awg0", "/dev/stdin") in wg_calls
    conf = vpn._data("awg0.conf").read_text()
    assert "Jc = 4" in conf and "H4 = 4" in conf and "I1 = <b 0xc200#tag>" in conf
    assert fw[-1].iface == "awg0"
    assert vpn.get_config("amneziawg").to_yaml()["obfuscation"]["S2"] == "68"


def test_only_one_tunnel(env):
    _, kernel, *_ = env
    vpn.update("wireguard", parse_wg_quick(CONF).model_copy(update={"enabled": True}))
    vpn.update("amneziawg", parse_wg_quick(AWG_CONF).model_copy(update={"enabled": True}))
    assert not vpn.get_config("wireguard").enabled and vpn.enabled_kind() == "amneziawg"
    assert "wg0" not in kernel.links and "awg0" in kernel.links


def _l2tp(**kw):
    base = dict(enabled=True, server="203.0.113.9", psk="s3cret", username="ivan", password="p@ss")
    return L2tpConfig(**{**base, **kw})


def test_l2tp_setup_and_ppp_events(env):
    store, kernel, _, fw, procs, runs = env
    st = vpn.update("l2tp", _l2tp())
    assert procs[-2].endswith("charon") and procs[-1] == "xl2tpd"
    assert ["swanctl", "--load-all", "--file", str(vpn._data("swanctl.conf"))] in runs
    swan = vpn._data("swanctl.conf").read_text()
    assert "remote_addrs = 203.0.113.9" in swan and "mode = transport" in swan and 'secret = "s3cret"' in swan
    assert "lns = 203.0.113.9" in vpn._data("xl2tpd.conf").read_text()
    opts = vpn._data("options.l2tp").read_text()
    assert 'name "ivan"' in opts and "ifname l2tp0" in opts and "ppp-up.sh" in opts
    assert oct(vpn._data("options.l2tp").stat().st_mode)[-3:] == "600"
    ep = [r for r in kernel.routes if r["dst"] == "203.0.113.9/32"]
    assert ep and ep[0]["gateway"] == "172.18.0.1"
    assert fw[-1].ipsec_server == "203.0.113.9" and fw[-1].iface == "l2tp0"
    assert st.config.psk is None and st.psk_set and st.password_set        # секреты наружу не отдаются

    kernel.links.add("l2tp0")                                              # pppd поднял интерфейс
    vpn.ppp_event("up", {"IFNAME": "l2tp0", "IPLOCAL": "10.10.0.5", "IPREMOTE": "10.10.0.1",
                         "DNS1": "10.10.0.1"})
    assert _routes(kernel, "l2tp0") == ["0.0.0.0/1", "128.0.0.0/1"]
    assert "nameserver 10.10.0.1" in wan.resolv_file().read_text()
    s2 = vpn.status("l2tp")
    assert s2.connected and s2.local_ip == "10.10.0.5"

    vpn.ppp_event("down", {"IFNAME": "l2tp0"})
    assert not vpn.status("l2tp").connected
    assert "10.10.0.1" not in wan.resolv_file().read_text()


def test_l2tp_keeps_secrets_and_validates(env):
    vpn.update("l2tp", _l2tp(enabled=False))
    vpn.update("l2tp", _l2tp(psk=None, password=None))                      # пусто = прежние
    cfg = vpn.get_config("l2tp")
    assert cfg.psk == "s3cret" and cfg.password == "p@ss" and cfg.enabled
    with pytest.raises(ValueError, match="кавычки"):
        L2tpConfig(psk='bad"psk')
    with pytest.raises(ValueError, match="split"):
        _l2tp(mode="split")
    assert _l2tp(mode="split", networks=["192.168.10.5/24"]).networks == ["192.168.10.0/24"]


def test_l2tp_firewall_rules_valid():
    rs = firewall.ruleset("eth1", "br-lan", False, firewall.VpnRules("l2tp0", True, True, False, "203.0.113.9"))
    assert "ip saddr 203.0.113.9 ip protocol esp accept" in rs


# --- импорт vpn:// из приложения Amnezia (AmneziaWG 3.1) ---------------------------------------
import base64 as _b64
import json as _json
import zlib as _zlib

_K1 = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
_K2 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
_K3 = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="


def _vpn_link(conf: str, container="amnezia-awg2", **extra) -> str:
    inner = {"config": conf, "port": "49513"}
    j = {"containers": [{"container": "amnezia-openvpn", "openvpn": {}},
                        {"container": container, "awg": {"last_config": _json.dumps(inner), "port": "49513"}}],
         "defaultContainer": container, "dns1": "1.1.1.1", "dns2": "1.0.0.1", "hostName": "203.0.113.5", **extra}
    data = _json.dumps(j).encode()
    raw = len(data).to_bytes(4, "big") + _zlib.compress(data)
    return "vpn://" + _b64.urlsafe_b64encode(raw).decode().rstrip("=")


AWG31 = f"""[Interface]
Address = 10.8.1.2/32
DNS = $PRIMARY_DNS, $SECONDARY_DNS
PrivateKey = {_K1}
Jc = 5
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 =
HeaderProtectionKey = {_K3}
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = {_K2}
PresharedKey = {_K3}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.5:49513
PersistentKeepalive = 25-35
"""


def test_import_amnezia_vpn_link():
    from app.models.wireguard import parse_wg_quick
    link = _vpn_link(AWG31)
    c = parse_wg_quick("  " + link[:40] + "\n" + link[40:] + "\n")      # перенос строки внутри — не мешает
    assert c.addresses == ["10.8.1.2/32"] and c.dns == ["1.1.1.1", "1.0.0.1"]
    assert c.endpoint == "203.0.113.5:49513" and c.private_key == _K1 and c.peer_public_key == _K2
    assert c.keepalive == 25 and c.mode == "full"
    o = c.obfuscation
    assert o["HeaderProtectionKey"] == _K3 and o["RandomTrailers"] == "on" and o["DisableCookies"] == "on"
    assert o["RekeyAfterTime"] == "100-120" and o["S3"] == "12" and o["Jc"] == "5" and "I1" not in o
    # в конфиг для awg setconf уходят и параметры AmneziaWG 3
    from app.services import vpn
    text = vpn.wg_conf(c, "203.0.113.5", obfuscation=True)
    assert "HeaderProtectionKey = " in text and "MaxHandshakeAttempts = 15-20" in text


def test_import_vpn_link_errors():
    from app.models.wireguard import parse_wg_quick
    with pytest.raises(ValueError, match="base64|JSON"):
        parse_wg_quick("vpn://%%%not-base64")
    j = _json.dumps({"containers": [{"container": "amnezia-openvpn"}]}).encode()
    link = "vpn://" + _b64.urlsafe_b64encode(len(j).to_bytes(4, "big") + _zlib.compress(j)).decode()
    with pytest.raises(ValueError, match="amnezia-openvpn"):
        parse_wg_quick(link)


def test_awg3_keys_canonical():
    from app.models.wireguard import WgConfig
    c = WgConfig(obfuscation={"headerprotectionkey": _K3, "randomtrailers": "on", "jc": "4", "s3": "20"})
    assert c.obfuscation == {"HeaderProtectionKey": _K3, "RandomTrailers": "on", "Jc": "4", "S3": "20"}
    with pytest.raises(ValueError, match="неизвестный параметр"):
        WgConfig(obfuscation={"Bogus": "1"})
