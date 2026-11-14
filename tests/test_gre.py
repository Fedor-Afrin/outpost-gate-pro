"""GRE «роутер — роутер»: модель, применение (ip), фаервол, OSPF, экспорт."""
import json

import pytest

from app.models.gre import GreConfig, GreTunnel
from app.models.routing import OspfConfig, OspfInterface, OspfNetwork, RoutingConfig
from app.services import firewall, gre, routing


def tun(**kw):
    base = dict(name="gre1", remote="10.8.1.3", local="10.8.1.2", underlay="awg0", address="172.16.0.1/30",
                routes=["192.168.20.0/24"])
    return GreTunnel(**{**base, **kw})


# --- модель ---------------------------------------------------------------------------------
def test_model_validation():
    t = tun()
    assert t.network == "172.16.0.0/30" and t.peer_hint == "172.16.0.2/30" and t.mtu == 1380
    assert tun(address="172.16.0.0/31").peer_hint == "172.16.0.1/31"
    assert tun(routes=["192.168.20.7/24", "192.168.20.0/24"]).routes == ["192.168.20.0/24"]
    assert GreTunnel(name="GRE5", remote="10.8.1.3", address="172.16.0.5/30").name == "gre5"
    bad = [dict(name="gre0"), dict(name="tun1"), dict(remote="vpn.example.com"), dict(address="172.16.0.1/32"),
           dict(address="172.16.0.0/30"), dict(remote="172.16.0.2"), dict(routes=["10.8.0.0/16"]),
           dict(routes=["0.0.0.0/0"]), dict(local="10.8.1.3"), dict(underlay="gre2"), dict(comment='a"b')]
    for kw in bad:
        with pytest.raises(ValueError):
            tun(**kw)


def test_config_unique():
    with pytest.raises(ValueError, match="дважды"):
        GreConfig(tunnels=[tun(), tun(address="172.16.0.5/30", remote="10.8.1.4")])
    with pytest.raises(ValueError, match="пересекаются"):
        GreConfig(tunnels=[tun(), tun(name="gre2", remote="10.8.1.4", address="172.16.0.2/30")])
    with pytest.raises(ValueError, match="одинаковым"):
        GreConfig(tunnels=[tun(), tun(name="gre2", address="172.16.0.5/30")])
    c = GreConfig(tunnels=[tun(), tun(name="gre2", remote="10.8.1.4", address="172.16.0.5/30", local=None,
                                      underlay=None, comment="склад")])
    assert GreConfig.from_yaml(c.to_yaml()) == c
    assert "local" not in c.to_yaml()["tunnels"][1]


# --- применение -------------------------------------------------------------------------------
class FakeIp:
    """ip …: запоминает команды, на -j-запросы отвечает по состоянию «ядра»."""

    def __init__(self, links=None, routes=None):
        self.calls, self.links, self.routes = [], links or {}, routes or {}

    def __call__(self, *args, check=True):
        self.calls.append(" ".join(args))
        a = list(args)
        if a[:1] == ["-j"]:
            if "type" in a:
                return json.dumps([{"ifname": n, "flags": ["UP"] if l.get("up") else [], "mtu": 1380,
                                    "linkinfo": {"info_data": {"local": l.get("local") or "any",
                                                               "remote": l["remote"], "ttl": 64}},
                                    "addr_info": [{"family": "inet", "local": x.split("/")[0],
                                                   "prefixlen": int(x.split("/")[1])} for x in l.get("addr", [])]}
                                   for n, l in self.links.items()])
            if a[1:3] == ["route", "show"]:
                key = " ".join(a[3:])
                return json.dumps([{"dst": d} for d in self.routes.get(key, [])])
        if a[:2] == ["link", "add"]:
            self.links[a[2]] = {"remote": a[a.index("remote") + 1],
                                "local": a[a.index("local") + 1] if "local" in a else None}
        if a[:2] == ["link", "del"]:
            self.links.pop(a[2], None)
        return ""


@pytest.fixture
def env(tmp_path, monkeypatch):
    from app.core.store import ConfigStore
    cfg = tmp_path / "router.yaml"
    cfg.write_text("{}\n")
    st = ConfigStore(str(cfg), str(tmp_path / "data"))
    monkeypatch.setattr(gre, "store", st)
    monkeypatch.setattr(gre, "_state_path", lambda: tmp_path / "data" / "gre.json")
    sysnet = tmp_path / "sys"
    (sysnet / "awg0").mkdir(parents=True)
    monkeypatch.setattr(gre, "SYS_NET", sysnet)
    fake = FakeIp()
    monkeypatch.setattr(gre, "ip", fake)
    return fake, sysnet


def test_apply_creates_and_removes(env):
    fake, sysnet = env
    cfg = GreConfig(tunnels=[tun()])
    assert gre.apply(cfg) == {}
    assert "link add gre1 type gre remote 10.8.1.3 local 10.8.1.2 ttl 64" in fake.calls
    assert "link set gre1 mtu 1380 up" in fake.calls and "addr add 172.16.0.1/30 dev gre1" in fake.calls
    assert "route replace 192.168.20.0/24 dev gre1 proto static metric 20" in fake.calls
    assert "route replace 10.8.1.3/32 dev awg0 metric 5" in fake.calls
    st = gre.load_state()
    assert st["managed"] == ["gre1"] and st["underlay"] == [{"tunnel": "gre1", "remote": "10.8.1.3", "dev": "awg0"}]

    # тот же туннель ещё раз — не пересоздаётся; адрес уже есть
    fake.links["gre1"]["addr"] = ["172.16.0.1/30"]
    fake.calls.clear()
    gre.apply(cfg)
    assert not any(c.startswith(("link add", "link del", "addr add")) for c in fake.calls)

    # сменился второй роутер — пересоздать
    fake.calls.clear()
    gre.apply(GreConfig(tunnels=[tun(remote="10.8.1.9")]))
    assert "link del gre1" in fake.calls and "link add gre1 type gre remote 10.8.1.9 local 10.8.1.2 ttl 64" in fake.calls
    assert "route del 10.8.1.3/32 dev awg0 metric 5" in fake.calls

    # выключили — удалить своё
    fake.calls.clear()
    gre.apply(GreConfig(tunnels=[tun(remote="10.8.1.9", enabled=False)]))
    assert "link del gre1" in fake.calls and "route del 10.8.1.9/32 dev awg0 metric 5" in fake.calls
    assert gre.load_state()["managed"] == []


def test_stale_routes_and_foreign_links(env):
    fake, _ = env
    fake.links["gre7"] = {"remote": "198.51.100.1"}               # чужой туннель — не наш, не трогаем
    fake.links["gre1"] = {"remote": "10.8.1.3", "local": "10.8.1.2", "addr": ["172.16.9.1/30"]}
    fake.routes["dev gre1 proto static"] = ["192.168.99.0/24", "192.168.20.0/24"]
    gre.apply(GreConfig(tunnels=[tun()]))
    assert "addr del 172.16.9.1/30 dev gre1" in fake.calls
    assert "route del 192.168.99.0/24 dev gre1 proto static" in fake.calls
    assert not any("gre7" in c for c in fake.calls if not c.startswith("-j"))


def test_underlay_missing_then_watch(env):
    fake, sysnet = env
    (sysnet / "awg0").rmdir()
    errors = gre.apply(GreConfig(tunnels=[tun()]))
    assert "нет интерфейса awg0" in errors["gre1"]
    assert not any(c.startswith("route replace 10.8.1.3/32") for c in fake.calls)

    with gre.store.transaction() as data:
        data["gre"] = GreConfig(tunnels=[tun()]).to_yaml()
    (sysnet / "awg0").mkdir()                                     # AmneziaWG поднялся позже
    fake.calls.clear()
    assert gre.watch() == ["gre1"]
    assert "route replace 10.8.1.3/32 dev awg0 metric 5" in fake.calls
    fake.routes["10.8.1.3/32 dev awg0"] = ["10.8.1.3"]
    assert gre.watch() == []                                      # всё на месте — ничего не делаем
    assert gre.load_state()["errors"] == {}


# --- фаервол, OSPF, экспорт ------------------------------------------------------------------------
def test_firewall_rules():
    rules = firewall.GreRules(["gre1", "gre2"], ["10.8.1.3", "10.8.1.4"])
    vpn = firewall.VpnRules(iface="awg0", nat=True, killswitch=True, inbound=False)
    text = firewall.ruleset("enp1s0", "br-lan", False, vpn, gre=rules)
    inp = text[text.index("chain input"):text.index("chain forward")]
    assert inp.index("ip protocol 47 ip saddr { 10.8.1.3, 10.8.1.4 } accept") < inp.index('iifname "awg0" drop')
    fwd = text[text.index("chain forward"):text.index("chain prerouting")]
    assert 'iifname "br-lan" oifname { "gre1", "gre2" } accept' in fwd
    assert 'iifname { "gre1", "gre2" } oifname "br-lan" accept' in fwd
    assert 'oifname { "gre1", "gre2" } tcp flags syn tcp option maxseg size set rt mtu' in fwd
    post = text[text.index("chain postrouting"):]
    assert "gre" not in post.split("}")[0]                        # в GRE без NAT: сети видны как есть
    assert "ip protocol 47" not in firewall.ruleset("enp1s0", "br-lan", False)
    sysr = firewall.system_rules("enp1s0", False, vpn, gre=rules)
    assert any("GRE от 10.8.1.3, 10.8.1.4" in x for x in sysr["input"])
    assert any("LAN ↔ GRE" in x for x in sysr["forward"])


def test_ospf_with_gre(monkeypatch):
    t1, t2 = tun(ospf=True, ospf_cost=50), tun(name="gre2", remote="10.8.1.4", address="172.16.0.5/30", ospf=False)
    monkeypatch.setattr(gre, "get_config", lambda data=None: GreConfig(tunnels=[t1, t2]))
    cfg = RoutingConfig(ospf=OspfConfig(enabled=True, networks=[OspfNetwork(network="192.168.1.0/24")],
                                        interfaces=[OspfInterface(name="br-lan", passive=True)]))
    eff = routing.with_gre(cfg)
    assert [n.network for n in eff.ospf.networks] == ["192.168.1.0/24", "172.16.0.0/30"]
    g = next(i for i in eff.ospf.interfaces if i.name == "gre1")
    assert g.network_type == "point-to-point" and g.cost == 50
    assert not any(i.name == "gre2" for i in eff.ospf.interfaces)
    assert len(cfg.ospf.networks) == 1                              # исходный конфиг не меняется
    text = routing.frr_conf(eff)
    assert "interface gre1\n ip ospf cost 50\n ip ospf network point-to-point" in text
    assert " network 172.16.0.0/30 area 0.0.0.0" in text
    # своё (заданное вручную) не перетираем; OSPF выключен — ничего не добавляем
    own = cfg.model_copy(deep=True)
    own.ospf.interfaces.append(OspfInterface(name="gre1", cost=7))
    assert next(i for i in routing.with_gre(own).ospf.interfaces if i.name == "gre1").cost == 7
    off = RoutingConfig()
    assert routing.with_gre(off) is off


def test_export_gre():
    from app.services.export import export_text
    data = {"gre": GreConfig(tunnels=[tun(ospf=True, comment="офис 2")]).to_yaml()}
    text = export_text(data, now=__import__("datetime").datetime(2026, 11, 14))
    assert '/interface gre\nadd name=gre1 disabled=no local-address=10.8.1.2 remote-address=10.8.1.3' in text
    assert "add address=172.16.0.1/30 interface=gre1 comment=GRE" in text
    assert "add dst-address=192.168.20.0/24 gateway=gre1 comment=GRE" in text
    assert "/routing ospf interface-template\nadd interfaces=gre1 area=0.0.0.0 type=ptp comment=GRE" in text


def test_split_tunnel_allowed_ips(monkeypatch):
    """В режиме split WireGuard пропускает только AllowedIPs: адрес второго роутера добавляется сам."""
    from app.models.wireguard import WgConfig
    from app.services import vpn
    monkeypatch.setattr(gre, "get_config", lambda data=None: GreConfig(tunnels=[
        tun(), tun(name="gre2", remote="10.9.0.7", address="172.16.0.5/30", underlay="wg0"),
        tun(name="gre3", remote="10.8.1.4", address="172.16.0.9/30", enabled=False)]))
    monkeypatch.setattr(routing, "ospf_interfaces", lambda cfg=None: [])
    split = WgConfig(mode="split", allowed_ips=["10.20.0.0/16"])
    assert vpn.allowed_ips(split, "awg0") == ["10.20.0.0/16", "10.8.1.3/32"]
    covered = WgConfig(mode="split", allowed_ips=["10.8.1.0/24"])
    assert vpn.allowed_ips(covered, "awg0") == ["10.8.1.0/24"]
    assert vpn.allowed_ips(WgConfig(mode="full"), "awg0") == ["0.0.0.0/0"]


def test_management_through_tunnel():
    """Галочка «управление через туннель»: при NAT из awg0 пускаются порты управления и ping, остальное — drop."""
    from app.models.l2tp import L2tpConfig
    from app.models.wireguard import WgConfig
    on = firewall.VpnRules(iface="awg0", nat=True, killswitch=True, inbound=False, management=True)
    text = firewall.ruleset("enp1s0", "br-lan", False, on)
    inp = text[text.index("chain input"):text.index("chain forward")]
    mgmt = ", ".join(str(p) for p in firewall.management_ports())
    assert inp.index(f'iifname "awg0" tcp dport {{ {mgmt} }} accept') < inp.index('iifname "awg0" drop')
    assert 'iifname "awg0" icmp type echo-request accept' in inp
    off = firewall.VpnRules(iface="awg0", nat=True, killswitch=True, inbound=False)
    assert "управление через туннель" not in firewall.ruleset("enp1s0", "br-lan", False, off)
    site = firewall.VpnRules(iface="awg0", nat=False, killswitch=False, inbound=True, management=True)
    assert 'iifname "awg0" drop' not in firewall.ruleset("enp1s0", "br-lan", False, site)   # site-to-site: и так открыто
    assert any("управление (порты" in x for x in firewall.system_rules("enp1s0", False, on)["input"])
    assert WgConfig.from_yaml(WgConfig(management=True).to_yaml()).management is True
    assert WgConfig.from_yaml({}).management is False
    assert L2tpConfig.from_yaml(L2tpConfig(management=True).to_yaml()).management is True
