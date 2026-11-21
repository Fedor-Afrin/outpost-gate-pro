"""OSPF и BGP: проверка настроек, генерация frr.conf, разбор ответов vtysh, фаервол."""
import pytest
from pydantic import ValidationError

from app.models.routing import BgpNeighbor, OspfInterface, RoutingConfig, check_prefix
from app.services import firewall, routing


def cfg(**kw):
    return RoutingConfig.model_validate(kw)


def test_ospf_conf():
    c = cfg(router_id="10.255.0.1", ospf={
        "enabled": True,
        "networks": [{"network": "192.168.1.1/24", "area": 0}, {"network": "10.8.0.0/24", "area": "0.0.0.0"}],
        "interfaces": [{"name": "br-lan", "passive": True},
                       {"name": "wg0", "cost": 10, "network_type": "point-to-point", "auth_key": "s3cret"}],
        "redistribute": ["connected"], "default_route": "always"})
    t = routing.frr_conf(c, "office")
    assert "hostname office" in t
    assert "interface wg0\n ip ospf cost 10\n ip ospf network point-to-point\n" in t
    assert " ip ospf message-digest-key 1 md5 s3cret" in t
    assert "interface br-lan\n ip ospf passive\nexit" in t
    assert " ospf router-id 10.255.0.1" in t
    assert " network 192.168.1.0/24 area 0.0.0.0" in t
    assert " redistribute connected" in t
    assert " default-information originate always" in t
    assert "router bgp" not in t
    assert t.endswith("end\n")


def test_bgp_conf_with_filters():
    c = cfg(bgp={"enabled": True, "asn": 65010, "networks": ["192.168.1.0/24"],
                 "neighbors": [{"address": "10.8.0.1", "remote_as": 65000, "description": "HQ",
                                "password": "pw", "multihop": 2, "prefix_in": ["10.0.0.0/8 le 24"],
                                "prefix_out": ["192.168.1.0/24"]},
                               {"address": "10.8.0.9", "remote_as": 65010, "enabled": False,
                                "update_source": "lo", "keepalive": 10, "hold": 30}]})
    t = routing.frr_conf(c)
    assert "router bgp 65010\n" in t and " no bgp ebgp-requires-policy" in t
    assert " neighbor 10.8.0.1 remote-as 65000" in t
    assert " neighbor 10.8.0.1 description HQ" in t
    assert " neighbor 10.8.0.1 password pw" in t
    assert " neighbor 10.8.0.1 ebgp-multihop 2" in t
    assert " neighbor 10.8.0.9 shutdown" in t
    assert " neighbor 10.8.0.9 update-source lo" in t
    assert " neighbor 10.8.0.9 timers 10 30" in t
    assert "ip prefix-list BGP-N1-IN seq 5 permit 10.0.0.0/8 le 24" in t
    assert "  neighbor 10.8.0.1 prefix-list BGP-N1-IN in" in t
    assert "  neighbor 10.8.0.1 prefix-list BGP-N1-OUT out" in t
    assert "  network 192.168.1.0/24" in t
    assert "router ospf" not in t


def test_passive_default():
    c = cfg(ospf={"enabled": True, "passive_default": True, "networks": [{"network": "10.0.0.0/8"}],
                  "interfaces": [{"name": "wg0"}]})
    t = routing.frr_conf(c)
    assert " passive-interface default" in t and "interface wg0\n no ip ospf passive\nexit" in t


def test_nonbroadcast_neighbor():
    c = cfg(ospf={"enabled": True, "networks": [{"network": "10.8.0.0/24"}],
                  "interfaces": [{"name": "wg0", "network_type": "non-broadcast", "neighbor": "10.8.0.1"}]})
    t = routing.frr_conf(c)
    assert " ip ospf network non-broadcast" in t and " neighbor 10.8.0.1" in t


@pytest.mark.parametrize("bad", [
    {"ospf": {"enabled": True}},                                         # нет сетей
    {"ospf": {"networks": [{"network": "10.0.0.0/33"}]}},
    {"ospf": {"networks": [{"network": "10.0.0.0/8"}, {"network": "10.0.0.0/8"}]}},
    {"ospf": {"redistribute": ["ospf"]}},
    {"ospf": {"default_route": "sometimes"}},
    {"bgp": {"enabled": True}},                                          # нет соседей
    {"bgp": {"asn": 0}},
    {"bgp": {"neighbors": [{"address": "10.0.0.1", "remote_as": 1}, {"address": "10.0.0.1", "remote_as": 2}]}},
    {"router_id": "1.2.3"},
])
def test_invalid(bad):
    with pytest.raises(ValidationError):
        cfg(**bad)


def test_interface_and_neighbor_checks():
    with pytest.raises(ValidationError):
        OspfInterface(name="wg0", hello=10, dead=10)
    with pytest.raises(ValidationError):
        OspfInterface(name="wg0", network_type="non-broadcast")
    with pytest.raises(ValidationError):
        OspfInterface(name="wg0", auth_key="has space")
    with pytest.raises(ValidationError):
        BgpNeighbor(address="10.0.0.1", remote_as=1, keepalive=60, hold=90)
    with pytest.raises(ValidationError):
        BgpNeighbor(address="10.0.0.1", remote_as=1, description='a"b')


def test_prefix_syntax():
    assert check_prefix("10.0.0.1/8") == "10.0.0.0/8"
    assert check_prefix("0.0.0.0/0  ge 8  le 24") == "0.0.0.0/0 ge 8 le 24"
    for bad in ("10.0.0.0", "10.0.0.0/8 le 8", "10.0.0.0/8 ge 24 le 16", "nonsense"):
        with pytest.raises(ValueError):
            check_prefix(bad)


def test_parse_vtysh_json():
    ospf = {"neighbors": {"10.255.0.9": [{"nbrState": "Full/-", "ifaceAddress": "10.8.0.1",
                                           "ifaceName": "wg0:10.8.0.2", "nbrPriority": 1,
                                           "upTimeInMsec": 3723000, "routerDeadIntervalTimerDueMsec": 35000}]}}
    n = routing.parse_ospf_neighbors(ospf)[0]
    assert (n.router_id, n.address, n.interface, n.state, n.uptime) == \
        ("10.255.0.9", "10.8.0.1", "wg0", "Full/-", "1h02m03s")

    c = cfg(bgp={"enabled": True, "neighbors": [{"address": "10.8.0.1", "remote_as": 65000},
                                                 {"address": "10.8.0.5", "remote_as": 65000, "enabled": False}]})
    summary = {"ipv4Unicast": {"routerId": "10.255.0.1", "peers": {
        "10.8.0.1": {"remoteAs": 65000, "state": "Established", "peerUptime": "00:10:00", "pfxRcd": 4, "pfxSnt": 1}}}}
    p = routing.parse_bgp_summary(summary, c)
    assert p[0].state == "Established" and p[0].prefixes_received == 4 and p[0].uptime == "00:10:00"
    assert p[1].state == "Idle (Admin)" and not p[1].enabled

    routes = {"10.0.0.0/8": [{"prefix": "10.0.0.0/8", "protocol": "bgp", "selected": True, "distance": 20,
                              "metric": 0, "nexthops": [{"ip": "10.8.0.1", "interfaceName": "wg0", "active": True}]}],
              "192.168.1.0/24": [{"prefix": "192.168.1.0/24", "protocol": "connected", "nexthops": []}],
              "172.16.0.0/16": [{"prefix": "172.16.0.0/16", "protocol": "ospf", "distance": 110, "metric": 20,
                                 "nexthops": [{"ip": "10.8.0.1", "interfaceName": "wg0"}]}]}
    r = routing.parse_routes(routes)
    assert [(x.protocol, x.prefix) for x in r] == [("bgp", "10.0.0.0/8"), ("ospf", "172.16.0.0/16")]
    assert r[0].nexthop == "10.8.0.1" and r[0].selected
    assert routing.parse_ospf_neighbors(None) == [] and routing.parse_routes(None) == []


def test_ospf_interfaces_and_peers(monkeypatch):
    monkeypatch.setattr(routing.netlink, "kernel_ipv4_addresses",
                        lambda: [("br-lan", "192.168.1.1/24"), ("wg0", "10.8.0.2/24"), ("eth0", "203.0.113.2/24")])
    c = cfg(ospf={"enabled": True, "networks": [{"network": "192.168.1.0/24"}, {"network": "10.8.0.0/24"}],
                  "interfaces": [{"name": "br-lan", "passive": True}]},
            bgp={"enabled": True, "neighbors": [{"address": "10.8.0.1", "remote_as": 1},
                                                 {"address": "10.8.0.7", "remote_as": 1, "enabled": False}]})
    assert routing.ospf_interfaces(c) == ["wg0"]
    assert routing.bgp_peers(c) == ["10.8.0.1"]
    off = cfg()
    assert routing.ospf_interfaces(off) == [] and routing.bgp_peers(off) == []


def test_firewall_allows_routing():
    rs = firewall.ruleset("eth0", "br-lan", False, firewall.VpnRules("wg0", True, False, False),
                          routing=firewall.RoutingRules(["wg0", "br-lan"], ["10.8.0.1"]))
    inp = rs[rs.index("chain input"):rs.index("chain forward")]
    assert 'iifname "wg0" ip protocol 89 accept' in inp
    assert 'iifname "br-lan" ip protocol 89' not in inp
    assert "ip saddr { 10.8.0.1 } tcp dport 179 accept" in inp
    # до «из туннеля — только ответы», иначе OSPF через VPN в режиме NAT не пройдёт
    assert inp.index("ip protocol 89") < inp.index('iifname "wg0" drop')
    assert "ip protocol 89" not in firewall.ruleset("eth0", "br-lan", False, routing=firewall.RoutingRules([], []))
    text = firewall.system_rules("eth0", False, None, firewall.RoutingRules(["wg0"], ["10.8.0.1"]))["input"]
    assert "OSPF на wg0 — разрешён" in text
    assert "BGP от соседей 10.8.0.1 (TCP 179) — разрешён" in text


def test_wireguard_allowed_ips_get_ospf_multicast(monkeypatch):
    from app.models.wireguard import WgConfig
    from app.services import vpn
    wg = WgConfig(mode="split", allowed_ips=["10.0.0.0/8"], addresses=["10.8.0.2/24"])
    monkeypatch.setattr(routing, "ospf_interfaces", lambda cfg=None: ["wg0"])
    assert vpn.allowed_ips(wg, "wg0") == ["10.0.0.0/8", "224.0.0.5/32", "224.0.0.6/32"]
    monkeypatch.setattr(routing, "ospf_interfaces", lambda cfg=None: [])
    assert vpn.allowed_ips(wg, "wg0") == ["10.0.0.0/8"]
    full = WgConfig(mode="full", allowed_ips=["0.0.0.0/0"], addresses=["10.8.0.2/24"])
    assert vpn.allowed_ips(full, "wg0") == ["0.0.0.0/0"]


def test_apply_without_frr(monkeypatch, tmp_path):
    monkeypatch.setattr(routing, "FRR_DIR", tmp_path)
    monkeypatch.setattr(routing, "installed", lambda: False)
    monkeypatch.setattr(routing, "running", lambda: False)
    routing.apply(cfg())                                  # всё выключено — ничего не нужно
    with pytest.raises(routing.RoutingError) as e:
        routing.apply(cfg(ospf={"enabled": True, "networks": [{"network": "10.0.0.0/8"}]}))
    assert "FRRouting" in e.value.message


def test_apply_starts_then_reloads(monkeypatch, tmp_path):
    calls = []
    state = {"running": False}
    monkeypatch.setattr(routing, "FRR_DIR", tmp_path)
    monkeypatch.setattr(routing, "installed", lambda: True)
    monkeypatch.setattr(routing, "check", lambda text: None)
    monkeypatch.setattr(routing, "running", lambda: state["running"])
    monkeypatch.setattr(routing, "FRR_RELOAD", str(tmp_path / "frr-reload.py"))
    (tmp_path / "frr-reload.py").write_text("")

    def fake_init(action):
        calls.append(action)
        state["running"] = action in ("start", "restart")
    monkeypatch.setattr(routing, "_frrinit", fake_init)

    class R:
        returncode = 0
        stdout = stderr = ""
    monkeypatch.setattr(routing, "_run", lambda cmd, timeout=30: calls.append(cmd[0].rsplit("/", 1)[-1]) or R())
    c = cfg(bgp={"enabled": True, "neighbors": [{"address": "10.8.0.1", "remote_as": 65000}]})
    routing.apply(c)
    assert calls == ["start"] and "router bgp 65001" in (tmp_path / "frr.conf").read_text()
    assert "bgpd=yes" in (tmp_path / "daemons").read_text()
    routing.apply(c)
    assert calls == ["start", "frr-reload.py"]
    routing.apply(cfg())
    assert calls[-1] == "stop"


def test_secrets_are_masked_and_kept():
    old = cfg(ospf={"networks": [{"network": "10.0.0.0/8"}], "interfaces": [{"name": "wg0", "auth_key": "k1"}]},
              bgp={"neighbors": [{"address": "10.8.0.1", "remote_as": 1, "password": "p1"}]})
    m = routing.masked(old)
    assert m.ospf.interfaces[0].auth_key == routing.SECRET and m.bgp.neighbors[0].password == routing.SECRET
    assert old.ospf.interfaces[0].auth_key == "k1"            # оригинал не тронут
    back = routing.keep_secrets(m, old)
    assert back.ospf.interfaces[0].auth_key == "k1" and back.bgp.neighbors[0].password == "p1"
    changed = m.model_copy(deep=True)
    changed.bgp.neighbors[0].password = "new"
    assert routing.keep_secrets(changed, old).bgp.neighbors[0].password == "new"
