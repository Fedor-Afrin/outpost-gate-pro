"""Два провайдера, NTP и Wake-on-LAN — без ядра: команды ip, ping и сокеты подменяются."""
import json

import pytest
import yaml
from pydantic import ValidationError

from app.core.store import ConfigStore
from app.models.lan import LanConfig
from app.models.ntp import NtpConfig
from app.models.wan import MultiWanConfig, Wan2Config
from app.services import dhcp, firewall, multiwan, ntp, tools, wan

INFO = {"wan1": {"interface": "eth0", "address": "203.0.113.10", "gateway": "203.0.113.1"},
        "wan2": {"interface": "eth2", "address": "100.64.5.7", "gateway": "100.64.5.1"}}


def H(**states):
    return {"wans": {w: {"healthy": v} for w, v in states.items()}}


# --- план маршрутов ---------------------------------------------------------------------------
def test_plan_failover():
    cfg = MultiWanConfig()
    p = multiwan.plan(cfg, INFO, H())
    assert p["active"] == ["wan1"]
    assert p["tables"] == [["route", "replace", "default", "via", "203.0.113.1", "dev", "eth0", "table", "101"],
                           ["route", "replace", "default", "via", "100.64.5.1", "dev", "eth2", "table", "102"]]
    assert (1000, ["lookup", "main", "suppress_prefixlength", "0"]) == p["rules"][0]
    assert (1010, ["from", "203.0.113.10", "lookup", "101"]) in p["rules"]
    assert (1021, ["oif", "eth2", "lookup", "102"]) in p["rules"]
    assert (1031, ["fwmark", "0x102", "lookup", "102"]) in p["rules"]
    assert p["main"] == [["default", "via", "203.0.113.1", "dev", "eth0", "metric", "0"],
                         ["default", "via", "100.64.5.1", "dev", "eth2", "metric", "1"]]
    # основной упал — трафик через WAN2
    p = multiwan.plan(cfg, INFO, H(wan1=False, wan2=True))
    assert p["active"] == ["wan2"] and p["main"][0][:3] == ["default", "via", "100.64.5.1"]
    # оба упали — остаёмся на основном (лучше, чем ничего)
    assert multiwan.plan(cfg, INFO, H(wan1=False, wan2=False))["active"] == ["wan1"]
    # основной — WAN2
    assert multiwan.plan(MultiWanConfig(primary="wan2"), INFO, H())["active"] == ["wan2"]
    # у WAN2 ещё нет адреса (DHCP ищет сервер) — только WAN1, без его таблицы
    info = {**INFO, "wan2": {"interface": "eth2", "address": None, "gateway": None}}
    p = multiwan.plan(cfg, info, H())
    assert ["route", "flush", "table", "102"] in p["tables"] and len(p["main"]) == 1


def test_plan_balance():
    cfg = MultiWanConfig(mode="balance", weight1=3, weight2=1)
    p = multiwan.plan(cfg, INFO, H(wan1=True, wan2=True))
    assert p["active"] == ["wan1", "wan2"]
    assert p["main"] == [["default", "metric", "0", "nexthop", "via", "203.0.113.1", "dev", "eth0", "weight", "3",
                          "nexthop", "via", "100.64.5.1", "dev", "eth2", "weight", "1"]]
    p = multiwan.plan(cfg, INFO, H(wan1=True, wan2=False))
    assert p["active"] == ["wan1"] and p["main"] == [["default", "via", "203.0.113.1", "dev", "eth0", "metric", "0"]]


def test_health_hysteresis():
    cfg = MultiWanConfig(fail_after=3, recover_after=2)
    h = {}
    assert multiwan.step(h, "wan1", True, 5.0, cfg, 1) is None          # первая проверка: просто «жив»
    assert h["wans"]["wan1"]["healthy"] is True
    assert [multiwan.step(h, "wan1", False, None, cfg, t) for t in (2, 3, 4)] == [None, None, "down"]
    assert multiwan.step(h, "wan1", True, 6.0, cfg, 5) is None          # одна удача — ещё не вернулся
    assert multiwan.step(h, "wan1", False, None, cfg, 6) is None        # и счётчик удач сбрасывается
    assert [multiwan.step(h, "wan1", True, 6.0, cfg, t) for t in (7, 8)] == [None, "up"]
    assert h["wans"]["wan1"]["since"] == 8 and h["wans"]["wan1"]["rtt"] == 6.0


def test_model_validation():
    assert Wan2Config(enabled=True, interface="eth2").mode == "dhcp"
    with pytest.raises(ValidationError):
        Wan2Config(enabled=True)                                          # нужен порт
    with pytest.raises(ValidationError):
        Wan2Config(enabled=True, interface="eth2", mode="static", address="10.0.0.2/24")   # нет шлюза
    with pytest.raises(ValidationError):
        MultiWanConfig(weight1=0)
    with pytest.raises(ValidationError):
        MultiWanConfig(check_targets=[])
    with pytest.raises(ValidationError):
        MultiWanConfig(check_targets=["example.com"])
    assert Wan2Config(enabled=True, interface="eth2").to_yaml() == {"enabled": True, "interface": "eth2", "mode": "dhcp"}


# --- фаервол с двумя WAN -----------------------------------------------------------------------
def test_firewall_two_wans():
    from app.models.firewall import PortForward
    fwd = [(1, PortForward(protocol="tcp", wan_port="8080", to_ip="192.168.88.20", to_port=80))]
    rs = firewall.ruleset(["eth0", "eth2"], "br-lan", False, forwards=fwd)
    assert 'iifname != { "eth0", "eth2" } accept' in rs
    assert 'iifname "br-lan" oifname { "eth0", "eth2" } accept' in rs
    assert 'oifname { "eth0", "eth2" } masquerade' in rs
    assert 'iifname { "eth0", "eth2" } meta l4proto tcp th dport 8080' in rs
    assert 'iifname "eth2" ct state new ct mark set 0x102' in rs
    assert 'ct mark 0 oifname "eth0" ct mark set 0x101' in rs
    assert 'iifname != { "eth0", "eth2" } ct mark { 0x101, 0x102 } meta mark set ct mark' in rs
    one = firewall.ruleset("eth0", "br-lan", False)
    assert "multiwan" not in one and 'oifname "eth0" masquerade' in one
    assert "С WAN (eth0, eth2)" in firewall.system_rules(["eth0", "eth2"], False, None)["input"][-2]


# --- второй WAN целиком: включить, проверка связи, выключить ---------------------------------------
@pytest.fixture
def env(tmp_path, monkeypatch):
    cfgf = tmp_path / "router.yaml"
    cfgf.write_text(yaml.safe_dump({"wan": {"interface": "eth0", "mode": "static", "address": "203.0.113.10/24",
                                            "gateway": "203.0.113.1"}}))
    store = ConfigStore(str(cfgf), str(tmp_path / "snap"))
    for mod in (wan, multiwan):
        monkeypatch.setattr(mod, "store", store)
    monkeypatch.setattr(wan, "state_file", lambda: tmp_path / "wan.json")
    monkeypatch.setattr(wan, "resolv_file", lambda: tmp_path / "resolv.wan")
    monkeypatch.setattr(multiwan, "_data", lambda name: tmp_path / name)
    wan.save_state({"interface": "eth0", "mode": "static", "state": "static", "address": "203.0.113.10/24",
                    "gateway": "203.0.113.1", "dns": ["203.0.113.53"]})
    ipcalls = []

    class R:
        returncode, stdout, stderr = 0, "", ""
    monkeypatch.setattr(multiwan, "ip", lambda *a, **k: ipcalls.append(list(a)) or R())
    from app.services import lan, netlink, system, vpn
    monkeypatch.setattr(netlink, "link_names", lambda: {"lo", "eth0", "eth1", "eth2", "br-lan"})
    monkeypatch.setattr(netlink, "link_set_up", lambda n: None)
    monkeypatch.setattr(netlink, "link_info", lambda n: {"link_up": True})
    monkeypatch.setattr(netlink, "addr_add", lambda *a: None)
    monkeypatch.setattr(netlink, "addr_del", lambda *a: None)
    monkeypatch.setattr(netlink, "route_add", lambda *a, **k: None)
    monkeypatch.setattr(netlink, "route_del", lambda *a, **k: None)
    monkeypatch.setattr(netlink, "kernel_ipv4_addresses", lambda: [])
    monkeypatch.setattr(netlink, "kernel_ipv4_routes", lambda: [])
    monkeypatch.setattr(lan, "segments", lambda data=None: [LanConfig(enabled=True, ports=["eth1"])])
    monkeypatch.setattr(lan, "on_wan_changed", lambda: None)
    monkeypatch.setattr(vpn, "on_wan_changed", lambda: None)
    monkeypatch.setattr(vpn, "refresh_endpoint_route", lambda: None)
    monkeypatch.setattr(vpn, "dns_override", lambda: [])
    monkeypatch.setattr(system, "audit", lambda *a: None)
    started = []
    monkeypatch.setattr(wan, "start_dhcp", lambda ifname, wid="wan1": started.append((ifname, wid)))
    return store, ipcalls, started, tmp_path


def test_wan2_enable_check_failover_disable(env, monkeypatch):
    store, ipcalls, started, tmp = env
    with pytest.raises(wan.WanError, match="занят WAN1"):
        wan.update_wan2(Wan2Config(enabled=True, interface="eth0"))
    with pytest.raises(wan.WanError, match="сегменту LAN"):
        wan.update_wan2(Wan2Config(enabled=True, interface="eth1"))
    assert "wan2" not in store.load()

    st = wan.update_wan2(Wan2Config(enabled=True, interface="eth2", mode="static", address="100.64.5.7/24",
                                    gateway="100.64.5.1", dns=["100.64.0.53"]))
    assert st.config.enabled and wan.multi() and store.load()["wan2"]["interface"] == "eth2"
    assert wan.active_interfaces() == ["eth0", "eth2"] and "eth2" in wan.physical_ports()
    assert ["route", "replace", "default", "via", "100.64.5.1", "dev", "eth2", "table", "102"] in ipcalls
    assert ["route", "replace", "default", "via", "203.0.113.1", "dev", "eth0", "metric", "0"] in ipcalls
    assert "nameserver 203.0.113.53\nnameserver 100.64.0.53" in (tmp / "resolv.wan").read_text()
    assert wan.current_gateway() == "203.0.113.1"

    # WAN1 перестал отвечать: после fail_after проверок трафик уходит в WAN2
    monkeypatch.setattr(multiwan, "probe", lambda ifname, t: (ifname == "eth2", 9.0 if ifname == "eth2" else None))
    flushed = []
    monkeypatch.setattr(multiwan, "flush_conntrack", flushed.append)
    cfg = multiwan.get_config()
    ipcalls.clear()
    for t in range(cfg.fail_after):
        changes = multiwan.checker.check_once(cfg, now=100 + t)
    assert changes == [("wan1", "down")] and flushed == ["wan1"]
    assert ["route", "replace", "default", "via", "100.64.5.1", "dev", "eth2", "metric", "0"] in ipcalls
    assert wan.current_gateway() == "100.64.5.1"
    assert (tmp / "resolv.wan").read_text().startswith("nameserver 100.64.0.53")   # DNS живого канала — первым
    s = multiwan.status()
    assert [(w.id, w.healthy, w.active) for w in s.wans] == [("wan1", False, False), ("wan2", True, True)]
    assert s.events[0]["wan"] == "wan1" and s.events[0]["state"] == "down"

    # вернулся
    monkeypatch.setattr(multiwan, "probe", lambda ifname, t: (True, 5.0))
    for t in range(cfg.recover_after):
        changes = multiwan.checker.check_once(cfg, now=200 + t)
    assert changes == [("wan1", "up")] and wan.current_gateway() == "203.0.113.1"

    # балансировка
    multiwan.update(MultiWanConfig(mode="balance", weight1=2))
    assert any("nexthop" in c for c in ipcalls)

    # выключить второй WAN — снова один канал
    ipcalls.clear()
    wan.update_wan2(Wan2Config(enabled=False, interface="eth2"))
    assert not wan.multi() and wan.active_interfaces() == ["eth0"]
    assert ["route", "flush", "table", "102"] in ipcalls
    assert ["route", "replace", "default", "via", "203.0.113.1", "metric", "1"] in ipcalls


def test_hook_wan2_dhcp(env, monkeypatch):
    store, ipcalls, started, tmp = env
    wan.update_wan2(Wan2Config(enabled=True, interface="eth2"))
    assert started == [("eth2", "wan2")] and wan.load_state("wan2")["state"] == "searching"
    from app.services import wan_hook
    lease = {"WAN_ID": "wan2", "interface": "eth2", "ip": "100.64.5.7", "subnet": "255.255.255.0",
             "router": "100.64.5.1", "dns": "100.64.0.53", "lease": "600"}
    wan_hook.handle("bound", lease)
    st = wan.load_state("wan2")
    assert st["gateway"] == "100.64.5.1" and st["address"] == "100.64.5.7/24"
    assert wan.load_state()["gateway"] == "203.0.113.1"                  # WAN1 не тронут
    assert ["route", "replace", "default", "via", "100.64.5.1", "dev", "eth2", "table", "102"] in ipcalls
    ipcalls.clear()
    wan_hook.handle("deconfig", {"WAN_ID": "wan2", "interface": "eth2"})
    assert ["route", "flush", "table", "102"] in ipcalls and wan.load_state("wan2")["gateway"] is None


# --- NTP ---------------------------------------------------------------------------------------
def test_ntp_conf_and_parsers(tmp_path):
    c = NtpConfig(enabled=True, servers=["pool.ntp.org", "TIME.google.com", "162.159.200.1"], orphan=True)
    assert c.servers == ["pool.ntp.org", "time.google.com", "162.159.200.1"]
    t = ntp.chrony_conf(c, ["192.168.88.0/24", "10.30.0.0/24"], tmp_path / "drift")
    assert "pool pool.ntp.org iburst" in t and "server time.google.com iburst" in t and "server 162.159.200.1 iburst" in t
    assert "allow 192.168.88.0/24" in t and "allow 10.30.0.0/24" in t and "local stratum 10 orphan" in t
    t = ntp.chrony_conf(NtpConfig(enabled=True, serve_lan=False), ["192.168.88.0/24"], tmp_path / "drift")
    assert "allow" not in t.replace("cmdallow", "")
    with pytest.raises(ValidationError):
        NtpConfig(servers=["bad host!"])
    tr = ntp.parse_tracking("A29FC801,162.159.200.1,3,1700000000.1,-0.000012,0.00001,0.0002,1.5,0.01,0.1,0.02,0.003,64.5,Normal")
    assert tr == {"reference": "162.159.200.1", "stratum": 3, "offset": -0.000012, "synced": True}
    assert ntp.parse_tracking("7F7F0101,,10,0,0,0,0,0,0,0,0,0,0,Not synchronised")["synced"] is False
    src = ntp.parse_sources("^,*,162.159.200.1,3,6,377,23,-0.000040,-0.000041,0.012\n^,?,10.0.0.1,0,6,0,-,0,0,0\n")
    assert [(s.address, s.state, s.reach) for s in src] == [("162.159.200.1", "*", 255), ("10.0.0.1", "?", 0)]


def test_dhcp_option_42_points_to_router():
    seg = LanConfig(enabled=True, address="192.168.88.1/24")
    opts = dhcp.option_data(seg, [], ntp_router=True)
    assert {"name": "ntp-servers", "data": "192.168.88.1"} in opts
    assert not any(o.get("name") == "ntp-servers" for o in dhcp.option_data(seg, []))
    own = LanConfig(enabled=True, address="192.168.88.1/24", dhcp_options={"ntp_servers": ["10.0.0.1"]})
    assert {"name": "ntp-servers", "data": "10.0.0.1"} in dhcp.option_data(own, [], ntp_router=True)


# --- Wake-on-LAN -------------------------------------------------------------------------------
def test_wol(monkeypatch):
    assert tools.normalize_mac("3C-52-82-AA-BB-CC") == "3c:52:82:aa:bb:cc"
    assert tools.normalize_mac("3c5282aabbcc") == "3c:52:82:aa:bb:cc"
    for bad in ("zz:52:82:aa:bb:cc", "01:00:5e:00:00:01", "ff:ff:ff:ff:ff:ff", "3c:52:82"):
        with pytest.raises(tools.ToolError):
            tools.normalize_mac(bad)
    pkt = tools.magic_packet("3c:52:82:aa:bb:cc")
    assert len(pkt) == 102 and pkt[:6] == b"\xff" * 6 and pkt[6:12] == bytes.fromhex("3c5282aabbcc")

    from app.models.lan import Lease
    from app.services import lan
    s1 = LanConfig(id="lan1", name="LAN", enabled=True, address="192.168.88.1/24")
    s2 = LanConfig(id="lan2", name="Phones", enabled=True, address="10.30.0.1/24")
    monkeypatch.setattr(lan, "segments", lambda data=None: [s1, s2])
    monkeypatch.setattr(lan, "leases", lambda: [Lease(ip="10.30.0.5", mac="3c:52:82:aa:bb:cc", lan="lan2")])
    monkeypatch.setattr(lan, "static_leases", lambda sid="lan1": [])
    sent = []
    monkeypatch.setattr(tools, "send_wol", lambda mac, bridge, bcast, repeat=3: sent.append((mac, bridge, bcast)))
    r = tools.wol("3C:52:82:AA:BB:CC")
    assert sent == [("3c:52:82:aa:bb:cc", "br-lan2", "10.30.0.255")] and r["sent"][0]["name"] == "Phones"
    sent.clear()
    tools.wol("aa:bb:cc:00:00:01")                       # неизвестное устройство — во все сегменты
    assert [b for _, b, _ in sent] == ["br-lan", "br-lan2"]
    sent.clear()
    tools.wol("aa:bb:cc:00:00:01", "LAN")
    assert [b for _, b, _ in sent] == ["br-lan"]
    with pytest.raises(tools.ToolError, match="нет включённого сегмента"):
        tools.wol("aa:bb:cc:00:00:01", "lan9")
