"""
Тесты LAN без ядра, nft и dnsmasq: всё системное подменяется.
Сценарий как в dev-режиме: WAN = eth1 (default от Docker), свободный порт eth0 с адресом Docker.
"""
import pytest
import yaml

from app.core.store import ConfigStore
from app.models.lan import LanConfig
from app.services import firewall, lan, netlink, oui, wan


class FakeKernel:
    def __init__(self):
        self.links = {"lo", "eth0", "eth1"}
        self.master = {}
        self.addrs = {("eth1", "172.18.0.2/16"), ("eth0", "172.19.0.2/16")}
        self.routes = [{"dst": "0.0.0.0/0", "gateway": "172.18.0.1", "interface": "eth1", "metric": 0, "proto": 3}]

    def link_names(self): return set(self.links)
    def link_info(self, n): return {"mac": f"02:00:00:00:00:0{len(n)}", "link_up": True} if n in self.links else {}
    def link_set_up(self, n): assert n in self.links
    def kernel_ipv4_addresses(self): return sorted(self.addrs)
    def kernel_ipv4_routes(self): return [dict(r) for r in self.routes]
    def addr_add(self, n, c):
        assert n in self.links, n
        self.addrs.add((n, c))
    def addr_del(self, n, c): self.addrs.discard((n, c))
    def bridge_create(self, name, mac=None): self.links.add(name)
    def link_delete(self, name):
        self.links.discard(name)
        self.addrs = {(n, c) for n, c in self.addrs if n != name}
    def link_set_master(self, port, bridge):
        if bridge: self.master[port] = bridge
        else: self.master.pop(port, None)


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / "router.yaml"
    cfg.write_text(yaml.safe_dump({"wan": {"interface": "eth1", "mode": "none"}}))
    store = ConfigStore(str(cfg), str(tmp_path / "data"))
    kernel = FakeKernel()
    for mod in (lan, wan):
        monkeypatch.setattr(mod, "store", store)
    monkeypatch.setattr(lan, "_data", lambda name: tmp_path / "data" / name)
    monkeypatch.setattr(wan, "state_file", lambda: tmp_path / "data" / "wan.json")
    monkeypatch.setattr(wan, "resolv_file", lambda: tmp_path / "data" / "resolv.wan")
    from app.services import vpn
    monkeypatch.setattr(vpn, "store", store)
    monkeypatch.setattr(vpn, "_data", lambda name: tmp_path / "data" / name)
    for name in ("link_names", "link_info", "link_set_up", "kernel_ipv4_addresses", "kernel_ipv4_routes",
                 "addr_add", "addr_del", "bridge_create", "link_delete", "link_set_master"):
        monkeypatch.setattr(netlink, name, getattr(kernel, name))
    calls = {"fw": [], "dhcp": [], "dns": 0}
    monkeypatch.setattr(firewall, "apply", lambda w, l, m, *rest: calls["fw"].append((w, l, m) + tuple(rest[4:5])))
    monkeypatch.setattr(firewall, "remove", lambda: None)
    from app.services import dhcp, dns
    monkeypatch.setattr(dhcp, "_data", lambda name: tmp_path / "data" / name)
    monkeypatch.setattr(dhcp, "apply", lambda segs, up: calls["dhcp"].append([(s.id, len(st)) for s, st in segs]))
    monkeypatch.setattr(dns, "store", store)
    monkeypatch.setattr(dns, "apply", lambda cfg=None: calls.__setitem__("dns", calls["dns"] + 1))
    (tmp_path / "data").mkdir()
    return store, kernel, calls


def test_enable_builds_bridge(env):
    store, kernel, calls = env
    st = lan.update(LanConfig(enabled=True))
    assert kernel.master == {"eth0": "br-lan"}                     # WAN (eth1) не тронут
    assert ("br-lan", "192.168.88.1/24") in kernel.addrs
    assert ("br-lan", "172.19.0.2/16") in kernel.addrs             # адрес порта переехал на мост
    assert ("eth0", "172.19.0.2/16") not in kernel.addrs
    assert calls["fw"] == [("eth1", ["br-lan"], True, [])] and calls["dhcp"] == [[("lan1", 0)]] and calls["dns"] == 1
    assert st.active
    roles = {p.name: p.role for p in st.ports}
    assert roles == {"eth1": "wan", "eth0": "lan"}
    saved = store.load()
    assert saved["lan"]["ports"] == "auto"
    assert saved["lan"]["dhcp-server"]["pool"] == "192.168.88.10-192.168.88.254"
    assert saved["firewall"] == {"wan-management": True}
    from app.services import dns
    assert saved["lan"]["domain"] == "office.lan" and dns.get_config().zone("office.lan")   # зона по умолчанию


def test_disable_restores_everything(env):
    _, kernel, _ = env
    before = set(kernel.addrs)
    lan.update(LanConfig(enabled=True))
    lan.update(LanConfig(enabled=False))
    assert kernel.addrs == before
    assert kernel.master == {} and "br-lan" not in kernel.links


def test_overlap_with_wan_rejected(env):
    store, kernel, _ = env
    with pytest.raises(lan.LanError, match="пересекается"):
        lan.update(LanConfig(enabled=True, address="172.18.5.1/24"))
    assert "lan" not in store.load()
    assert "br-lan" not in kernel.links                            # откат


def test_explicit_ports(env):
    _, kernel, _ = env
    kernel.links |= {"eth2", "eth3"}
    lan.update(LanConfig(enabled=True, ports=["eth2", "eth1"]))    # eth1 = WAN — игнорируется
    assert kernel.master == {"eth2": "br-lan"}


def test_firewall_ruleset():
    rs = firewall.ruleset("eth1", "br-lan", wan_management=True)
    assert 'oifname "eth1" masquerade' in rs
    assert 'iifname "br-lan" oifname "eth1" accept' in rs
    assert "policy drop" in rs and "tcp dport { 22, 8000 } accept" in rs
    assert rs.index("delete table inet outpost_gate_pro") < rs.index("table inet outpost_gate_pro {")
    assert "tcp dport" not in firewall.ruleset("eth1", "br-lan", wan_management=False)


def test_lan_config_validation():
    c = LanConfig(address="10.10.0.1/16")
    assert (c.pool_start, c.pool_end) == ("10.10.0.10", "10.10.255.254")
    small = LanConfig(address="192.168.1.1/29")
    assert (small.pool_start, small.pool_end) == ("192.168.1.2", "192.168.1.6")
    with pytest.raises(ValueError, match="адрес роутера"):
        LanConfig(address="192.168.88.1/24", pool_start="192.168.88.1")
    with pytest.raises(ValueError, match="вне сети"):
        LanConfig(pool_start="10.0.0.5")
    with pytest.raises(ValueError):
        LanConfig(lease_time="forever")
    back = LanConfig.from_yaml(*LanConfig(enabled=True, ports=["eth2"], wan_management=False).to_yaml())
    assert back.ports == ["eth2"] and back.wan_management is False and back.enabled


KEA_HEADER = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context\n"


def test_leases_and_vendor(env, tmp_path, monkeypatch):
    far = 4102444800   # 2100 год
    (tmp_path / "data" / "kea").mkdir(exist_ok=True)
    (tmp_path / "data" / "kea" / "kea-leases4.csv").write_text(
        KEA_HEADER
        + f"192.168.88.20,00:0b:82:aa:bb:cc,,43200,{far},1,0,0,GXP1625.office.lan.,0,\n"
        + f"192.168.88.11,da:a1:19:00:11:22,,43200,{far},1,0,0,,0,\n"
        + "192.168.88.12,da:a1:19:00:11:23,,43200,1000,1,0,0,old,0,\n"            # истекла
        + f"192.168.88.13,da:a1:19:00:11:24,,43200,{far},1,0,0,declined,1,\n")   # не default
    oui_file = tmp_path / "oui.txt"
    oui_file.write_text("00-0B-82   (hex)\t\tGrandstream Networks, Inc.\n")
    monkeypatch.setattr(oui, "OUI_FILES", [oui_file])
    oui._table.cache_clear()
    rows = lan.leases()
    assert [r.ip for r in rows] == ["192.168.88.11", "192.168.88.20"]
    assert rows[1].hostname == "GXP1625" and rows[1].vendor == "Grandstream Networks, Inc." and rows[1].lan == "lan1"
    assert rows[0].hostname is None and "случайный" in rows[0].vendor
    oui._table.cache_clear()


def test_static_leases(env):
    store, _, calls = env
    from app.models.lan import StaticLease
    lan.update(LanConfig(enabled=True))
    view = lan.add_static(StaticLease(mac="00-0B-82-AA-BB-CC", ip="192.168.88.5", name="GXP1625"))
    assert view[0].mac == "00:0b:82:aa:bb:cc" and not view[0].in_pool and view[0].valid
    lan.add_static(StaticLease(mac="00:0b:82:00:00:01", ip="192.168.88.50", name="Телефон бухгалтера"))
    assert calls["dhcp"][-1] == [("lan1", 2)]                      # Kea получил оба закреплённых
    assert lan.static_view()[1].in_pool

    for bad, code in ((StaticLease(mac="00:0b:82:aa:bb:cc", ip="192.168.88.6"), 409),
                      (StaticLease(mac="00:0b:82:00:00:02", ip="192.168.88.5"), 409),
                      (StaticLease(mac="00:0b:82:00:00:03", ip="10.0.0.5"), 400),
                      (StaticLease(mac="00:0b:82:00:00:04", ip="192.168.88.1"), 400)):
        with pytest.raises(lan.LanError) as e:
            lan.add_static(bad)
        assert e.value.status == code

    lan.update(LanConfig(enabled=True, lease_time="1d"))           # смена LAN не теряет закреплённые
    assert len(store.load()["lan"]["dhcp-server"]["static-leases"]) == 2
    lan.update_static("00:0b:82:aa:bb:cc", StaticLease(mac="00:0b:82:aa:bb:cc", ip="192.168.88.6"))
    assert lan.delete_static("00:0B:82:00:00:01")[0].ip == "192.168.88.6"
    with pytest.raises(lan.LanError):
        lan.delete_static("00:0b:82:00:00:01")


def test_leases_mark_static(env, tmp_path):
    from app.models.lan import StaticLease
    lan.update(LanConfig(enabled=True))
    lan.add_static(StaticLease(mac="00:0b:82:aa:bb:cc", ip="192.168.88.5", name="Телефон"))
    (tmp_path / "data" / "kea").mkdir(exist_ok=True)
    (tmp_path / "data" / "kea" / "kea-leases4.csv").write_text(
        KEA_HEADER + "192.168.88.5,00:0b:82:aa:bb:cc,,4294967295,0,1,0,0,gxp,0,\n")
    row = lan.leases()[0]
    assert row.static and row.name == "Телефон" and row.expires is None


# --- сегменты ---------------------------------------------------------------------------
def test_second_segment_takes_ports_and_isolated(env):
    store, kernel, calls = env
    kernel.links |= {"eth2", "eth3"}
    lan.update(LanConfig(enabled=True))
    assert set(kernel.master) == {"eth0", "eth2", "eth3"}
    segs = lan.add_segment(LanConfig(enabled=True, name="Guests", address="10.20.0.1/24", ports=["eth3"],
                                     domain="guest.lan"))
    assert [s.config.id for s in segs] == ["lan1", "lan2"]
    assert kernel.master == {"eth0": "br-lan", "eth2": "br-lan", "eth3": "br-lan2"}   # auto отдал eth3
    assert ("br-lan2", "10.20.0.1/24") in kernel.addrs
    assert calls["fw"][-1] == ("eth1", ["br-lan", "br-lan2"], True, [])              # транзита нет
    assert calls["dhcp"][-1] == [("lan1", 0), ("lan2", 0)]
    data = store.load()
    assert data["lans"][0]["id"] == "lan2" and data["lans"][0]["ports"] == ["eth3"]
    assert {z["name"] for z in data["dns"]["zones"]} == {"office.lan", "guest.lan"}  # зона создана сама

    # разрешить LAN → Guests
    primary = lan.get_config().model_copy(update={"forward_to": ["lan2"]})
    lan.update(primary)
    assert calls["fw"][-1][3] == [("br-lan", "br-lan2")]

    # удалить сегмент: порт вернулся в lan1, ссылка forward-to убрана
    lan.delete_segment("lan2")
    assert kernel.master == {"eth0": "br-lan", "eth2": "br-lan", "eth3": "br-lan"}
    assert "br-lan2" not in kernel.links and lan.get_config().forward_to == []


def test_segment_validation(env):
    _, kernel, _ = env
    kernel.links |= {"eth2", "eth3"}
    lan.update(LanConfig(enabled=True))
    with pytest.raises(lan.LanError, match="пересекаются"):
        lan.add_segment(LanConfig(enabled=True, address="192.168.88.200/25", ports=["eth3"]))
    with pytest.raises(lan.LanError, match="без портов"):
        lan.add_segment(LanConfig(enabled=True, address="10.20.0.1/24"))
    lan.add_segment(LanConfig(enabled=True, address="10.20.0.1/24", ports=["eth3"]))
    with pytest.raises(lan.LanError, match="уже в сегменте"):
        lan.add_segment(LanConfig(enabled=True, address="10.30.0.1/24", ports=["eth3"]))
    with pytest.raises(lan.LanError, match="нельзя удалить"):
        lan.delete_segment("lan1")
    with pytest.raises(lan.LanError, match="несуществующий"):
        lan.update(lan.get_config().model_copy(update={"forward_to": ["lan9"]}))
    assert "lan2" in {s.id for s in lan.segments()}                # после ошибок всё на месте
    with pytest.raises(ValueError):
        LanConfig(id="lan2", forward_to=["lan2"])


def test_dhcp_settings_without_rebuild(env):
    store, kernel, calls = env
    from app.models.lan import DhcpSettings
    lan.update(LanConfig(enabled=True))
    fw_before = len(calls["fw"])
    st = lan.update_dhcp("lan1", DhcpSettings(pool_start="192.168.88.100", pool_end="192.168.88.150",
                                              lease_time="1d", dhcp_options={"ntp_servers": ["192.168.88.1"]}))
    assert len(calls["fw"]) == fw_before                            # мост не пересобирался
    assert st.segments[0].settings.pool_start == "192.168.88.100"
    saved = store.load()["lan"]["dhcp-server"]
    assert saved["pool"] == "192.168.88.100-192.168.88.150" and saved["options"] == {"ntp_servers": ["192.168.88.1"]}
    with pytest.raises(lan.LanError):
        lan.update_dhcp("lan1", DhcpSettings(pool_start="10.0.0.1", pool_end="10.0.0.9"))
    with pytest.raises(lan.LanError):
        lan.update_dhcp("lan7", DhcpSettings())


# --- VLAN ----------------------------------------------------------------------------------------
def _vlan_kernel(kernel, monkeypatch):
    created = []

    def vlan_create(name, parent, vid):
        assert parent in kernel.links
        kernel.links.add(name)
        created.append((name, parent, vid))
    monkeypatch.setattr(netlink, "vlan_create", vlan_create)
    return created


def test_segment_on_vlan_trunk(env, monkeypatch):
    store, kernel, calls = env
    kernel.links |= {"eth2"}
    created = _vlan_kernel(kernel, monkeypatch)
    lan.update(LanConfig(enabled=True))                                    # eth0, eth2 — без тега
    lan.add_segment(LanConfig(enabled=True, name="Phones", address="10.30.0.1/24", vlan_id=30,
                              trunk_ports=["eth2"]))
    assert created == [("eth2.30", "eth2", 30)]
    assert kernel.master["eth2.30"] == "br-lan2" and kernel.master["eth2"] == "br-lan"   # native + tagged
    assert store.load()["lans"][0]["vlan"] == {"id": 30, "trunk-ports": ["eth2"]}
    st = lan.status()
    eth2 = next(p for p in st.ports if p.name == "eth2")
    assert eth2.segment == "lan1" and eth2.vlans == ["30 (Phones)"]
    assert "eth2.30" not in {p.name for p in st.ports}                     # VLAN-интерфейс — не порт
    # повторная сборка и удаление: VLAN-интерфейс убирается
    lan.delete_segment("lan2")
    assert "eth2.30" not in kernel.links
    # одинаковый VLAN у двух сегментов — нельзя
    lan.add_segment(LanConfig(enabled=True, address="10.30.0.1/24", vlan_id=30, trunk_ports=["eth2"]))
    with pytest.raises(lan.LanError, match="VLAN 30 уже"):
        lan.add_segment(LanConfig(enabled=True, address="10.40.0.1/24", vlan_id=30, trunk_ports=["eth0"]))


def test_wan_on_provider_vlan(env, monkeypatch):
    store, kernel, calls = env
    created = _vlan_kernel(kernel, monkeypatch)
    from app.models.wan import WanConfig
    monkeypatch.setattr(wan, "write_upstream_dns", lambda dns: None)
    monkeypatch.setattr(netlink, "route_add", lambda *a, **k: None)
    monkeypatch.setattr(netlink, "route_del", lambda *a, **k: None)
    wan.apply(WanConfig(interface="eth1", mode="static", address="203.0.113.2/24", gateway="203.0.113.1", vlan_id=100))
    assert created == [("eth1.100", "eth1", 100)] and ("eth1.100", "203.0.113.2/24") in kernel.addrs
    st = wan.load_state()
    assert st["interface"] == "eth1.100" and st["base"] == "eth1"
    assert "eth1.100" not in wan.candidates()
    assert lan.wan_interface() == "eth1.100" and set(lan._wan_ports()) == {"eth1.100", "eth1"}
    assert "eth1" not in lan.lan_ports(LanConfig(enabled=True), "eth1.100")   # физический WAN не уходит в LAN
    wan.cleanup(wan.load_state())
    assert "eth1.100" not in kernel.links
    assert WanConfig(interface="eth1", mode="dhcp", vlan_id=100).to_yaml()["vlan_id"] == 100
