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
    calls = {"fw": [], "dnsmasq": 0}
    monkeypatch.setattr(firewall, "apply", lambda w, l, m, *rest: calls["fw"].append((w, l, m)))
    monkeypatch.setattr(firewall, "remove", lambda: None)
    def fake_start(cfg):
        calls["dnsmasq"] += 1
        lan._data("dnsmasq.conf").parent.mkdir(parents=True, exist_ok=True)
        lan._data("dnsmasq.conf").write_text(lan.dnsmasq_conf(cfg, "leases", "resolv"))
        lan.write_hosts_file()
    monkeypatch.setattr(lan, "start_dnsmasq", fake_start)
    (tmp_path / "data").mkdir()
    return store, kernel, calls


def test_enable_builds_bridge(env):
    store, kernel, calls = env
    st = lan.update(LanConfig(enabled=True))
    assert kernel.master == {"eth0": "br-lan"}                     # WAN (eth1) не тронут
    assert ("br-lan", "192.168.88.1/24") in kernel.addrs
    assert ("br-lan", "172.19.0.2/16") in kernel.addrs             # адрес порта переехал на мост
    assert ("eth0", "172.19.0.2/16") not in kernel.addrs
    assert calls["fw"] == [("eth1", "br-lan", True)] and calls["dnsmasq"] == 1
    assert st.active
    roles = {p.name: p.role for p in st.ports}
    assert roles == {"eth1": "wan", "eth0": "lan"}
    saved = store.load()
    assert saved["lan"]["ports"] == "auto"
    assert saved["lan"]["dhcp-server"]["pool"] == "192.168.88.10-192.168.88.254"
    assert saved["firewall"] == {"wan-management": True}


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


def test_dnsmasq_conf():
    conf = lan.dnsmasq_conf(LanConfig(enabled=True, lease_time="1d"), "/d/leases", "/d/resolv.wan", "/d/hosts")
    assert "dhcp-hostsfile=/d/hosts" in conf
    assert "interface=br-lan" in conf and "bind-dynamic" in conf
    assert "dhcp-range=192.168.88.10,192.168.88.254,255.255.255.0,1d" in conf
    assert "dhcp-option=option:router,192.168.88.1" in conf
    assert "resolv-file=/d/resolv.wan" in conf
    no_dhcp = lan.dnsmasq_conf(LanConfig(enabled=True, dhcp_enabled=False), "l", "r")
    assert "dhcp-range" not in no_dhcp and "no-dhcp-interface=br-lan" in no_dhcp


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


def test_leases_and_vendor(env, tmp_path, monkeypatch):
    (tmp_path / "data" / "dnsmasq.leases").write_text(
        "1762700000 00:0b:82:aa:bb:cc 192.168.88.20 GXP1625 01:00:0b:82:aa:bb:cc\n"
        "1762700500 da:a1:19:00:11:22 192.168.88.11 * *\n")
    oui_file = tmp_path / "oui.txt"
    oui_file.write_text("00-0B-82   (hex)\t\tGrandstream Networks, Inc.\n")
    monkeypatch.setattr(oui, "OUI_FILES", [oui_file])
    oui._table.cache_clear()
    rows = lan.leases()
    assert [r.ip for r in rows] == ["192.168.88.11", "192.168.88.20"]
    assert rows[1].hostname == "GXP1625" and rows[1].vendor == "Grandstream Networks, Inc."
    assert rows[0].hostname is None and "случайный" in rows[0].vendor
    oui._table.cache_clear()


def test_static_leases(env):
    store, _, _ = env
    from app.models.lan import StaticLease
    lan.update(LanConfig(enabled=True))
    view = lan.add_static(StaticLease(mac="00-0B-82-AA-BB-CC", ip="192.168.88.5", name="GXP1625"))
    assert view[0].mac == "00:0b:82:aa:bb:cc" and not view[0].in_pool and view[0].valid
    lan.add_static(StaticLease(mac="00:0b:82:00:00:01", ip="192.168.88.50", name="Телефон бухгалтера"))
    hosts = lan._data("dnsmasq.hosts").read_text()
    assert "00:0b:82:aa:bb:cc,192.168.88.5,GXP1625" in hosts
    assert "00:0b:82:00:00:01,192.168.88.50\n" in hosts           # кириллица — не hostname
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
    (tmp_path / "data" / "dnsmasq.leases").write_text("0 00:0b:82:aa:bb:cc 192.168.88.5 gxp *\n")
    row = lan.leases()[0]
    assert row.static and row.name == "Телефон" and row.expires is None
