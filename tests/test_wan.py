"""
Тесты WAN без ядра и без udhcpc: netlink и запуск DHCP-клиента подменяются.
"""
import ipaddress

import pytest
import yaml

from app.core.store import ConfigStore
from app.models.wan import WanConfig
from app.services import netlink, wan, wan_hook


class FakeKernel:
    def __init__(self):
        self.links = {"lo", "eth0", "eth1", "br-lan"}
        self.addrs = {("eth1", "172.18.0.2/16"), ("eth0", "172.19.0.2/16")}
        self.routes = [  # default от Docker идёт через eth1 — значит WAN = eth1
            {"dst": "0.0.0.0/0", "gateway": "172.18.0.1", "interface": "eth1", "metric": 0, "proto": 3},
        ]

    def link_names(self):
        return set(self.links)

    def link_info(self, ifname):
        return {"mac": "02:00:00:00:00:01", "link_up": True} if ifname in self.links else {}

    def link_set_up(self, ifname):
        pass

    def kernel_ipv4_addresses(self):
        return sorted(self.addrs)

    def kernel_ipv4_routes(self):
        return [dict(r) for r in self.routes]

    def addr_add(self, ifname, cidr):
        self.addrs.add((ifname, cidr))

    def addr_del(self, ifname, cidr):
        self.addrs.discard((ifname, cidr))

    def route_add(self, dst, gateway=None, ifname=None, metric=1, proto=4):
        nets = [ipaddress.ip_interface(a).network for i, a in self.addrs]
        if gateway and not any(ipaddress.ip_address(gateway) in n for n in nets):
            raise netlink.NetlinkOpError(f"шлюз {gateway} недоступен")
        out = next((i for i, a in self.addrs
                    if ipaddress.ip_address(gateway) in ipaddress.ip_interface(a).network), None)
        self.routes.append({"dst": dst, "gateway": gateway, "interface": out, "metric": metric, "proto": proto})

    def route_del(self, dst, gateway=None, ifname=None, metric=1):
        self.routes = [r for r in self.routes
                       if not (r["dst"] == dst and r["gateway"] == gateway and r["metric"] == metric)]


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / "router.yaml"
    cfg.write_text(yaml.safe_dump({"system": {"identity": "test"}}))
    store = ConfigStore(str(cfg), str(tmp_path / "data"))
    kernel = FakeKernel()
    monkeypatch.setattr(wan, "store", store)
    monkeypatch.setattr(wan, "state_file", lambda: tmp_path / "data" / "wan.json")
    monkeypatch.setattr(wan, "resolv_file", lambda: tmp_path / "data" / "resolv.wan")
    from app.services import lan, vpn
    monkeypatch.setattr(lan, "on_wan_changed", lambda: None)
    monkeypatch.setattr(vpn, "on_wan_changed", lambda: None)
    monkeypatch.setattr(vpn, "refresh_endpoint_route", lambda: None)
    monkeypatch.setattr(vpn, "dns_override", lambda: [])
    for name in ("link_names", "link_info", "link_set_up", "kernel_ipv4_addresses",
                 "kernel_ipv4_routes", "addr_add", "addr_del", "route_add", "route_del"):
        monkeypatch.setattr(netlink, name, getattr(kernel, name))
    started = []
    monkeypatch.setattr(wan, "start_dhcp", lambda ifname, wid="wan1": started.append(ifname))
    return store, kernel, started


def test_detect_by_default_route(env):
    assert wan.detect_interface() == "eth1"
    assert "br-lan" not in wan.candidates() and "lo" not in wan.candidates()


def test_startup_fixes_interface(env):
    store, _, _ = env
    wan.apply_startup()
    assert store.load()["wan"] == {"interface": "eth1", "mode": "none"}


def test_static_apply_and_switch_back(env):
    store, kernel, _ = env
    cfg = WanConfig(interface="eth1", mode="static", address="172.18.0.50/16",
                    gateway="172.18.0.1", dns=["1.1.1.1"])
    st = wan.update(cfg)
    assert ("eth1", "172.18.0.50/16") in kernel.addrs
    assert any(r["metric"] == wan.WAN_METRIC and r["gateway"] == "172.18.0.1" for r in kernel.routes)
    assert st.dns == ["1.1.1.1"] and st.dhcp_state == "static"
    assert store.load()["wan"]["mode"] == "static"

    wan.update(WanConfig(interface="eth1", mode="none"))
    assert ("eth1", "172.18.0.50/16") not in kernel.addrs                # своё убрали
    assert ("eth1", "172.18.0.2/16") in kernel.addrs                     # чужое не тронули
    assert not any(r["metric"] == wan.WAN_METRIC for r in kernel.routes)


def test_failed_static_rolls_back(env, monkeypatch):
    store, kernel, _ = env
    before = set(kernel.addrs)

    def broken_route_add(*a, **k):  # имитация ошибки ядра при установке шлюза
        raise netlink.NetlinkOpError("сбой")
    monkeypatch.setattr(netlink, "route_add", broken_route_add)
    with pytest.raises(wan.WanError):
        wan.update(WanConfig(interface="eth1", mode="static", address="10.9.9.2/24", gateway="10.9.9.1"))
    assert kernel.addrs == before            # адрес откатили
    assert "wan" not in store.load()         # конфиг не изменился


def test_dhcp_mode_starts_client(env):
    store, _, started = env
    wan.update(WanConfig(interface="eth1", mode="dhcp"))
    assert started == ["eth1"]
    assert wan.load_state()["state"] == "searching"


def test_hook_bound_and_deconfig(env):
    _, kernel, _ = env
    wan.save_state({"interface": "eth0", "mode": "dhcp", "state": "searching"})
    lease = {"interface": "eth0", "ip": "192.168.122.50", "subnet": "255.255.255.0",
             "router": "192.168.122.1", "dns": "192.168.122.1 8.8.8.8", "lease": "3600"}
    wan_hook.handle("bound", lease)
    assert ("eth0", "192.168.122.50/24") in kernel.addrs
    assert any(r["gateway"] == "192.168.122.1" and r["proto"] == netlink.RTPROT_DHCP for r in kernel.routes)
    st = wan.load_state()
    assert st["state"] == "bound" and st["dns"] == ["192.168.122.1", "8.8.8.8"]
    assert "nameserver 192.168.122.1" in wan.resolv_file().read_text()   # для dnsmasq

    wan_hook.handle("renew", {**lease, "ip": "192.168.122.77"})          # адрес сменился
    assert ("eth0", "192.168.122.50/24") not in kernel.addrs
    assert ("eth0", "192.168.122.77/24") in kernel.addrs

    wan_hook.handle("deconfig", {"interface": "eth0"})
    assert ("eth0", "192.168.122.77/24") not in kernel.addrs
    assert not any(r["gateway"] == "192.168.122.1" for r in kernel.routes)
    assert wan.load_state()["state"] == "searching"


def test_validation():
    with pytest.raises(ValueError, match="нужны"):
        WanConfig(mode="static", address="10.0.0.2/24")
    with pytest.raises(ValueError, match="не входит"):
        WanConfig(mode="static", address="10.0.0.2/24", gateway="10.0.1.1")
    with pytest.raises(ValueError, match="маску"):
        WanConfig(mode="static", address="10.0.0.2", gateway="10.0.0.1")
    with pytest.raises(ValueError):
        WanConfig(mode="dhcp", dns=["8.8.8.888"])
    assert WanConfig(mode="dhcp", dns=["1.1.1.1", ""]).dns == ["1.1.1.1"]
