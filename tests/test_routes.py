"""
Тесты логики IP → Routes без доступа к ядру: netlink подменяется фейком.
Фейк ведёт себя как ядро: шлюз должен входить в подключённую сеть,
дубликат dst+metric через другой шлюз — ошибка.
"""
import ipaddress

import pytest
import yaml

from app.core.store import ConfigStore
from app.models.route import RouteCreate, RouteUpdate
from app.services import netlink
from app.services import routes as svc


class FakeKernel:
    def __init__(self):
        self.links = {"lo", "eth0", "eth1"}
        self.connected = {"eth0": "172.18.0.0/16", "eth1": "192.168.1.0/24"}
        self.routes = [
            {"dst": "0.0.0.0/0", "gateway": "172.18.0.1", "interface": "eth0", "metric": 0, "proto": 3},
            {"dst": "172.18.0.0/16", "gateway": None, "interface": "eth0", "metric": 0, "proto": 2},
            {"dst": "192.168.1.0/24", "gateway": None, "interface": "eth1", "metric": 0, "proto": 2},
        ]

    def link_names(self):
        return set(self.links)

    def kernel_ipv4_routes(self):
        return [dict(r) for r in self.routes]

    def route_add(self, dst, gateway=None, ifname=None, metric=1):
        if gateway:
            ifname = next((i for i, net in self.connected.items()
                           if ipaddress.ip_address(gateway) in ipaddress.ip_network(net)), None)
            if not ifname:
                raise netlink.NetlinkOpError(f"шлюз {gateway} недоступен")
        for r in self.routes:
            if r["dst"] == dst and r["metric"] == metric:
                if r["gateway"] == gateway and r["interface"] == ifname:
                    return
                raise netlink.NetlinkOpError("уже существует через другой шлюз")
        self.routes.append({"dst": dst, "gateway": gateway, "interface": ifname, "metric": metric, "proto": 4})

    def route_del(self, dst, gateway=None, ifname=None, metric=1):
        self.routes = [r for r in self.routes if not (
            r["dst"] == dst and r["metric"] == metric and
            (r["gateway"] == gateway if gateway else r["interface"] == ifname))]


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / "router.yaml"
    cfg.write_text(yaml.safe_dump({"ip": {"routes": [
        {"dst-address": "10.0.0.0/8", "gateway": "192.168.1.254"},  # без id и distance
    ]}}))
    store = ConfigStore(str(cfg), str(tmp_path / "data"))
    kernel = FakeKernel()
    monkeypatch.setattr(svc, "store", store)
    for name in ("link_names", "kernel_ipv4_routes", "route_add", "route_del"):
        monkeypatch.setattr(svc.netlink, name, getattr(kernel, name))
    return store, kernel


def _routes(kernel, dst):
    return [r for r in kernel.routes if r["dst"] == dst]


def test_startup_applies(env):
    store, kernel = env
    svc.apply_all()
    assert _routes(kernel, "10.0.0.0/8")[0]["gateway"] == "192.168.1.254"
    e = store.load()["ip"]["routes"][0]
    assert e["id"] == 1 and e["distance"] == 1


def test_print_flags(env):
    svc.apply_all()
    rows = {r.dst_address: r for r in svc.list_routes()}
    assert rows["10.0.0.0/8"].static and rows["10.0.0.0/8"].active
    assert rows["10.0.0.0/8"].interface == "eth1"
    assert rows["0.0.0.0/0"].dynamic and not rows["0.0.0.0/0"].connected
    assert rows["192.168.1.0/24"].connected


def test_default_route_backup(env):
    """Резервный default с distance=10 рядом с докеровским (metric 0)."""
    _, kernel = env
    r = svc.add_route(RouteCreate(gateway="192.168.1.1", distance=10, comment="backup"))
    assert r.dst_address == "0.0.0.0/0"
    assert len(_routes(kernel, "0.0.0.0/0")) == 2


def test_unreachable_gateway_rejected(env):
    store, _ = env
    with pytest.raises(svc.RouteError) as e:
        svc.add_route(RouteCreate(dst_address="8.8.8.0/24", gateway="10.99.99.1"))
    assert e.value.status == 400
    assert len(store.load()["ip"]["routes"]) == 1  # конфиг не изменился


def test_interface_gateway(env):
    _, kernel = env
    svc.add_route(RouteCreate(dst_address="172.16.0.0/12", gateway="eth1"))
    assert _routes(kernel, "172.16.0.0/12")[0]["interface"] == "eth1"
    with pytest.raises(svc.RouteError) as e:
        svc.add_route(RouteCreate(dst_address="172.20.0.0/16", gateway="wg9"))
    assert e.value.status == 400


def test_disable_change_remove(env):
    _, kernel = env
    svc.apply_all()
    svc.update_route(1, RouteUpdate(disabled=True))
    assert not _routes(kernel, "10.0.0.0/8")
    svc.update_route(1, RouteUpdate(disabled=False, distance=5))
    assert _routes(kernel, "10.0.0.0/8")[0]["metric"] == 5
    # неудачная смена шлюза — откат к старому
    with pytest.raises(svc.RouteError):
        svc.update_route(1, RouteUpdate(gateway="10.99.99.1"))
    assert _routes(kernel, "10.0.0.0/8")[0]["gateway"] == "192.168.1.254"
    svc.remove_route(1)
    assert not _routes(kernel, "10.0.0.0/8")


def test_duplicate_and_validation(env):
    svc.apply_all()
    with pytest.raises(svc.RouteError) as e:
        svc.add_route(RouteCreate(dst_address="10.1.2.3/8", gateway="192.168.1.254"))
    assert e.value.status == 409  # 10.1.2.3/8 нормализуется в 10.0.0.0/8
    with pytest.raises(ValueError):
        RouteCreate(dst_address="10.0.0.0/33", gateway="1.1.1.1")
    with pytest.raises(ValueError):
        RouteCreate(gateway="bad gateway!")
    assert RouteCreate(dst_address="default", gateway="eth0").dst_address == "0.0.0.0/0"
