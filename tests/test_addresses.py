"""
Тесты логики IP → Addresses без доступа к ядру:
netlink подменяется фейком, конфиг пишется во временную папку.
"""
import pytest
import yaml

from app.core.store import ConfigStore
from app.models.address import AddressCreate, AddressUpdate
from app.services import addresses as svc


class FakeKernel:
    def __init__(self):
        self.links = {"lo", "eth0", "eth1"}
        self.addrs = {("eth0", "172.18.0.2/16")}  # «докеровский» — станет динамическим

    def link_names(self):
        return set(self.links)

    def kernel_ipv4_addresses(self):
        return list(self.addrs)

    def addr_add(self, ifname, cidr):
        self.addrs.add((ifname, cidr))

    def addr_del(self, ifname, cidr):
        self.addrs.discard((ifname, cidr))


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / "router.yaml"
    cfg.write_text(yaml.safe_dump({"ip": {"addresses": [
        {"address": "192.168.88.1/24", "interface": "eth1"},  # без id — как в исходном конфиге
    ]}}))
    store = ConfigStore(str(cfg), str(tmp_path / "data"))
    kernel = FakeKernel()
    monkeypatch.setattr(svc, "store", store)
    for name in ("link_names", "kernel_ipv4_addresses", "addr_add", "addr_del"):
        monkeypatch.setattr(svc.netlink, name, getattr(kernel, name))
    return store, kernel, tmp_path


def test_startup_applies_and_assigns_ids(env):
    store, kernel, _ = env
    svc.apply_all(wait_seconds=0)
    assert ("eth1", "192.168.88.1/24") in kernel.addrs
    assert store.load()["ip"]["addresses"][0]["id"] == 1


def test_print_shows_dynamic(env):
    svc.apply_all(wait_seconds=0)
    rows = svc.list_addresses()
    static = [r for r in rows if not r.dynamic]
    dynamic = [r for r in rows if r.dynamic]
    assert static[0].address == "192.168.88.1/24" and static[0].network == "192.168.88.0"
    assert not static[0].invalid
    assert dynamic[0].address == "172.18.0.2/16" and dynamic[0].id is None


def test_add_and_remove(env):
    store, kernel, tmp = env
    a = svc.add_address(AddressCreate(address="10.0.0.1/30", interface="eth0", comment="link"))
    assert a.id == 2
    assert ("eth0", "10.0.0.1/30") in kernel.addrs
    assert len(store.load()["ip"]["addresses"]) == 2
    assert list((tmp / "data" / "snapshots").glob("*.yaml"))  # снимок до изменения

    svc.remove_address(a.id)
    assert ("eth0", "10.0.0.1/30") not in kernel.addrs
    assert len(store.load()["ip"]["addresses"]) == 1


def test_disable_enable(env):
    _, kernel, _ = env
    svc.apply_all(wait_seconds=0)
    svc.update_address(1, AddressUpdate(disabled=True))
    assert ("eth1", "192.168.88.1/24") not in kernel.addrs
    svc.update_address(1, AddressUpdate(disabled=False))
    assert ("eth1", "192.168.88.1/24") in kernel.addrs


def test_errors(env):
    with pytest.raises(svc.AddressError) as e:
        svc.add_address(AddressCreate(address="1.1.1.1/24", interface="eth9"))
    assert e.value.status == 400
    with pytest.raises(svc.AddressError) as e:
        svc.add_address(AddressCreate(address="192.168.88.1/24", interface="eth1"))
    assert e.value.status == 409
    with pytest.raises(svc.AddressError) as e:
        svc.remove_address(99)
    assert e.value.status == 404


def test_validation():
    assert AddressCreate(address="10.1.1.1", interface="eth0").address == "10.1.1.1/32"
    with pytest.raises(ValueError):
        AddressCreate(address="999.1.1.1/24", interface="eth0")
    with pytest.raises(ValueError):
        AddressCreate(address="fe80::1/64", interface="eth0")
