"""Kea (конфиг, опции, аренды) и BIND (named.conf, зоны, имена из DHCP, PTR) — без самих демонов."""
import json

import pytest
from pydantic import ValidationError

from app.models.dns import DnsConfig, DnsRecord, DnsZone, reverse_network, reverse_zone_for
from app.models.lan import CustomOption, DhcpOptions, LanConfig, Lease, StaticLease
from app.services import dhcp, dns, firewall


def seg(**kw):
    return LanConfig(enabled=True, **kw)


# --- Kea ---------------------------------------------------------------------------------------
def test_kea_conf_two_segments():
    a = seg(dhcp_options={"ntp_servers": ["192.168.1.1"], "tftp_server": "tftp.office.lan",
                          "boot_file": "cfg$mac.xml", "tftp_servers_150": ["192.168.1.5"],
                          "sip_servers": ["192.168.1.5"], "static_routes": ["10.0.0.0/8 via 192.168.1.254"],
                          "provisioning_url": "http://pbx/prov", "time_offset": 7200, "mtu": 1400,
                          "custom": [{"code": 224, "type": "uint16", "value": "443"}]})
    b = seg(id="lan2", name="Guests", address="10.20.0.1/24", ports=["eth3"], dns_enabled=False,
            domain="guest.lan", lease_time="1h")
    conf = dhcp.kea_conf([(a, [StaticLease(mac="00:0b:82:aa:bb:cc", ip="192.168.1.5", name="GXP1625"),
                               StaticLease(mac="00:0b:82:00:00:09", ip="10.20.0.99")]),     # чужая сеть — мимо
                          (b, [StaticLease(mac="00:0b:82:00:00:01", ip="10.20.0.9", name="Телефон")])],
                         ["1.1.1.1", "8.8.8.8"], "/var/lib/kea/kea-leases4.csv")
    json.dumps(conf)                                              # сериализуется
    d = conf["Dhcp4"]
    assert d["interfaces-config"]["interfaces"] == ["br-lan", "br-lan2"]
    s1, s2 = d["subnet4"]
    assert (s1["id"], s1["subnet"], s1["interface"]) == (1, "192.168.1.0/24", "br-lan")
    assert s1["pools"] == [{"pool": "192.168.1.10 - 192.168.1.254"}] and s1["valid-lifetime"] == 43200
    opts = {o.get("name") or o["code"]: o["data"] for o in s1["option-data"]}
    assert opts["routers"] == "192.168.1.1" and opts["domain-name-servers"] == "192.168.1.1"
    assert opts["domain-name"] == "office.lan" and opts["domain-search"] == "office.lan"
    assert opts["ntp-servers"] == "192.168.1.1" and opts["tftp-server-name"] == "tftp.office.lan"
    assert opts["boot-file-name"] == "cfg$mac.xml" and opts["time-offset"] == "7200" and opts["interface-mtu"] == "1400"
    assert opts[150] == "c0a80105" and opts[120] == "01c0a80105"
    assert opts[121] == opts[249] == "080ac0a801fe"
    assert opts[160] == b"http://pbx/prov".hex() and opts[224] == "01bb"
    raw = [o for o in s1["option-data"] if "code" in o]
    assert all(o["csv-format"] is False and o["space"] == "dhcp4" for o in raw)
    # закреплённый адрес — только в своей подсети; кириллическое имя не уходит как hostname
    assert s1["reservations"] == [{"hw-address": "00:0b:82:aa:bb:cc", "ip-address": "192.168.1.5", "hostname": "GXP1625"}]
    assert s2["reservations"] == [{"hw-address": "00:0b:82:00:00:01", "ip-address": "10.20.0.9"}]
    # DNS на сегменте выключен — клиенты получают DNS провайдера
    o2 = {o.get("name"): o["data"] for o in s2["option-data"] if "name" in o}
    assert o2["domain-name-servers"] == "1.1.1.1, 8.8.8.8" and s2["valid-lifetime"] == 3600
    assert d["ddns-send-updates"] is False and d["lease-database"]["name"] == "/var/lib/kea/kea-leases4.csv"
    assert "control-socket" not in d                 # Kea 2.6.3+: сокет только в /run/kea — он не нужен



def test_dhcp_option_validation():
    with pytest.raises(ValidationError):
        DhcpOptions(dns_servers=["300.1.1.1"])
    with pytest.raises(ValidationError):
        DhcpOptions(static_routes=["10.0.0.0/8"])
    with pytest.raises(ValidationError):
        DhcpOptions(custom=[{"code": 3, "type": "ip", "value": "1.1.1.1"}])       # роутер задаёт сам
    with pytest.raises(ValidationError):
        DhcpOptions(custom=[{"code": 200, "type": "uint8", "value": "300"}])
    with pytest.raises(ValidationError):
        DhcpOptions(custom=[{"code": 200, "type": "text", "value": "a"}, {"code": 200, "type": "text", "value": "b"}])
    with pytest.raises(ValidationError):
        DhcpOptions(tftp_server='bad"name')
    assert DhcpOptions(vendor_43="01:04:C0:A8:01:05").vendor_43 == "0104c0a80105"
    assert CustomOption(code=200, type="bool", value="yes").hex() == "01"
    assert CustomOption(code=200, type="uint32", value="0x10").hex() == "00000010"


def test_read_leases_and_migration(tmp_path, monkeypatch):
    monkeypatch.setattr(dhcp, "_data", lambda n: tmp_path / n)
    (tmp_path / "dnsmasq.leases").write_text(
        "4102444800 00:0b:82:aa:bb:cc 192.168.1.20 GXP1625 *\n"
        "0 da:a1:19:00:11:22 10.20.0.7 * *\n"
        "4102444800 da:a1:19:00:11:23 172.31.0.5 x *\n")                    # не в сегментах — пропуск
    segs = [(seg(), []), (seg(id="lan2", address="10.20.0.1/24", ports=["eth3"]), [])]
    dhcp.migrate_dnsmasq_leases(segs)
    assert not (tmp_path / "dnsmasq.leases").exists()
    assert b"\r" not in dhcp.leases_file().read_bytes()           # Kea не принимает \r\n
    rows = dhcp.read_leases({1: "lan1", 2: "lan2"}, now=1_800_000_000)
    assert [(r.ip, r.lan, r.hostname) for r in rows] == [("10.20.0.7", "lan2", None), ("192.168.1.20", "lan1", "GXP1625")]
    dhcp.migrate_dnsmasq_leases(segs)                                         # второй раз — ничего


# --- DNS -----------------------------------------------------------------------------------------
def test_record_validation():
    assert DnsRecord(name="mail", type="mx", value="mx1").rdata() == "10 mx1"
    with pytest.raises(ValidationError):
        DnsRecord(name="@", type="CNAME", value="x")
    with pytest.raises(ValidationError):
        DnsRecord(name="www", type="A", value="::1")
    with pytest.raises(ValidationError):
        DnsRecord(name="bad name", type="A", value="1.1.1.1")
    with pytest.raises(ValidationError):
        DnsRecord(name="_sip._tcp", type="SRV", value="pbx")                # нет порта
    with pytest.raises(ValidationError):
        DnsZone(name="corp.local")
    with pytest.raises(ValidationError):
        DnsConfig(zones=[{"name": "a.lan"}, {"name": "A.lan."}])
    long_txt = DnsRecord(name="@", type="TXT", value="x" * 300).rdata()
    assert long_txt.count('"') == 4                                             # две строки по ≤255
    assert reverse_zone_for("10.20.0.0/16") == "20.10.in-addr.arpa"
    assert str(reverse_network("20.10.in-addr.arpa")) == "10.20.0.0/16"


def dns_cfg():
    return DnsConfig(forwarders=["9.9.9.9"], allow=["10.8.0.0/24"], zones=[
        DnsZone(name="office.lan", records=[
            DnsRecord(name="pbx", type="A", value="192.168.1.5"),
            DnsRecord(name="www", type="CNAME", value="pbx"),
            DnsRecord(name="@", type="MX", value="mail.example.com.", priority=5),
            DnsRecord(name="_sip._udp", type="SRV", value="pbx", port=5060),
            DnsRecord(name="laptop", type="A", value="192.168.1.77", comment="вручную важнее DHCP")]),
        DnsZone(name="guest.lan", dhcp_names=False),
        DnsZone(name="1.168.192.in-addr.arpa", records=[DnsRecord(name="5", type="PTR", value="pbx.office.lan.")]),
    ])


def test_auto_names_and_ptr():
    cfg = dns_cfg()
    segs = [seg(), seg(id="lan2", address="10.20.0.1/24", ports=["eth3"], domain="guest.lan")]
    leases = [Lease(ip="192.168.1.20", mac="aa:aa:aa:aa:aa:01", hostname="Laptop"),        # имя занято записью
              Lease(ip="192.168.1.21", mac="aa:aa:aa:aa:aa:02", hostname="printer"),
              Lease(ip="192.168.1.22", mac="aa:aa:aa:aa:aa:03", hostname="bad_name!"),
              Lease(ip="10.20.0.50", mac="aa:aa:aa:aa:aa:04", hostname="guestphone")]       # dhcp_names выключены
    static = {"lan1": [StaticLease(mac="00:0b:82:aa:bb:cc", ip="192.168.1.6", name="gxp")]}
    auto = dns.auto_names(cfg, segs, leases, static)
    got = {(a.zone, a.name, a.type, a.value, a.source) for a in auto}
    assert ("office.lan", "router", "A", "192.168.1.1", "router") in got
    assert ("office.lan", "printer", "A", "192.168.1.21", "dhcp") in got
    assert ("office.lan", "gxp", "A", "192.168.1.6", "static-lease") in got
    assert not any(a.name == "laptop" for a in auto)                     # своя запись важнее
    assert not any(a.name == "guestphone" for a in auto)
    assert ("guest.lan", "router", "A", "10.20.0.1", "router") in got
    ptr = {(a.name, a.value) for a in auto if a.type == "PTR"}
    assert ("21", "printer.office.lan.") in ptr and ("77", "laptop.office.lan.") in ptr
    assert not any(n == "5" for n, _ in ptr)                             # PTR 5 задан вручную


def test_hidden_auto_names():
    """Скрытые имена (DHCP, router) не попадают ни в зону, ни в обратную зону; ns скрыть нельзя."""
    cfg = dns_cfg()
    cfg.zones[0].hidden = ["Printer", "router"]
    cfg = DnsConfig.model_validate(cfg.model_dump())
    assert cfg.zones[0].hidden == ["printer", "router"]
    segs = [seg()]
    leases = [Lease(ip="192.168.1.21", mac="aa:aa:aa:aa:aa:02", hostname="printer"),
              Lease(ip="192.168.1.23", mac="aa:aa:aa:aa:aa:05", hostname="nas")]
    auto = dns.auto_names(cfg, segs, leases, {})
    names = {(a.zone, a.name) for a in auto}
    assert ("office.lan", "nas") in names and ("office.lan", "ns") in names
    assert ("office.lan", "printer") not in names and ("office.lan", "router") not in names
    assert not any(a.type == "PTR" and a.value.startswith("printer.") for a in auto)
    body = dns.zone_file(cfg.zones[0], [a for a in auto if a.zone == "office.lan"], 1, "192.168.1.1")
    assert "printer" not in body and "\nns IN A" in body
    with pytest.raises(ValueError):
        DnsZone(name="office.lan", hidden=["ns"])


def test_named_conf_and_zone_files(tmp_path, monkeypatch):
    monkeypatch.setattr(dns, "zone_dir", lambda: tmp_path)
    cfg = dns_cfg()
    segs = [seg(), seg(id="lan2", address="10.20.0.1/24", ports=["eth3"], domain="guest.lan", dns_enabled=False)]
    auto = dns.auto_names(cfg, segs, [], {})
    files = dns.render(cfg, segs, auto, tmp_path)
    conf = files[tmp_path / "named.conf"]
    assert "listen-on port 53 { 127.0.0.1; 192.168.1.1; };" in conf          # lan2 — DNS выключен
    assert "acl trusted { 127.0.0.0/8; 192.168.1.0/24; 10.20.0.0/24; 10.8.0.0/24; };" in conf
    assert "forwarders { 9.9.9.9; };" in conf and "forward first;" in conf
    assert 'zone "1.168.192.in-addr.arpa"' in conf and "dnssec-validation no;" in conf
    assert conf.index("acl trusted") < conf.index("options {")
    z = files[tmp_path / "db.office.lan"]
    assert "$ORIGIN office.lan." in z and "@ IN NS ns.office.lan." in z
    assert "www IN CNAME pbx" in z and "@ IN MX 5 mail.example.com." in z
    assert "_sip._udp IN SRV 10 0 5060 pbx" in z and "laptop IN A 192.168.1.77 ; вручную важнее DHCP" in z
    assert "ns IN A 192.168.1.1 ; auto: router" in z
    r = files[tmp_path / "db.1.168.192.in-addr.arpa"]
    assert "@ IN NS localhost." in r and "5 IN PTR pbx.office.lan." in r and "77 IN PTR laptop.office.lan." in r

    # серийный номер меняется только при изменении содержимого
    for p, text in files.items():
        p.write_text(text)
    serial = json.loads(files[tmp_path / "serials.json"])["office.lan"]["serial"]
    again = dns.render(cfg, segs, auto, tmp_path)
    assert json.loads(again[tmp_path / "serials.json"])["office.lan"]["serial"] == serial
    cfg.zones[0].records.append(DnsRecord(name="new", type="A", value="192.168.1.9"))
    changed = dns.render(cfg, segs, dns.auto_names(cfg, segs, [], {}), tmp_path)
    assert json.loads(changed[tmp_path / "serials.json"])["office.lan"]["serial"] > serial
    assert f"( {serial} " in files[tmp_path / "db.office.lan"]


def test_named_conf_auto_forwarders(tmp_path, monkeypatch):
    from app.services import wan
    monkeypatch.setattr(wan, "resolv_file", lambda: tmp_path / "resolv")
    (tmp_path / "resolv").write_text("nameserver 1.1.1.1\nnameserver 127.0.0.11\nnameserver ::1\n")
    cfg = DnsConfig(forward_only=True, dnssec=True)
    assert dns.upstream(cfg) == ["1.1.1.1"]                     # loopback Docker не годится в forwarders
    conf = dns.named_conf(cfg, ["192.168.1.1"], ["192.168.1.0/24"], dns.upstream(cfg), "/d")
    assert "forward only;" in conf and "dnssec-validation auto;" in conf
    assert "forwarders" not in dns.named_conf(cfg, [], [], [], "/d")


# --- фаервол с несколькими сегментами -------------------------------------------------------------
def test_firewall_multi_lan(tmp_path):
    import shutil
    import subprocess
    rs = firewall.ruleset("eth0", ["br-lan", "br-lan2"], False, firewall.VpnRules("wg0", False, False, True),
                          links=[("br-lan", "br-lan2")])
    assert 'iifname { "br-lan", "br-lan2" } oifname "eth0" accept' in rs
    assert 'iifname { "br-lan", "br-lan2" } oifname "wg0" accept' in rs
    assert 'iifname "wg0" oifname { "br-lan", "br-lan2" } accept' in rs
    assert 'iifname "br-lan" oifname "br-lan2" accept' in rs
    assert 'iifname "br-lan2" oifname "br-lan"' not in rs                 # обратно — только если разрешено
    text = firewall.system_rules("eth0", False, None, None, [("LAN", "Guests")])["forward"]
    assert "LAN → Guests — разрешено" in text
    if shutil.which("nft"):
        f = tmp_path / "rs.nft"
        f.write_text(rs)
        r = subprocess.run(["nft", "-c", "-f", str(f)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def test_kea_dirs(tmp_path, monkeypatch):
    """Kea 2.6.3+: аренды только в /var/lib/kea — это ссылка на data/kea; старый файл переезжает."""
    data, lib, run = tmp_path / "data", tmp_path / "var-lib-kea", tmp_path / "run-kea"
    data.mkdir()
    monkeypatch.setattr(dhcp, "_data", lambda n: data / n)
    monkeypatch.setattr(dhcp, "KEA_LIB", lib)
    monkeypatch.setattr(dhcp, "KEA_RUN", run)
    lib.mkdir()
    (lib / "kea-leases4.csv").write_text("from package\n")       # пакетная папка с файлом
    (data / "kea-leases4.csv").write_text("old stage-2 leases\n")
    dhcp._prepare_dirs()
    assert lib.is_symlink() and lib.resolve() == (data / "kea").resolve() and run.is_dir()
    assert dhcp.leases_file().read_text() == "old stage-2 leases\n"
    assert not (data / "kea-leases4.csv").exists()
    dhcp._prepare_dirs()                                           # повторно — ничего не ломает
    assert lib.is_symlink() and dhcp.leases_file().exists()


def test_kea_leases_crlf_repaired(tmp_path, monkeypatch):
    data = tmp_path / "data"
    (data / "kea").mkdir(parents=True)
    monkeypatch.setattr(dhcp, "_data", lambda n: data / n)
    monkeypatch.setattr(dhcp, "KEA_LIB", tmp_path / "lib")
    monkeypatch.setattr(dhcp, "KEA_RUN", tmp_path / "run")
    dhcp.leases_file().write_bytes(b"address,hwaddr,client_id\r\n")
    dhcp._prepare_dirs()
    assert dhcp.leases_file().read_bytes() == b"address,hwaddr,client_id\n"


def test_kea_rebinds_when_bridge_recreated(tmp_path, monkeypatch):
    """Мост пересоздан (новый ifindex) — Kea получает SIGHUP и заново открывает сокеты."""
    import signal as _signal
    from app.services import dhcp

    class FakeKea:
        def __init__(self):
            self.signals = []
        def running(self):
            return True
        def signal(self, sig):
            self.signals.append(sig)

    def link(name, idx):
        (tmp_path / name).mkdir(exist_ok=True)
        (tmp_path / name / "ifindex").write_text(f"{idx}\n")

    kea = FakeKea()
    monkeypatch.setattr(dhcp, "SYS_NET", tmp_path)
    monkeypatch.setattr(dhcp, "_kea", kea)
    link("br-lan", 5)
    monkeypatch.setattr(dhcp, "_ifindex", dhcp.ifindexes(["br-lan", "br-lan2"]))   # br-lan2 ещё нет
    assert dhcp._ifindex == {"br-lan": 5, "br-lan2": 0}
    assert dhcp.watch_interfaces() == [] and kea.signals == []

    link("br-lan", 87)                                     # пересоздан
    assert dhcp.watch_interfaces() == ["br-lan"] and kea.signals == [_signal.SIGHUP]
    assert dhcp.watch_interfaces() == []                   # второй раз — уже учтено

    (tmp_path / "br-lan" / "ifindex").unlink()             # моста временно нет — ничего не делаем
    assert dhcp.watch_interfaces() == []
    link("br-lan2", 88)                                    # появился позже Kea
    assert dhcp.watch_interfaces() == ["br-lan2"] and len(kea.signals) == 2
