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
    a = seg(dhcp_options={"ntp_servers": ["192.168.88.1"], "tftp_server": "tftp.office.lan",
                          "boot_file": "cfg$mac.xml", "tftp_servers_150": ["192.168.88.5"],
                          "sip_servers": ["192.168.88.5"], "static_routes": ["10.0.0.0/8 via 192.168.88.254"],
                          "provisioning_url": "http://pbx/prov", "time_offset": 7200, "mtu": 1400,
                          "custom": [{"code": 224, "type": "uint16", "value": "443"}]})
    b = seg(id="lan2", name="Guests", address="10.20.0.1/24", ports=["eth3"], dns_enabled=False,
            domain="guest.lan", lease_time="1h")
    conf = dhcp.kea_conf([(a, [StaticLease(mac="00:0b:82:aa:bb:cc", ip="192.168.88.5", name="GXP1625"),
                               StaticLease(mac="00:0b:82:00:00:09", ip="10.20.0.99")]),     # чужая сеть — мимо
                          (b, [StaticLease(mac="00:0b:82:00:00:01", ip="10.20.0.9", name="Телефон")])],
                         ["1.1.1.1", "8.8.8.8"], "/d/leases.csv", "/d/sock")
    json.dumps(conf)                                              # сериализуется
    d = conf["Dhcp4"]
    assert d["interfaces-config"]["interfaces"] == ["br-lan", "br-lan2"]
    s1, s2 = d["subnet4"]
    assert (s1["id"], s1["subnet"], s1["interface"]) == (1, "192.168.88.0/24", "br-lan")
    assert s1["pools"] == [{"pool": "192.168.88.10 - 192.168.88.254"}] and s1["valid-lifetime"] == 43200
    opts = {o.get("name") or o["code"]: o["data"] for o in s1["option-data"]}
    assert opts["routers"] == "192.168.88.1" and opts["domain-name-servers"] == "192.168.88.1"
    assert opts["domain-name"] == "office.lan" and opts["domain-search"] == "office.lan"
    assert opts["ntp-servers"] == "192.168.88.1" and opts["tftp-server-name"] == "tftp.office.lan"
    assert opts["boot-file-name"] == "cfg$mac.xml" and opts["time-offset"] == "7200" and opts["interface-mtu"] == "1400"
    assert opts[150] == "c0a85805" and opts[120] == "01c0a85805"
    assert opts[121] == opts[249] == "080ac0a858fe"
    assert opts[160] == b"http://pbx/prov".hex() and opts[224] == "01bb"
    raw = [o for o in s1["option-data"] if "code" in o]
    assert all(o["csv-format"] is False and o["space"] == "dhcp4" for o in raw)
    # закреплённый адрес — только в своей подсети; кириллическое имя не уходит как hostname
    assert s1["reservations"] == [{"hw-address": "00:0b:82:aa:bb:cc", "ip-address": "192.168.88.5", "hostname": "GXP1625"}]
    assert s2["reservations"] == [{"hw-address": "00:0b:82:00:00:01", "ip-address": "10.20.0.9"}]
    # DNS на сегменте выключен — клиенты получают DNS провайдера
    o2 = {o.get("name"): o["data"] for o in s2["option-data"] if "name" in o}
    assert o2["domain-name-servers"] == "1.1.1.1, 8.8.8.8" and s2["valid-lifetime"] == 3600
    assert d["ddns-send-updates"] is False and d["lease-database"]["name"] == "/d/leases.csv"


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
    assert DhcpOptions(vendor_43="01:04:C0:A8:58:05").vendor_43 == "0104c0a85805"
    assert CustomOption(code=200, type="bool", value="yes").hex() == "01"
    assert CustomOption(code=200, type="uint32", value="0x10").hex() == "00000010"


def test_read_leases_and_migration(tmp_path, monkeypatch):
    monkeypatch.setattr(dhcp, "_data", lambda n: tmp_path / n)
    (tmp_path / "dnsmasq.leases").write_text(
        "4102444800 00:0b:82:aa:bb:cc 192.168.88.20 GXP1625 *\n"
        "0 da:a1:19:00:11:22 10.20.0.7 * *\n"
        "4102444800 da:a1:19:00:11:23 172.31.0.5 x *\n")                    # не в сегментах — пропуск
    segs = [(seg(), []), (seg(id="lan2", address="10.20.0.1/24", ports=["eth3"]), [])]
    dhcp.migrate_dnsmasq_leases(segs)
    assert not (tmp_path / "dnsmasq.leases").exists()
    rows = dhcp.read_leases({1: "lan1", 2: "lan2"}, now=1_800_000_000)
    assert [(r.ip, r.lan, r.hostname) for r in rows] == [("10.20.0.7", "lan2", None), ("192.168.88.20", "lan1", "GXP1625")]
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
            DnsRecord(name="pbx", type="A", value="192.168.88.5"),
            DnsRecord(name="www", type="CNAME", value="pbx"),
            DnsRecord(name="@", type="MX", value="mail.example.com.", priority=5),
            DnsRecord(name="_sip._udp", type="SRV", value="pbx", port=5060),
            DnsRecord(name="laptop", type="A", value="192.168.88.77", comment="вручную важнее DHCP")]),
        DnsZone(name="guest.lan", dhcp_names=False),
        DnsZone(name="88.168.192.in-addr.arpa", records=[DnsRecord(name="5", type="PTR", value="pbx.office.lan.")]),
    ])


def test_auto_names_and_ptr():
    cfg = dns_cfg()
    segs = [seg(), seg(id="lan2", address="10.20.0.1/24", ports=["eth3"], domain="guest.lan")]
    leases = [Lease(ip="192.168.88.20", mac="aa:aa:aa:aa:aa:01", hostname="Laptop"),        # имя занято записью
              Lease(ip="192.168.88.21", mac="aa:aa:aa:aa:aa:02", hostname="printer"),
              Lease(ip="192.168.88.22", mac="aa:aa:aa:aa:aa:03", hostname="bad_name!"),
              Lease(ip="10.20.0.50", mac="aa:aa:aa:aa:aa:04", hostname="guestphone")]       # dhcp_names выключены
    static = {"lan1": [StaticLease(mac="00:0b:82:aa:bb:cc", ip="192.168.88.6", name="gxp")]}
    auto = dns.auto_names(cfg, segs, leases, static)
    got = {(a.zone, a.name, a.type, a.value, a.source) for a in auto}
    assert ("office.lan", "router", "A", "192.168.88.1", "router") in got
    assert ("office.lan", "printer", "A", "192.168.88.21", "dhcp") in got
    assert ("office.lan", "gxp", "A", "192.168.88.6", "static-lease") in got
    assert not any(a.name == "laptop" for a in auto)                     # своя запись важнее
    assert not any(a.name == "guestphone" for a in auto)
    assert ("guest.lan", "router", "A", "10.20.0.1", "router") in got
    ptr = {(a.name, a.value) for a in auto if a.type == "PTR"}
    assert ("21", "printer.office.lan.") in ptr and ("77", "laptop.office.lan.") in ptr
    assert not any(n == "5" for n, _ in ptr)                             # PTR 5 задан вручную


def test_named_conf_and_zone_files(tmp_path, monkeypatch):
    monkeypatch.setattr(dns, "zone_dir", lambda: tmp_path)
    cfg = dns_cfg()
    segs = [seg(), seg(id="lan2", address="10.20.0.1/24", ports=["eth3"], domain="guest.lan", dns_enabled=False)]
    auto = dns.auto_names(cfg, segs, [], {})
    files = dns.render(cfg, segs, auto, tmp_path)
    conf = files[tmp_path / "named.conf"]
    assert "listen-on port 53 { 127.0.0.1; 192.168.88.1; };" in conf          # lan2 — DNS выключен
    assert "acl trusted { 127.0.0.0/8; 192.168.88.0/24; 10.20.0.0/24; 10.8.0.0/24; };" in conf
    assert "forwarders { 9.9.9.9; };" in conf and "forward first;" in conf
    assert 'zone "88.168.192.in-addr.arpa"' in conf and "dnssec-validation no;" in conf
    assert conf.index("acl trusted") < conf.index("options {")
    z = files[tmp_path / "db.office.lan"]
    assert "$ORIGIN office.lan." in z and "@ IN NS ns.office.lan." in z
    assert "www IN CNAME pbx" in z and "@ IN MX 5 mail.example.com." in z
    assert "_sip._udp IN SRV 10 0 5060 pbx" in z and "laptop IN A 192.168.88.77 ; вручную важнее DHCP" in z
    assert "ns IN A 192.168.88.1 ; auto: router" in z
    r = files[tmp_path / "db.88.168.192.in-addr.arpa"]
    assert "@ IN NS localhost." in r and "5 IN PTR pbx.office.lan." in r and "77 IN PTR laptop.office.lan." in r

    # серийный номер меняется только при изменении содержимого
    for p, text in files.items():
        p.write_text(text)
    serial = json.loads(files[tmp_path / "serials.json"])["office.lan"]["serial"]
    again = dns.render(cfg, segs, auto, tmp_path)
    assert json.loads(again[tmp_path / "serials.json"])["office.lan"]["serial"] == serial
    cfg.zones[0].records.append(DnsRecord(name="new", type="A", value="192.168.88.9"))
    changed = dns.render(cfg, segs, dns.auto_names(cfg, segs, [], {}), tmp_path)
    assert json.loads(changed[tmp_path / "serials.json"])["office.lan"]["serial"] > serial
    assert f"( {serial} " in files[tmp_path / "db.office.lan"]


def test_named_conf_auto_forwarders(tmp_path, monkeypatch):
    from app.services import wan
    monkeypatch.setattr(wan, "resolv_file", lambda: tmp_path / "resolv")
    (tmp_path / "resolv").write_text("nameserver 1.1.1.1\nnameserver 127.0.0.11\nnameserver ::1\n")
    cfg = DnsConfig(forward_only=True, dnssec=True)
    assert dns.upstream(cfg) == ["1.1.1.1"]                     # loopback Docker не годится в forwarders
    conf = dns.named_conf(cfg, ["192.168.88.1"], ["192.168.88.0/24"], dns.upstream(cfg), "/d")
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
