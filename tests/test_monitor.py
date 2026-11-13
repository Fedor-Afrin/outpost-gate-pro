"""Мониторинг: история, разбор /proc и ping, учёт клиентов, Prometheus, SNMP, Zabbix, фаервол."""
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.store import ConfigStore
from app.models.lan import LanConfig
from app.models.monitoring import MonitoringConfig
from app.services import exporters, firewall, monitor


# --- история ----------------------------------------------------------------------------------
def test_history_buckets_and_average():
    h = monitor.History({"a": (10, 6), "b": (60, 3)})
    t0 = 1_000_000_020                     # кратно 10 и 60
    for i, v in enumerate([10, 20, 30, 40, 50, 60, 70]):
        h.add(t0 + i * 10, "cpu", v)
    h.add(t0, "cpu", None)                 # пропуск значения не ломает ряд
    s = h.series("cpu", "a", t0 + 60)
    assert s["step"] == 10 and s["values"] == [20, 30, 40, 50, 60, 70]   # 10 вытеснено кольцом
    b = h.series("cpu", "b", t0 + 60)
    assert b["values"][-2:] == [35.0, 70.0] and b["values"][0] is None
    assert h.series("nothing", "a", t0)["values"] == [None] * 6


def test_history_dump_load_roundtrip():
    h = monitor.History({"a": (10, 4)})
    h.add(100, "x", 1.5)
    raw = json.loads(json.dumps(h.dump()))
    h2 = monitor.History({"a": (10, 4)})
    h2.load(raw)
    assert h2.series("x", "a", 100)["values"][-1] == 1.5
    h3 = monitor.History({"a": (10, 5)})    # другая сетка — история не подхватывается
    h3.load(raw)
    assert h3.keys() == []


# --- источники --------------------------------------------------------------------------------
def test_cpu_memory_rate_ping():
    a = monitor.cpu_times("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4")
    b = monitor.cpu_times("cpu  150 0 150 900 0 0 0 0 0 0")
    assert a == (800, 1000) and monitor.cpu_percent(a, b) == 50.0
    assert monitor.cpu_percent(None, b) is None and monitor.cpu_times("") is None
    m = monitor.memory("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n")
    assert m == {"total": 1024000, "used": 768000, "percent": 75.0}
    assert monitor.rate(100, 300, 10) == 20.0
    assert monitor.rate(300, 100, 10) is None and monitor.rate(None, 5, 10) is None
    out = ("--- 8.8.8.8 ping statistics ---\n3 packets transmitted, 2 received, 33.3333% packet loss, time 602ms\n"
           "rtt min/avg/max/mdev = 11.2/12.5/13.9/1.1 ms\n")
    assert monitor.parse_ping(out) == (12.5, 33.3333)
    assert monitor.parse_ping("3 packets transmitted, 0 received, 100% packet loss") == (None, 100.0)


def test_interface_counters(tmp_path, monkeypatch):
    def iface(name, rx, tx, oper="up", carrier="1", speed="1000"):
        st = tmp_path / name / "statistics"
        st.mkdir(parents=True)
        for k, v in {"rx_bytes": rx, "tx_bytes": tx, "rx_errors": 1, "tx_errors": 0, "rx_dropped": 2, "tx_dropped": 0}.items():
            (st / k).write_text(f"{v}\n")
        (tmp_path / name / "operstate").write_text(oper)
        (tmp_path / name / "carrier").write_text(carrier)
        (tmp_path / name / "speed").write_text(speed)
        (tmp_path / name / "address").write_text("02:00:00:00:00:01")
    iface("eth0", 5000, 700)
    iface("eth2", 0, 0, oper="down", carrier="0", speed="-1")
    iface("lo", 1, 1)
    iface("veth12ab", 1, 1)
    iface("br-0123456789ab", 1, 1)     # мост Docker
    iface("br-lan", 10, 20, oper="up", speed="")
    monkeypatch.setattr(monitor, "SYS_NET", tmp_path)
    c = monitor.interface_counters()
    assert sorted(c) == ["br-lan", "eth0", "eth2"]
    assert c["eth0"]["rx_bytes"] == 5000 and c["eth0"]["up"] and c["eth0"]["speed"] == 1_000_000_000
    assert not c["eth2"]["up"] and c["eth2"]["speed"] is None and c["eth0"]["rx_dropped"] == 2


def test_accounting_ruleset_and_parse():
    t = monitor.acct_ruleset(["192.168.88.0/24", "10.30.0.0/24"])
    assert "table inet outpost_acct" in t and "policy accept" in t
    assert "ip saddr { 192.168.88.0/24, 10.30.0.0/24 } update @up { ip saddr counter }" in t
    assert "counter;" in monitor.acct_ruleset(["10.0.0.0/24"], variant=1)
    listing = """table inet outpost_acct {
        set up {
                type ipv4_addr
                size 4096
                flags dynamic
                elements = { 192.168.88.20 counter packets 10 bytes 1500, 192.168.88.21 counter packets 1 bytes 60 }
        }
}"""
    assert monitor.parse_acct(listing) == {"192.168.88.20": 1500, "192.168.88.21": 60}


# --- сборщик целиком (без системы: источники подменены) ----------------------------------------
@pytest.fixture
def fake(tmp_path, monkeypatch):
    seg1 = LanConfig(id="lan1", name="LAN", address="192.168.88.1/24", enabled=True)
    seg2 = LanConfig(id="lan2", name="Phones", address="10.30.0.1/24", vlan_id=30, trunk_ports=["eth1"], enabled=True)
    topo = {"roles": {"eth0": ("wan", "WAN"), "br-lan": ("lan", "LAN"), "br-lan2": ("lan", "Phones"),
                      "eth1": ("port", "LAN"), "eth1.30": ("vlan", "Phones"), "wg0": ("vpn", "WireGuard")},
            "wan": "eth0", "segments": [seg1, seg2], "nets": ["192.168.88.0/24", "10.30.0.0/24"]}
    state = {"if": {"eth0": 1000, "br-lan": 500}, "acct": ({"192.168.88.20": 100}, {"192.168.88.20": 1000})}

    def counters(names=None):
        return {n: {"rx_bytes": v, "tx_bytes": v // 2, "rx_errors": 0, "tx_errors": 1, "rx_dropped": 0,
                    "tx_dropped": 0, "up": True, "speed": None, "mac": None} for n, v in state["if"].items()}

    class Acct:
        ok, error = True, None
        def ensure(self, nets): self.nets = nets
        def read(self): return state["acct"]
        def remove(self): pass

    monkeypatch.setattr(monitor, "topology", lambda: topo)
    monkeypatch.setattr(monitor, "interface_counters", counters)
    monkeypatch.setattr(monitor, "ping", lambda t: (12.0, 0.0) if t == "1.1.1.1" else (None, 100.0))
    monkeypatch.setattr(monitor, "disks", lambda: [{"name": "data", "path": "/var/lib", "total": 100, "used": 40, "percent": 40.0}])
    monkeypatch.setattr(monitor, "get_config", lambda: MonitoringConfig(ping_targets=["1.1.1.1", "9.9.9.9"]))
    monkeypatch.setattr(monitor.Collector, "_collect_slow", lambda self, topo: {
        "leases": [{"ip": "192.168.88.20", "mac": "aa:aa:aa:aa:aa:01", "lan": "lan1", "name": "laptop"}],
        "dhcp": [{"id": "lan1", "name": "LAN", "leases": 1}, {"id": "lan2", "name": "Phones", "leases": 0}],
        "vpn": {"kind": "wireguard", "up": True},
        "routing": {"ospf_neighbors": 1, "bgp": [{"peer": "10.8.0.1", "remote_as": 65000, "description": "HQ",
                                                   "up": True, "state": "Established", "prefixes": 3}]},
        "smb_sessions": 2})
    import app.services.wan as wan
    monkeypatch.setattr(wan, "current_gateway", lambda: "203.0.113.1")
    monkeypatch.setattr(monitor, "_data", lambda *p: tmp_path.joinpath("monitor", *p))
    col = monitor.Collector()
    col.acct = Acct()
    return col, state, tmp_path


def test_collect_snapshot_rates_and_history(fake):
    col, state, tmp = fake
    col.collect(now=1_000_000_000)
    state["if"] = {"eth0": 11000, "br-lan": 1500}
    state["acct"] = ({"192.168.88.20": 600}, {"192.168.88.20": 21000})
    s = col.collect(now=1_000_000_010)
    eth0 = next(i for i in s["interfaces"] if i["name"] == "eth0")
    assert eth0["role"] == "wan" and eth0["rx_rate"] == 1000.0 and eth0["tx_rate"] == 500.0
    assert [i["name"] for i in s["interfaces"]][:2] == ["eth0", "br-lan"]
    assert s["wan"] == {"interface": "eth0", "up": True, "gateway": "203.0.113.1"}
    assert [(p["name"], p["target"]) for p in s["ping"]] == [("gateway", "203.0.113.1"), ("1.1.1.1", "1.1.1.1"), ("9.9.9.9", "9.9.9.9")]
    c = s["clients"][0]
    assert (c["ip"], c["name"], c["segment"], c["rx_rate"], c["tx_rate"]) == ("192.168.88.20", "laptop", "LAN", 2000.0, 50.0)
    hist = col.history.series("if:eth0:rx", "1h", 1_000_000_010)["values"]
    assert hist[-1] == 1000.0 and col.history.series("ping:1.1.1.1:rtt", "1h", 1_000_000_010)["values"][-1] == 12.0
    # файл для Zabbix agent
    cur = json.loads((tmp / "monitor" / "current.json").read_text())
    assert cur["values"]["if.rx:eth0"] == 1000.0 and cur["values"]["ping.loss:9.9.9.9"] == 100.0
    assert cur["values"]["vpn.up"] == 1 and cur["values"]["bgp.up"] == 1 and cur["values"]["dhcp.leases"] == 1
    assert {"{#IFNAME}": "eth1.30", "{#ROLE}": "vlan", "{#LABEL}": "Phones"} not in cur["discovery"]["if"]  # нет счётчиков — нет в списке
    assert {"{#IFNAME}": "eth0", "{#ROLE}": "wan", "{#LABEL}": "WAN"} in cur["discovery"]["if"]
    # сохранение истории и загрузка
    col.save()
    col2 = monitor.Collector()
    col2.load()
    assert col2.history.series("if:eth0:rx", "1h", 1_000_000_010)["values"][-1] == 1000.0


def test_zbx_script(fake, capsys):
    import runpy, sys
    col, state, tmp = fake
    col.collect(now=1_000_000_000)
    path = str(tmp / "monitor" / "current.json")
    script = Path(__file__).resolve().parent.parent / "app" / "scripts" / "zbx.py"
    mod = runpy.run_path(str(script))
    assert mod["main"](["zbx.py", path, "get", "wan.up"]) == 0
    assert mod["main"](["zbx.py", path, "get", "nope"]) == 1
    assert mod["main"](["zbx.py", path, "discovery", "ping"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "1" and json.loads(out[1])[0] == {"{#TARGET}": "203.0.113.1", "{#NAME}": "gateway"}


# --- Prometheus ---------------------------------------------------------------------------------
def test_prometheus_text(fake):
    col, state, _ = fake
    col.collect(now=1_000_000_000)
    t = exporters.prometheus_text(col.snapshot, 'office "main"', "0.2.0")
    assert 'og_info{identity="office \\"main\\"",version="0.2.0",mode="dev"} 1' in t
    assert 'og_interface_receive_bytes_total{interface="eth0",role="wan",label="WAN"} 1000' in t
    assert t.count("# TYPE og_interface_receive_bytes_total counter") == 1
    assert 'og_ping_rtt_seconds{target="1.1.1.1",name="1.1.1.1"} 0.012' in t
    assert 'og_ping_loss_ratio{target="9.9.9.9",name="9.9.9.9"} 1.0' in t
    assert 'og_client_receive_bytes_total{ip="192.168.88.20",name="laptop",mac="aa:aa:aa:aa:aa:01",segment="LAN"} 1000' in t
    assert 'og_bgp_peer_up{peer="10.8.0.1",remote_as="65000",description="HQ"} 1' in t
    assert 'og_vpn_up{type="wireguard"} 1' in t and "og_smb_sessions 2" in t
    assert 'og_dhcp_leases_active{segment="Phones",lan="lan2"} 0' in t
    assert "og_up 0" in exporters.prometheus_text({"time": None}, "x", "1")


def test_metrics_access():
    lan = ["192.168.88.0/24"]
    off = MonitoringConfig()
    assert exporters.metrics_access(off, "192.168.88.5", None, None, lan)[0] == 404
    on = MonitoringConfig(prometheus={"enabled": True, "allowed": ["10.0.0.5"]})
    assert exporters.metrics_access(on, "192.168.88.5", None, None, lan) is None
    assert exporters.metrics_access(on, "10.0.0.5", None, None, lan) is None
    assert exporters.metrics_access(on, "127.0.0.1", None, None, lan) is None
    assert exporters.metrics_access(on, "203.0.113.7", None, None, lan)[0] == 403
    assert exporters.metrics_access(on, "testclient", None, None, lan)[0] == 403
    tok = MonitoringConfig(prometheus={"enabled": True, "token": "s3cret-token-0123456789"})
    assert exporters.metrics_access(tok, "192.168.88.5", None, None, lan)[0] == 401
    assert exporters.metrics_access(tok, "192.168.88.5", "Bearer s3cret-token-0123456789", None, lan) is None
    assert exporters.metrics_access(tok, "192.168.88.5", None, "s3cret-token-0123456789", lan) is None
    assert exporters.metrics_access(tok, "192.168.88.5", "Bearer wrong", None, lan)[0] == 401


# --- настройки --------------------------------------------------------------------------------
def test_config_validation():
    c = MonitoringConfig.model_validate({"ping_targets": ["8.8.8.8", " 8.8.8.8", ""],
                                         "snmp": {"allowed": ["10.0.0.5", "10.1.0.0/16"]},
                                         "zabbix": {"enabled": True, "server": ["10.0.0.5"], "server_active": "zbx.lan:10051"}})
    assert c.ping_targets == ["8.8.8.8"] and c.snmp.allowed == ["10.0.0.5", "10.1.0.0/16"]
    bad = [
        {"ping_targets": ["google.com"]},
        {"ping_targets": ["1.1.1.%d" % i for i in range(6)]},
        {"prometheus": {"token": "short"}},
        {"prometheus": {"allowed": ["anywhere"]}},
        {"snmp": {"community": "with space"}},
        {"snmp": {"version": "v1"}},
        {"snmp": {"enabled": True, "version": "v3", "user": "zbx", "auth_password": "short", "priv_password": "longenough"}},
        {"snmp": {"enabled": True, "version": "v3", "auth_password": "longenough", "priv_password": "longenough"}},
        {"snmp": {"location": 'Office "A"'}},
        {"zabbix": {"enabled": True}},
        {"zabbix": {"server_active": "bad host!"}},
    ]
    for b in bad:
        with pytest.raises(ValidationError):
            MonitoringConfig.model_validate(b)


def test_snmpd_conf():
    c = MonitoringConfig(snmp={"enabled": True, "community": "office", "allowed": ["10.0.0.5"], "location": "Server room"})
    t = exporters.snmpd_conf(c, ["192.168.88.0/24"], "office")
    assert "agentAddress udp:161" in t and 'sysName "office"' in t and 'sysLocation "Server room"' in t
    assert "rocommunity office 192.168.88.0/24" in t and "rocommunity office 10.0.0.5" in t
    assert "rocommunity office 127.0.0.1" in t and "createUser" not in t
    v3 = MonitoringConfig(snmp={"enabled": True, "version": "v3", "user": "zbx",
                                "auth_password": "authpass1", "priv_password": "privpass1"})
    t = exporters.snmpd_conf(v3, ["192.168.88.0/24"], "office")
    assert 'createUser zbx SHA "authpass1" AES "privpass1"' in t and "rouser zbx priv" in t
    assert "rocommunity" not in t


def test_zabbix_conf(tmp_path):
    c = MonitoringConfig(zabbix={"enabled": True, "server": ["10.0.0.5", "10.0.1.0/24"], "server_active": "10.0.0.5",
                                 "metadata": "outpost"})
    t2 = exporters.zabbix_conf(c, "agent2", "office", tmp_path / "current.json")
    assert "Hostname=office" in t2 and "Server=10.0.0.5,10.0.1.0/24" in t2 and "ServerActive=10.0.0.5" in t2
    assert "HostMetadata=outpost" in t2 and "LogType=console" in t2 and "AllowRoot" not in t2
    assert f'zbx.py {tmp_path}/current.json get "$1"' in t2 and "UserParameter=outpost.discovery[*]" in t2
    td = exporters.zabbix_conf(MonitoringConfig(zabbix={"server_active": "zbx.lan", "hostname": "gw-1"}),
                               "agentd", "office", tmp_path / "current.json")
    assert "AllowRoot=1" in td and "Hostname=gw-1" in td and "Server=127.0.0.1" in td


@pytest.fixture
def env(tmp_path, monkeypatch):
    store = ConfigStore(tmp_path / "router.yaml", tmp_path / "snap")
    monkeypatch.setattr(exporters, "store", store)
    calls = []
    monkeypatch.setattr(exporters, "apply", lambda c=None: calls.append(c))
    monkeypatch.setattr(exporters, "status", lambda: exporters.get_config())
    monkeypatch.setattr(firewall, "refresh", lambda *a: calls.append("fw"))
    return store, calls


def test_update_keeps_snmp_passwords_and_rolls_back(env, monkeypatch):
    store, calls = env
    base = {"snmp": {"enabled": True, "version": "v3", "user": "zbx", "auth_password": "authpass1", "priv_password": "privpass1"}}
    exporters.update(base)
    assert calls[-1] == "fw" and store.load()["monitoring"]["snmp"]["auth_password"] == "authpass1"
    # форма присылает пароли пустыми (наружу их не отдаём) — старые сохраняются
    cfg = exporters.update({"snmp": {**base["snmp"], "auth_password": "", "priv_password": None, "location": "Rack 2"}})
    assert cfg.snmp.priv_password == "privpass1" and cfg.snmp.location == "Rack 2"
    assert exporters.masked(cfg).snmp.auth_password is None
    with pytest.raises(exporters.ExportError) as e:
        exporters.update({"zabbix": {"enabled": True}})
    assert e.value.status == 422 and "Zabbix server" in e.value.message

    def boom(c=None):
        raise exporters.ExportError(400, "snmpd не запустился")
    monkeypatch.setattr(exporters, "apply", boom)
    with pytest.raises(exporters.ExportError):
        exporters.update({"prometheus": {"enabled": True}})
    assert store.load()["monitoring"]["snmp"]["location"] == "Rack 2"   # откат


def test_firewall_monitor_rules(env):
    store, _ = env
    exporters.update({"prometheus": {"enabled": True, "allowed": ["10.0.0.5"]},
                      "snmp": {"enabled": True, "allowed": ["10.0.0.0/24"]},
                      "zabbix": {"enabled": True, "server": ["10.0.0.5"]}})
    rules = exporters.firewall_rules()
    assert ("udp", 161, ["10.0.0.0/24"], "SNMP") in rules and ("tcp", 10050, ["10.0.0.5"], "Zabbix agent") in rules
    rs = firewall.ruleset("eth0", "br-lan", False, firewall.VpnRules("wg0", True, False, False), monitor=rules)
    line = "ip saddr { 10.0.0.0/24 } udp dport 161 accept   # SNMP"
    assert line in rs and rs.index(line) < rs.index('iifname "wg0" drop')
    assert "tcp dport 8000 accept   # Prometheus /metrics" in rs
    text = firewall.system_rules("eth0", False, None, monitor=rules)["input"]
    assert "SNMP (UDP 161) от 10.0.0.0/24 — разрешён" in text
    # только LAN (списки пустые) — дополнительных правил нет
    exporters.update({"snmp": {"enabled": True}})
    assert exporters.firewall_rules() == []


def test_initconfig_and_host_ssh_port(monkeypatch):
    import json
    from app.scripts import initconfig
    d = initconfig.build({"identity": "office", "timezone": "Asia/Jerusalem",
                          "wan": {"interface": "ens18", "mode": "none"},
                          "wan2": {"interface": "ens20", "mode": "dhcp"}, "multiwan_mode": "balance",
                          "lan": {"address": "192.168.88.1/24", "ports": ["ens19"], "wan_management": True}})
    assert d["wan"] == {"interface": "ens18", "mode": "none"} and d["wan2"]["enabled"] is True
    assert d["lan"]["ports"] == ["ens19"] and d["lan"]["enabled"] is True and d["multiwan"]["mode"] == "balance"
    assert d["firewall"] == {"wan-management": True} and d["ntp"]["timezone"] == "Asia/Jerusalem"
    assert initconfig.main(["x", json.dumps({"wan": {"interface": "ens18", "mode": "static"}, "lan": {}})]) == 2
    monkeypatch.setenv("HOST_SSH_PORT", "22")
    monkeypatch.setenv("CLI_SSH_PORT", "2222")
    assert firewall.management_ports() == [22, 2222, 8000]
