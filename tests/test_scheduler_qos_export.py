"""Планировщик, QoS и экспорт конфигурации — без ядра: tc, сокеты и сервисы подменяются."""
from datetime import datetime

import pytest
import yaml
from pydantic import ValidationError

from app.core.store import ConfigStore
from app.models.lan import LanConfig
from app.models.qos import QosConfig
from app.models.scheduler import Schedule, Task, cron_match
from app.services import export, firewall, qos, scheduler


# --- расписание ----------------------------------------------------------------------------------
def test_schedule_matching():
    mon8 = datetime(2026, 11, 16, 8, 0)          # понедельник
    sat8 = datetime(2026, 11, 21, 8, 0)
    assert Schedule(kind="daily", time="08:00").matches(mon8) and not Schedule(time="08:01").matches(mon8)
    wk = Schedule(kind="weekly", time="08:00", days=[0, 1, 2, 3, 4])
    assert wk.matches(mon8) and not wk.matches(sat8)
    iv = Schedule(kind="interval", every=15)
    assert iv.matches(datetime(2026, 1, 1, 10, 45)) and not iv.matches(datetime(2026, 1, 1, 10, 50))
    once = Schedule(kind="once", at="2026-12-31 23:59")
    assert once.at == "2026-12-31T23:59" and once.matches(datetime(2026, 12, 31, 23, 59))
    assert cron_match("*/15 8-18 * * 1-5", datetime(2026, 11, 16, 9, 30))
    assert not cron_match("*/15 8-18 * * 1-5", datetime(2026, 11, 21, 9, 30))    # суббота
    assert cron_match("0 0 1 * *", datetime(2026, 12, 1, 0, 0))
    assert cron_match("0 0 * * 0", datetime(2026, 11, 22, 0, 0)) and cron_match("0 0 * * 7", datetime(2026, 11, 22, 0, 0))
    for bad in ({"kind": "cron", "cron": "* * *"}, {"kind": "cron", "cron": "61 * * * *"}, {"time": "25:00"},
                {"kind": "weekly", "days": []}, {"kind": "once", "at": "завтра"}, {"days": [7]}):
        with pytest.raises(ValidationError):
            Schedule(**bad)


def test_next_run():
    t = lambda **s: Task(name="x", schedule=s, action={"type": "backup"})  # noqa: E731
    now = datetime(2026, 11, 16, 8, 0, 30)                              # пн 08:00:30
    assert scheduler.next_run(t(kind="daily", time="08:00"), now) == datetime(2026, 11, 17, 8, 0)
    assert scheduler.next_run(t(kind="weekly", time="07:00", days=[4]), now) == datetime(2026, 11, 20, 7, 0)
    assert scheduler.next_run(t(kind="interval", every=15), now) == datetime(2026, 11, 16, 8, 15)
    assert scheduler.next_run(t(kind="interval", every=7), datetime(2026, 11, 16, 23, 58)) == datetime(2026, 11, 17, 0, 0)
    assert scheduler.next_run(t(kind="cron", cron="30 9 * * 1-5"), now) == datetime(2026, 11, 16, 9, 30)
    assert scheduler.next_run(t(kind="once", at="2026-11-01T10:00"), now) is None
    with pytest.raises(ValidationError):
        Task(name="x", action={"type": "wol"})                         # нет MAC
    with pytest.raises(ValidationError):
        Task(name="x", action={"type": "format_disk"})


@pytest.fixture
def sched(tmp_path, monkeypatch):
    cfg = tmp_path / "router.yaml"
    cfg.write_text(yaml.safe_dump({"system": {"identity": "office"}}))
    store = ConfigStore(str(cfg), str(tmp_path / "snap"))
    monkeypatch.setattr(scheduler, "store", store)
    monkeypatch.setattr(scheduler, "_data", lambda name: tmp_path / name)
    from app.services import system
    monkeypatch.setattr(system, "audit", lambda *a: None)
    return store, tmp_path


def test_scheduler_crud_tick_and_actions(sched, monkeypatch):
    store, tmp = sched
    from app.services import lan, tools
    woke = []
    monkeypatch.setattr(tools, "wol", lambda mac, l=None: woke.append(mac) or {"mac": mac, "sent": [{"name": "LAN"}]})
    seg = LanConfig(id="lan2", name="Guests", enabled=True, address="10.20.0.1/24")
    changed = []
    monkeypatch.setattr(lan, "segments", lambda data=None: [LanConfig(enabled=True), seg])
    monkeypatch.setattr(lan, "update_segment", lambda sid, new: changed.append((sid, new.enabled)))

    a = scheduler.add(Task(name="Разбудить ПК", schedule={"kind": "weekly", "time": "08:00", "days": [0, 1, 2, 3, 4]},
                           action={"type": "wol", "mac": "3c:52:82:aa:bb:cc"}))
    b = scheduler.add(Task(name="Гости ночью", schedule={"kind": "daily", "time": "23:00"},
                           action={"type": "lan_segment", "lan": "Guests", "enabled": False}))
    c = scheduler.add(Task(name="Копия", schedule={"kind": "once", "at": "2026-11-16T08:00"}, action={"type": "backup"}))
    assert (a.id, b.id, c.id) == (1, 2, 3) and len(store.load()["scheduler"]["tasks"]) == 3

    recs = scheduler.tick(datetime(2026, 11, 16, 8, 0))
    assert [r.name for r in recs] == ["Разбудить ПК", "Копия"] and all(r.ok for r in recs)
    assert woke == ["3c:52:82:aa:bb:cc"] and list((tmp / "backups").glob("router-*.yaml"))
    assert scheduler.tasks()[2].enabled is False                          # «один раз» выключилась
    scheduler.tick(datetime(2026, 11, 16, 23, 0))
    assert changed == [("lan2", False)]

    # ошибка действия — в журнал, без исключения
    monkeypatch.setattr(tools, "wol", lambda mac, l=None: (_ for _ in ()).throw(tools.ToolError("нет включённых сегментов LAN")))
    r = scheduler.run_now(1)
    assert r.ok is False and r.manual and "нет включённых" in r.message
    st = scheduler.status()
    assert st.tasks[0].last_ok is False and st.tasks[0].description.startswith("пн,вт,ср,чт,пт в 08:00 → Разбудить")
    assert st.tasks[1].description == "каждый день в 23:00 → выключить сегмент Guests" and st.log[0].ok is False

    scheduler.update(2, Task(name="Гости ночью", enabled=False, schedule={"kind": "daily", "time": "22:00"},
                             action={"type": "lan_segment", "lan": "Guests", "enabled": False}))
    assert scheduler.tasks()[1].schedule.time == "22:00" and scheduler.tick(datetime(2026, 11, 16, 22, 0)) == []
    scheduler.delete(3)
    assert [t.id for t in scheduler.tasks()] == [1, 2]
    with pytest.raises(scheduler.SchedulerError):
        scheduler.delete(9)


# --- QoS -------------------------------------------------------------------------------------------
def test_qos_plan():
    cfg = QosConfig(enabled=True, wan_down=100, wan_up=20,
                    segments=[{"lan": "lan2", "down": 20, "up": 5}],
                    devices=[{"ip": "10.20.0.50", "name": "phone", "down": 2}, {"ip": "10.20.0.60", "up": 1},
                             {"ip": "192.168.1.20", "down": 50}])
    cmds = qos.plan_segment(cfg, "br-lan2", "10.20.0.0/24", "lan2")
    text = [" ".join(c) for c in cmds]
    assert "class add dev br-lan2 parent 1: classid 1:1 htb rate 20000kbit ceil 20000kbit" in text
    assert "filter add dev br-lan2 parent 1: protocol ip prio 1 u32 match ip tos 0xb8 0xfc flowid 1:10" in text
    assert "class add dev br-lan2 parent 1:1 classid 1:100 htb rate 2000kbit ceil 2000kbit prio 1" in text
    assert "filter add dev br-lan2 parent 1: protocol ip prio 2 u32 match ip dst 10.20.0.50/32 flowid 1:100" in text
    assert not any("192.168.1.20" in t for t in text)                     # устройство другого сегмента
    assert any("match ip src 10.20.0.60/32 police rate 1000kbit" in t for t in text)
    assert any("prio 5 u32 match ip src 10.20.0.0/24 police rate 5000kbit" in t for t in text)
    # без лимитов сегмента: потолок — скорость провайдера
    assert "rate 100000kbit" in " ".join(qos.plan_segment(cfg, "br-lan", "192.168.1.0/24", "lan1")[1])
    # без голоса и без лимитов — ничего
    assert qos.plan_segment(QosConfig(enabled=True, voice=False), "br-lan", "192.168.1.0/24", "lan1") == []
    w = [" ".join(c) for c in qos.plan_wan(cfg, "eth0")]
    assert "class add dev eth0 parent 1: classid 1:1 htb rate 20000kbit ceil 20000kbit" in w and any("1:10" in x for x in w)
    assert qos.plan_wan(QosConfig(enabled=True), "eth0") == []
    for bad in ({"devices": [{"ip": "10.0.0.1"}]}, {"devices": [{"ip": "x", "down": 1}]},
                {"sip_ports": "sip"}, {"rtp_ports": "70000"},
                {"devices": [{"ip": "10.0.0.1", "up": 1}, {"ip": "10.0.0.1", "down": 1}]}):
        with pytest.raises(ValidationError):
            QosConfig(**bad)
    assert QosConfig(segments=[{"lan": "lan2"}]).segments == []           # пустой лимит не хранится


def test_qos_apply_and_firewall(tmp_path, monkeypatch):
    cfgf = tmp_path / "router.yaml"
    cfgf.write_text("{}")
    store = ConfigStore(str(cfgf), str(tmp_path / "snap"))
    monkeypatch.setattr(qos, "store", store)
    calls = []

    class R:
        returncode, stdout, stderr = 0, "[]", ""
    monkeypatch.setattr(qos, "tc", lambda *a: calls.append(a) or R())
    monkeypatch.setattr(qos, "_segments", lambda: [LanConfig(enabled=True, address="192.168.1.1/24")])
    monkeypatch.setattr(qos, "_wans", lambda: ["eth0"])
    monkeypatch.setattr(firewall, "refresh", lambda *a: None)
    st = qos.update(QosConfig(enabled=True, wan_up=20, devices=[{"ip": "192.168.1.20", "name": "laptop", "down": 10}]))
    assert st.active and ("qdisc", "del", "dev", "br-lan", "root") in calls
    assert any(c[:2] == ("filter", "add") and "192.168.1.20/32" in c for c in calls)
    assert qos.firewall_ports() == ("5060-5061", "10000-20000")
    assert qos.set_device_enabled("192.168.1.20", False) == "ограничение 192.168.1.20: выключено"
    assert qos.get_config().devices[0].enabled is False
    rs = firewall.ruleset("eth0", "br-lan", False, qos=("5060-5061", "10000-20000"))
    assert "udp dport { 5060-5061, 10000-20000 } ip dscp set ef" in rs and "hook forward priority mangle" in rs
    assert "qos_mark" not in firewall.ruleset("eth0", "br-lan", False)
    stats = qos.parse_class_stats([{"class": "htb", "handle": "1:10", "stats": {"bytes": 500, "packets": 5, "drops": 1}},
                                   {"class": "htb", "handle": "1:1", "stats": {"bytes": 9}}],
                                  "br-lan", {"1:10": ("voice", "LAN: голос")})
    assert [(s.label, s.bytes, s.drops) for s in stats] == [("LAN: голос", 500, 1)]


# --- экспорт ------------------------------------------------------------------------------------------
CONFIG = {
    "system": {"identity": "office"},
    "wan": {"interface": "eth0", "mode": "static", "address": "203.0.113.10/24", "gateway": "203.0.113.1", "dns": ["1.1.1.1"]},
    "lan": {"enabled": True, "address": "192.168.1.1/24", "dhcp-server": {"static-leases": [
        {"mac": "00:0b:82:aa:bb:cc", "ip": "192.168.1.5", "name": "Телефон директора"}]}},
    "lans": [{"id": "lan2", "name": "Guests", "enabled": True, "address": "10.20.0.1/24", "ports": ["eth3"]}],
    "firewall": {"rules": [{"id": 1, "chain": "input", "action": "accept", "in-zone": "wan", "protocol": "tcp",
                            "dst-ports": "22", "description": "SSH"}],
                 "forwards": [{"id": 1, "protocol": "tcp", "wan-port": "8080", "to-ip": "192.168.1.20", "to-port": 80}]},
    "vpn": {"wireguard": {"enabled": True, "private-key": "cHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHA=",
                          "address": ["10.8.0.2/32"],
                          "peer": {"public-key": "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s=",
                                   "endpoint": "vpn.example.com:51820", "allowed-ips": ["0.0.0.0/0"]}}},
    "qos": {"enabled": True, "wan_down": 200, "wan_up": 50, "segments": [{"lan": "lan2", "down": 20, "up": 5}],
            "devices": [{"ip": "192.168.1.20", "name": "laptop", "down": 10, "up": 2}]},
    "scheduler": {"tasks": [{"id": 1, "name": "Разбудить ПК", "schedule": {"kind": "weekly", "time": "08:00", "days": [0, 4]},
                             "action": {"type": "wol", "mac": "3c:52:82:aa:bb:cc"}}]},
    "ntp": {"enabled": True, "servers": ["pool.ntp.org"], "timezone": "Asia/Jerusalem"},
}


def test_export_text():
    t = export.export_text(CONFIG, version="0.2.0", now=datetime(2026, 11, 13, 20, 0),
                           users=[{"name": "admin", "role": "full"}, {"name": "ivan", "role": "read"}])
    lines = t.splitlines()
    assert lines[0] == "# 2026-11-13 20:00:00 by OutpostGate Pro 0.2.0"
    for expected in [
        "/system identity", "set name=office",
        "set time-zone-name=Asia/Jerusalem",
        "set interface=eth0 mode=static address=203.0.113.10/24 gateway=203.0.113.1 dns=1.1.1.1",
        "set [ find id=lan1 ] name=LAN address=192.168.1.1/24 ports=auto dns=yes domain=office.lan wan-management=yes disabled=no",
        "add id=lan2 name=Guests address=10.20.0.1/24 ports=eth3 dns=yes wan-management=yes disabled=no",
        'add server=LAN mac-address=00:0b:82:aa:bb:cc address=192.168.1.5 comment="Телефон директора"',
        "add chain=input action=accept protocol=tcp dst-port=22 in-interface-list=WAN comment=SSH",
        "add chain=dstnat action=dst-nat protocol=tcp dst-port=8080 to-addresses=192.168.1.20 to-ports=80",
        "set enabled=yes wan-limit=50M/200M voice-priority=yes sip-ports=5060-5061 rtp-ports=10000-20000",
        "set [ find lan=Guests ] max-limit=5M/20M",
        "add name=laptop target=192.168.1.20 max-limit=2M/10M",
        'add name="Разбудить ПК" start-time=08:00 days=mon,fri on-event=wol mac=3c:52:82:aa:bb:cc',
        "add name=ivan group=read",
    ]:
        assert expected in lines, expected
    assert "private-key" not in t and "секреты скрыты" in lines[1]
    assert "/interface wireguard peers" in lines and "endpoint=vpn.example.com:51820" in t
    full = export.export_text(CONFIG, show_sensitive=True)
    assert 'private-key="cHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHA="' in full
    assert export.q('a "b"') == '"a \\"b\\""' and export.q(True) == "yes" and export.q(["a", "b"]) == "a,b"
    # пустая конфигурация тоже экспортируется
    assert "/lan segment" in export.export_text({})
