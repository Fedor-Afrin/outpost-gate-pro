"""
Тесты Tools: разбор вывода ping / traceroute / tcpdump / ip neigh, проверка ввода,
TCP ping на настоящем локальном сокете, сканер с подменой ping и ARP.
"""
import asyncio
import sys

import pytest

from app.services import tools


def collect(agen):
    async def go():
        return [ev async for ev in agen]
    return asyncio.run(go())


def test_parse_ping():
    assert tools.parse_ping_line("64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=12.4 ms") == \
        {"type": "row", "row": {"seq": 3, "from": "8.8.8.8", "ttl": 117, "time_ms": 12.4, "status": "ok"}}
    assert tools.parse_ping_line("no answer yet for icmp_seq=2")["row"] == {"seq": 2, "status": "timeout"}
    unreach = tools.parse_ping_line("From 192.168.88.1 icmp_seq=1 Destination Host Unreachable")
    assert unreach["row"]["status"] == "Destination Host Unreachable"
    assert tools.parse_ping_line("4 packets transmitted, 3 received, 25% packet loss, time 3004ms")["data"] == \
        {"sent": 4, "received": 3, "loss": 25.0}
    assert tools.parse_ping_line("rtt min/avg/max/mdev = 11.1/12.4/13.8/0.9 ms")["data"]["avg"] == 12.4
    assert tools.parse_ping_line("ping: nosuch.host: Name or service not known")["type"] == "error"
    assert tools.parse_ping_line("PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.") is None
    v6 = tools.parse_ping_line("64 bytes from 2a00:1450:4028:80c::200e: icmp_seq=1 ttl=117 time=9.8 ms")
    assert v6["row"]["from"] == "2a00:1450:4028:80c::200e" and v6["row"]["time_ms"] == 9.8


def test_parse_traceroute():
    assert tools.parse_traceroute_line(" 1  172.18.0.1  0.071 ms  0.020 ms  0.018 ms") == \
        {"hop": 1, "ip": "172.18.0.1", "other_ips": [], "times": [0.071, 0.02, 0.018], "notes": []}
    r = tools.parse_traceroute_line(" 5  1.1.1.1  3.1 ms 2.2.2.2  4.5 ms *")
    assert r["ip"] == "1.1.1.1" and r["other_ips"] == ["2.2.2.2"] and r["times"] == [3.1, 4.5, None]
    assert tools.parse_traceroute_line(" 7  * * *")["times"] == [None, None, None]
    assert tools.parse_traceroute_line(" 9  10.0.0.1  5.0 ms !H  5.1 ms !H  * ")["notes"] == ["!H", "!H"]
    assert tools.parse_traceroute_line("traceroute to 8.8.8.8 (8.8.8.8), 30 hops max") is None


def test_parse_neighbors():
    data = [{"dst": "192.168.88.20", "dev": "br-lan", "lladdr": "00:0B:82:aa:bb:cc", "state": ["REACHABLE"]},
            {"dst": "192.168.88.3", "dev": "br-lan", "state": ["FAILED"]},
            {"dst": "fe80::1", "dev": "br-lan", "lladdr": "aa:aa:aa:aa:aa:aa", "state": ["STALE"]}]
    rows = tools.parse_neighbors(data, {"00:0b:82:aa:bb:cc": "Телефон"})
    assert [r["ip"] for r in rows] == ["192.168.88.3", "192.168.88.20"]          # IPv6 пропущен, сортировка
    assert rows[1]["mac"] == "00:0b:82:aa:bb:cc" and rows[1]["name"] == "Телефон"
    assert rows[0]["mac"] is None and rows[0]["state"] == "FAILED"


def test_input_validation():
    for bad in ("-oProxyCommand=x", "a b", "", "x" * 300):
        with pytest.raises(tools.ToolError):
            tools.check_host(bad)
    assert tools.parse_ports("22, 80,5060-5062") == [22, 80, 5060, 5061, 5062]
    assert len(tools.parse_ports("1-1024")) == 1024
    for bad in ("1-2000", "100-50", "70000", "abc"):
        with pytest.raises(tools.ToolError):
            tools.parse_ports(bad)
    with pytest.raises(tools.ToolError):
        tools.check_int(0, 1, 10, "x")
    assert set(tools.TOOLS) == {"ping", "port_scan", "traceroute", "scan"}   # захвата пакетов больше нет
    with pytest.raises(tools.ToolError, match="/22"):
        collect(tools.scan({"network": "10.0.0.0/16"}))


def test_run_lines_and_timeout():
    lines = collect(tools.run_lines([sys.executable, "-c", "print('a'); print('b')"], timeout=5))
    assert lines == ["a", "b"]
    slow = collect(tools.run_lines([sys.executable, "-c", "import time; print('x', flush=True); time.sleep(30)"],
                                   timeout=1))
    assert slow == ["x"]                                                     # процесс убит по таймауту


def test_tcp_probe_and_port_scan():
    async def go():
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        open_ = await tools.tcp_probe("127.0.0.1", port)
        events = [ev async for ev in tools.port_scan({"host": "localhost", "ports": f"{port}, {port + 1}"})]
        server.close()
        await server.wait_closed()
        closed = await tools.tcp_probe("127.0.0.1", port)
        return open_, closed, port, events
    (st_open, t_open), (st_closed, _), port, events = asyncio.run(go())
    assert st_open == "open" and t_open is not None and st_closed == "closed"
    rows = {e["row"]["port"]: e["row"]["status"] for e in events if e["type"] == "row"}
    assert rows[port] == "open"
    summary = events[-1]["data"]
    assert summary["ip"] in ("127.0.0.1", "::1") and summary["open"] == 1 and summary["scanned"] == 2


def test_scan_ping_plus_arp(monkeypatch):
    async def fake_ping(ip, iface=None):
        return 1.5 if ip == "192.168.88.10" else None
    monkeypatch.setattr(tools, "_ping_once", fake_ping)
    monkeypatch.setattr(tools, "neighbors", lambda: [
        {"ip": "192.168.88.10", "mac": "00:0b:82:00:00:01", "vendor": "Grandstream", "name": "GXP", "interface": "br-lan", "state": "REACHABLE"},
        {"ip": "192.168.88.11", "mac": "da:00:00:00:00:02", "vendor": "случайный MAC", "name": None, "interface": "br-lan", "state": "STALE"},
        {"ip": "192.168.88.12", "mac": None, "vendor": None, "name": None, "interface": "br-lan", "state": "FAILED"},
        {"ip": "10.0.0.5", "mac": "00:00:00:00:00:03", "vendor": None, "name": None, "interface": "eth1", "state": "REACHABLE"},
    ])
    events = collect(tools.scan({"network": "192.168.88.0/28"}))
    rows = [e["row"] for e in events if e["type"] == "row"]
    assert [(r["ip"], r["source"]) for r in rows] == [("192.168.88.10", "ping"), ("192.168.88.11", "arp")]
    assert rows[0]["name"] == "GXP" and rows[0]["ping_ms"] == 1.5
    assert events[-1]["data"] == {"network": "192.168.88.0/28", "scanned": 14, "found": 2}


def test_scan_filters_by_interface(monkeypatch):
    async def fake_ping(ip, iface=None):
        assert iface == "br-lan"
        return None
    monkeypatch.setattr(tools, "_ping_once", fake_ping)
    monkeypatch.setattr(tools, "neighbors", lambda: [
        {"ip": "192.168.88.11", "mac": "aa:00:00:00:00:01", "vendor": None, "name": None, "interface": "br-lan", "state": "STALE"},
        {"ip": "192.168.88.12", "mac": "aa:00:00:00:00:02", "vendor": None, "name": None, "interface": "eth0", "state": "STALE"}])
    events = collect(tools.scan({"network": "192.168.88.0/28", "interface": "br-lan"}))
    assert [e["row"]["ip"] for e in events if e["type"] == "row"] == ["192.168.88.11"]
