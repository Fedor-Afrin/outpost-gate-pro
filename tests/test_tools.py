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
    unreach = tools.parse_ping_line("From 192.168.1.1 icmp_seq=1 Destination Host Unreachable")
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
    data = [{"dst": "192.168.1.20", "dev": "br-lan", "lladdr": "00:0B:82:aa:bb:cc", "state": ["REACHABLE"]},
            {"dst": "192.168.1.3", "dev": "br-lan", "state": ["FAILED"]},
            {"dst": "fe80::1", "dev": "br-lan", "lladdr": "aa:aa:aa:aa:aa:aa", "state": ["STALE"]}]
    rows = tools.parse_neighbors(data, {"00:0b:82:aa:bb:cc": "Телефон"})
    assert [r["ip"] for r in rows] == ["192.168.1.3", "192.168.1.20"]          # IPv6 пропущен, сортировка
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
        return 1.5 if ip == "192.168.1.10" else None
    monkeypatch.setattr(tools, "_ping_once", fake_ping)
    monkeypatch.setattr(tools, "neighbors", lambda: [
        {"ip": "192.168.1.10", "mac": "00:0b:82:00:00:01", "vendor": "Grandstream", "name": "GXP", "interface": "br-lan", "state": "REACHABLE"},
        {"ip": "192.168.1.11", "mac": "da:00:00:00:00:02", "vendor": "случайный MAC", "name": None, "interface": "br-lan", "state": "STALE"},
        {"ip": "192.168.1.12", "mac": None, "vendor": None, "name": None, "interface": "br-lan", "state": "FAILED"},
        {"ip": "10.0.0.5", "mac": "00:00:00:00:00:03", "vendor": None, "name": None, "interface": "eth1", "state": "REACHABLE"},
    ])
    events = collect(tools.scan({"network": "192.168.1.0/28"}))
    rows = [e["row"] for e in events if e["type"] == "row"]
    assert [(r["ip"], r["source"]) for r in rows] == [("192.168.1.10", "ping"), ("192.168.1.11", "arp")]
    assert rows[0]["name"] == "GXP" and rows[0]["ping_ms"] == 1.5
    assert events[-1]["data"] == {"network": "192.168.1.0/28", "scanned": 14, "found": 2}


def test_scan_filters_by_interface(monkeypatch):
    async def fake_ping(ip, iface=None):
        assert iface == "br-lan"
        return None
    monkeypatch.setattr(tools, "_ping_once", fake_ping)
    monkeypatch.setattr(tools, "neighbors", lambda: [
        {"ip": "192.168.1.11", "mac": "aa:00:00:00:00:01", "vendor": None, "name": None, "interface": "br-lan", "state": "STALE"},
        {"ip": "192.168.1.12", "mac": "aa:00:00:00:00:02", "vendor": None, "name": None, "interface": "eth0", "state": "STALE"}])
    events = collect(tools.scan({"network": "192.168.1.0/28", "interface": "br-lan"}))
    assert [e["row"]["ip"] for e in events if e["type"] == "row"] == ["192.168.1.11"]


# --- DNS роутера ------------------------------------------------------------------------------
import socket as _socket
import struct as _struct
import threading as _threading

ZONE = {"samba.office.lan": ("CNAME", "router.office.lan"), "router.office.lan": ("A", "192.168.1.1"),
        "nas.office.lan": ("A", "192.168.1.30"), "example.com": ("A", "93.184.216.34")}


def _qname(data, pos=12):
    labels = []
    while data[pos]:
        labels.append(data[pos + 1:pos + 1 + data[pos]].decode())
        pos += data[pos] + 1
    return ".".join(labels), pos + 1


def _enc(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def _answer(data):
    qid = data[:2]
    name, pos = _qname(data)
    qtype = _struct.unpack(">H", data[pos:pos + 2])[0]
    question = data[12:pos + 4]
    answers, n = b"", name
    for _ in range(5):
        if n not in ZONE:
            break
        t, v = ZONE[n]
        if t == "CNAME":
            rd = _enc(v)
            answers += b"\xc0\x0c" + _struct.pack(">HHIH", 5, 1, 60, len(rd)) + rd   # имя — ссылкой на вопрос
            n = v
            continue
        if qtype == 1:
            rd = _socket.inet_aton(v)
            answers += _enc(n) + _struct.pack(">HHIH", 1, 1, 60, 4) + rd
        break
    count = answers.count(b"\x00\x01\x00\x01\x00\x00\x00\x3c") + answers.count(b"\x00\x05\x00\x01\x00\x00\x00\x3c")
    rcode = 0 if name in ZONE else 3
    return qid + _struct.pack(">HHHHH", 0x8180 | rcode, 1, count, 0, 0) + question + answers


@pytest.fixture
def fake_bind(monkeypatch):
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    stop = _threading.Event()

    def serve():
        s.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = s.recvfrom(512)
            except OSError:
                continue
            s.sendto(_answer(data), addr)

    t = _threading.Thread(target=serve, daemon=True)
    t.start()
    monkeypatch.setattr(tools, "LOCAL_DNS", s.getsockname())
    monkeypatch.setattr(tools, "local_domains", lambda: ["office.lan", "guest.lan"])
    yield
    stop.set()
    t.join()
    s.close()


def test_dns_packet_roundtrip():
    pkt = tools.dns_packet("samba.office.lan.", 1, 0x1234)
    assert pkt[:2] == b"\x12\x34" and _qname(pkt)[0] == "samba.office.lan"
    assert tools.parse_dns_reply(_answer(pkt), 0x1234) == (0, ["192.168.1.1"])     # CNAME -> A
    with pytest.raises(ValueError):
        tools.parse_dns_reply(_answer(pkt), 0x9999)


def test_router_lookup_local_names(fake_bind):
    r = tools.router_lookup("samba.office.lan", want6=False)
    assert r == {"name": "samba.office.lan", "addresses": ["192.168.1.1"], "rcode": 0}
    r = tools.router_lookup("nas", want6=False)                       # короткое имя — с доменом сегмента
    assert r["name"] == "nas.office.lan" and r["addresses"] == ["192.168.1.30"]
    r = tools.router_lookup("nothing.office.lan", want6=False)
    assert r["addresses"] == [] and tools.rcode_text(r["rcode"]).startswith("имя не найдено")
    assert tools.resolve_sync("samba", 4) == ("192.168.1.1", "DNS роутера: samba.office.lan")
    assert tools.resolve_sync("10.0.0.1") == ("10.0.0.1", "")


def test_dns_lookup_tool(fake_bind):
    d = asyncio.run(tools.dns_lookup("samba"))
    assert d["host"] == "samba.office.lan" and d["addresses"] == ["192.168.1.1"]
    assert d["server"] == "DNS роутера (BIND)" and d["error"] is None
    d = asyncio.run(tools.dns_lookup("missing.office.lan"))
    assert d["addresses"] == [] and "NXDOMAIN" in d["error"]


def test_bind_down_falls_back(monkeypatch):
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()
    s.close()                                                         # порт закрыт — BIND «выключен»
    monkeypatch.setattr(tools, "LOCAL_DNS", port)
    assert tools.dns_query("x.lan", 1, timeout=0.5) is None
    assert tools.router_lookup("x.lan") is None
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.7", 0))])
    assert tools.resolve_sync("printer.example") == ("192.0.2.7", "системный DNS")
