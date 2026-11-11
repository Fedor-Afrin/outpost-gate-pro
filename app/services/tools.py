"""
Tools — сетевая диагностика (без Nmap: только стандартные утилиты и свой код).

  ping        — ICMP, IPv4 или IPv6 (iputils ping)
  port_scan   — сканер TCP-портов узла (свой код: подключение к каждому порту)
  traceroute  — маршрут до узла (ICMP)
  dns         — разрешение имени через DNS роутера
  neighbors   — таблица соседей (ARP): IP, MAC, производитель, имя из DHCP
  scan        — сканер подсети: ping-обход + ARP (видит и тех, кто не отвечает на ping)
У каждого инструмента (кроме DNS и соседей) можно выбрать интерфейс.

Потоковые инструменты — асинхронные генераторы событий:
  {"type": "row", "row": {...}}      строка таблицы
  {"type": "info", "text": "..."}    служебное сообщение
  {"type": "summary", "data": {...}} итог
Процесс утилиты завершается, когда генератор закрыт (кнопка «Стоп» или закрытая вкладка).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import subprocess
import time
from typing import AsyncIterator

from app.services import oui

HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,15}$")
MAX_SCAN_HOSTS = 1024
MAX_SCAN_PORTS = 1024
SERVICES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 554: "RTSP", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
            2000: "MikroTik", 3306: "MySQL", 3389: "RDP", 5060: "SIP", 5061: "SIP-TLS", 5432: "PostgreSQL",
            5900: "VNC", 8000: "HTTP-alt", 8080: "HTTP-proxy", 8291: "Winbox", 8443: "HTTPS-alt", 8728: "RouterOS API"}


class ToolError(Exception):
    pass


# --- проверка ввода (команды запускаются без shell, но аргументы всё равно проверяем) ----------
def check_host(host: str) -> str:
    host = (host or "").strip()
    if not HOST_RE.match(host) or host.startswith("-"):
        raise ToolError(f"неверный адрес или имя: '{host}'")
    return host


def check_int(value, lo: int, hi: int, what: str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError) as e:
        raise ToolError(f"{what}: нужно число") from e
    if not lo <= v <= hi:
        raise ToolError(f"{what}: от {lo} до {hi}")
    return v


def check_iface(iface: str | None) -> str | None:
    if not iface or iface == "auto":
        return None
    if not IFACE_RE.match(iface) or iface.startswith("-"):
        raise ToolError(f"неверный интерфейс: '{iface}'")
    return iface


def parse_ports(text: str | None, limit: int = MAX_SCAN_PORTS) -> list[int]:
    ports: list[int] = []
    for item in (text or "").replace(" ", "").split(","):
        if not item:
            continue
        if "-" in item:
            a, b = (check_int(x, 1, 65535, "порт") for x in item.split("-", 1))
            if b < a:
                raise ToolError(f"диапазон портов {item}: начало больше конца")
            ports += list(range(a, b + 1))
            if len(ports) > limit:
                raise ToolError(f"не больше {limit} портов за раз")
        else:
            ports.append(check_int(item, 1, 65535, "порт"))
    if len(ports) > limit:
        raise ToolError(f"не больше {limit} портов за раз")
    return sorted(set(ports))


# --- запуск утилиты построчно -----------------------------------------------------------------
async def run_lines(cmd: list[str], timeout: float) -> AsyncIterator[str]:
    """Строки вывода команды; по таймауту или закрытию генератора процесс убивается."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    except FileNotFoundError as e:
        raise ToolError(f"нет программы {cmd[0]}") from e
    deadline = time.monotonic() + timeout
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=left)
            except asyncio.TimeoutError:
                break
            if not line:
                break
            yield line.decode(errors="replace").rstrip()
    finally:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()


# --- ping ------------------------------------------------------------------------------------
PING_REPLY = re.compile(r"from (\S+?):? icmp_seq=(\d+) (?:ttl|hlim)=(\d+) time=([\d.]+) ms")
PING_LOST = re.compile(r"no answer yet for icmp_seq=(\d+)")
PING_ERR = re.compile(r"From (\S+?):? icmp_seq=(\d+) (.+)")
PING_STATS = re.compile(r"(\d+) packets transmitted, (\d+) received.*?([\d.]+)% packet loss")
PING_RTT = re.compile(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms")


def parse_ping_line(line: str) -> dict | None:
    if m := PING_REPLY.search(line):
        return {"type": "row", "row": {"seq": int(m[2]), "from": m[1], "ttl": int(m[3]),
                                       "time_ms": float(m[4]), "status": "ok"}}
    if m := PING_LOST.search(line):
        return {"type": "row", "row": {"seq": int(m[1]), "status": "timeout"}}
    if m := PING_ERR.search(line):
        return {"type": "row", "row": {"seq": int(m[2]), "from": m[1], "status": m[3].strip()}}
    if m := PING_STATS.search(line):
        return {"type": "summary", "data": {"sent": int(m[1]), "received": int(m[2]), "loss": float(m[3])}}
    if m := PING_RTT.search(line):
        return {"type": "summary", "data": {"min": float(m[1]), "avg": float(m[2]), "max": float(m[3])}}
    if line.startswith("ping:"):
        return {"type": "error", "text": line}
    return None


async def ping(params: dict) -> AsyncIterator[dict]:
    host = check_host(params.get("host"))
    count = check_int(params.get("count", 4), 1, 100, "количество")
    family = "-6" if str(params.get("family", "4")) == "6" else "-4"
    cmd = ["ping", family, "-n", "-O", "-c", str(count), "-W", "2", "-i", "0.5"]
    if iface := check_iface(params.get("interface")):
        cmd += ["-I", iface]
    async for line in run_lines(cmd + [host], timeout=count * 0.5 + 5):
        if ev := parse_ping_line(line):
            yield ev


# --- TCP: проверка порта и сканер портов --------------------------------------------------------
async def resolve(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ToolError(f"не удалось разрешить имя {host}: {e.strerror}") from e
    return sorted(infos, key=lambda i: i[0] != socket.AF_INET)[0][4][0]   # IPv4 в приоритете


async def tcp_probe(host: str, port: int, timeout: float = 2.0, iface: str | None = None) -> tuple[str, float | None]:
    """('open' | 'closed' | 'filtered' | ошибка, время мс). iface — отправить через этот интерфейс."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    start = time.perf_counter()
    try:
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout=timeout)
        return "open", round((time.perf_counter() - start) * 1000, 2)
    except asyncio.TimeoutError:
        return "filtered", None                      # нет ответа: порт закрыт фаерволом или узла нет
    except ConnectionRefusedError:
        return "closed", round((time.perf_counter() - start) * 1000, 2)
    except OSError as e:
        return e.strerror or str(e), None
    finally:
        sock.close()


async def port_scan(params: dict) -> AsyncIterator[dict]:
    host = check_host(params.get("host"))
    ports = parse_ports(params.get("ports") or "22, 80, 443")
    if not ports:
        raise ToolError("укажите порты: 22, 80, 443 или диапазон 1-1024")
    iface = check_iface(params.get("interface"))
    ip = await resolve(host)
    show_all = len(ports) <= 64            # на больших диапазонах — только открытые
    yield {"type": "info", "text": f"Сканирую {host}" + (f" ({ip})" if ip != host else "")
                                   + f": {len(ports)} портов" + ("" if show_all else ", показываю только открытые")}
    sem = asyncio.Semaphore(100)
    counts = {"open": 0, "closed": 0, "filtered": 0}

    async def probe(port: int):
        async with sem:
            return port, await tcp_probe(ip, port, 1.5, iface)

    for fut in asyncio.as_completed([probe(p) for p in ports]):
        port, (status, ms) = await fut
        counts[status if status in counts else "filtered"] += 1
        if show_all or status == "open":
            yield {"type": "row", "row": {"port": port, "service": SERVICES.get(port), "status": status,
                                          "time_ms": ms}}
    yield {"type": "summary", "data": {"host": host, "ip": ip, "scanned": len(ports), **counts}}


# --- traceroute -----------------------------------------------------------------------------------
def parse_traceroute_line(line: str) -> dict | None:
    """' 3  10.0.0.1  5.123 ms  4.9 ms *' -> {'hop': 3, 'ip': '10.0.0.1', 'times': [5.123, 4.9, None]}"""
    tokens = line.split()
    if not tokens or not tokens[0].isdigit():
        return None
    hop, ips, times, notes = int(tokens[0]), [], [], []
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t == "*":
            times.append(None)
        elif i + 1 < len(tokens) and tokens[i + 1] == "ms":
            times.append(float(t))
            i += 1
        elif t.startswith("!"):
            notes.append(t)
        else:
            try:
                ipaddress.ip_address(t)
                ips.append(t)
            except ValueError:
                pass
        i += 1
    return {"hop": hop, "ip": ips[0] if ips else None, "other_ips": ips[1:], "times": times, "notes": notes}


async def traceroute(params: dict) -> AsyncIterator[dict]:
    host = check_host(params.get("host"))
    max_hops = check_int(params.get("max_hops", 30), 1, 64, "максимум хопов")
    cmd = ["traceroute", "-I", "-n", "-q", "3", "-w", "2", "-m", str(max_hops)]   # ICMP
    if iface := check_iface(params.get("interface")):
        cmd += ["-i", iface]
    async for line in run_lines(cmd + [host], timeout=max_hops * 7 + 5):
        if row := parse_traceroute_line(line):
            yield {"type": "row", "row": row}
        elif line.startswith("traceroute to"):
            yield {"type": "info", "text": line}
        elif line.strip():
            yield {"type": "error", "text": line}


# --- DNS ----------------------------------------------------------------------------------------
async def dns_lookup(host: str) -> dict:
    host = check_host(host)
    loop = asyncio.get_running_loop()
    start = time.perf_counter()
    try:
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return {"host": host, "addresses": [], "error": e.strerror, "time_ms": None}
    ms = round((time.perf_counter() - start) * 1000, 2)
    addrs = sorted({i[4][0] for i in infos}, key=lambda a: (":" in a, a))
    return {"host": host, "addresses": addrs, "error": None, "time_ms": ms}


# --- соседи (ARP) ------------------------------------------------------------------------------
def _names() -> dict[str, str]:
    """MAC -> имя: из закреплённых адресов и DHCP-аренд LAN."""
    try:
        from app.services import lan
        names = {l.mac: (l.name or l.hostname) for l in lan.leases() if l.name or l.hostname}
        names.update({s.mac: s.name for s in lan.static_leases() if s.name})
        return names
    except Exception:
        return {}


def parse_neighbors(data: list[dict], names: dict[str, str] | None = None) -> list[dict]:
    names = names or {}
    out = []
    for n in data:
        dst = n.get("dst", "")
        if ":" in dst:          # IPv6 соседей пока не показываем
            continue
        mac = (n.get("lladdr") or "").lower() or None
        out.append({
            "ip": dst, "interface": n.get("dev"), "mac": mac,
            "state": ",".join(n.get("state", [])) or None,
            "vendor": oui.vendor(mac) if mac else None,
            "name": names.get(mac) if mac else None,
        })
    return sorted(out, key=lambda x: tuple(int(p) for p in x["ip"].split(".")))


def neighbors() -> list[dict]:
    try:
        r = subprocess.run(["ip", "-j", "-4", "neigh", "show"], capture_output=True, text=True, timeout=5)
    except FileNotFoundError as e:
        raise ToolError("нет программы ip") from e
    return parse_neighbors(json.loads(r.stdout or "[]"), _names())


# --- сканер подсети -------------------------------------------------------------------------------
async def _ping_once(ip: str, iface: str | None = None) -> float | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-n", "-c", "1", "-W", "1", *(["-I", iface] if iface else []), ip,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except FileNotFoundError as e:
        raise ToolError("нет программы ping") from e
    out, _ = await proc.communicate()
    m = PING_REPLY.search(out.decode(errors="replace"))
    return float(m[4]) if m else None


def default_scan_network() -> str | None:
    try:
        from app.services import lan
        cfg = lan.get_config()
        return str(ipaddress.ip_interface(cfg.address).network) if cfg.enabled else None
    except Exception:
        return None


async def scan(params: dict) -> AsyncIterator[dict]:
    try:
        net = ipaddress.ip_network((params.get("network") or default_scan_network() or "").strip(), strict=False)
    except ValueError as e:
        raise ToolError("укажите сеть, например 192.168.88.0/24") from e
    if net.version != 4 or net.num_addresses > MAX_SCAN_HOSTS + 2:
        raise ToolError(f"сеть IPv4 не больше {MAX_SCAN_HOSTS} адресов (/22)")
    iface = check_iface(params.get("interface"))
    hosts = [str(h) for h in net.hosts()]
    yield {"type": "info", "text": f"Сканирую {net}: {len(hosts)} адресов" + (f" через {iface}" if iface else "")}

    found: dict[str, dict] = {}
    sem = asyncio.Semaphore(64)

    async def probe(ip: str):
        async with sem:
            return ip, await _ping_once(ip, iface)

    # 1) ping-обход — заодно ядро разошлёт ARP-запросы всем адресам
    for fut in asyncio.as_completed([probe(ip) for ip in hosts]):
        ip, ms = await fut
        if ms is not None:
            found[ip] = {"ip": ip, "ping_ms": ms, "source": "ping"}

    # 2) ARP: устройства, которые не отвечают на ping, но ответили на ARP (телефоны, Windows)
    loop = asyncio.get_running_loop()
    try:
        neigh = await loop.run_in_executor(None, neighbors)
    except ToolError:
        neigh = []
    for n in neigh:
        if iface and n["interface"] != iface:
            continue
        if n["mac"] and ipaddress.ip_address(n["ip"]) in net and n["state"] not in ("FAILED", "INCOMPLETE"):
            row = found.setdefault(n["ip"], {"ip": n["ip"], "ping_ms": None, "source": "arp"})
            row.update(mac=n["mac"], vendor=n["vendor"], name=n["name"], interface=n["interface"])

    for ip in sorted(found, key=lambda a: tuple(int(p) for p in a.split("."))):
        yield {"type": "row", "row": found[ip]}
    yield {"type": "summary", "data": {"network": str(net), "scanned": len(hosts), "found": len(found)}}


TOOLS = {"ping": ping, "port_scan": port_scan, "traceroute": traceroute, "scan": scan}
