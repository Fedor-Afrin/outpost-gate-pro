"""
Мониторинг: сбор метрик раз в 10 секунд и история для встроенного дашборда.

Что собирается:
  * система — CPU, память, диски, температура, нагрузка, время работы;
  * интерфейсы — скорость приёма и передачи, счётчики байт, ошибки, потери, состояние;
  * связь — задержка и потери до шлюза провайдера и до заданных адресов (ping);
  * клиенты LAN — сколько скачал и отправил каждый адрес (учёт в nftables, своя таблица);
  * сервисы (раз в 30 с) — аренды DHCP, VPN, соседи OSPF и BGP, подключения Samba.

История хранится в памяти кольцевыми буферами и раз в 5 минут сохраняется в
data/monitor/history.json.gz — после перезапуска графики не пропадают:
  1 час   — точка каждые 10 с     24 часа — каждую минуту
  7 дней  — каждые 10 минут       30 дней — каждый час
Последний замер дополнительно пишется в data/monitor/current.json — его читает
Zabbix agent (app/scripts/zbx.py), не дёргая API.
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import os
import re
import shutil
import subprocess
import threading
import time
from array import array
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.core.config import settings

INTERVAL = 10
SLOW_EVERY = 3                      # сервисы — раз в 3 замера (30 с)
SAVE_EVERY = 300
TIERS = {"1h": (10, 360), "24h": (60, 1440), "7d": (600, 1008), "30d": (3600, 720)}
SYS_NET = Path(os.getenv("SYS_NET", "/sys/class/net"))
PROC = Path(os.getenv("PROC_ROOT", "/proc"))
ACCT_TABLE = "outpost_acct"
VPN_IFACES = {"wg0": "WireGuard", "awg0": "AmneziaWG", "l2tp0": "L2TP"}
SKIP_IF = re.compile(r"^(lo|veth.*|docker\d*|br-[0-9a-f]{12}|ifb\d+|dummy\d+|gre0|gretap0|erspan0|ip_vti0|ip6tnl0|sit0|tunl0|ip6_vti0|ip6gre0|nlmon\d+)$")


def _data(*parts: str) -> Path:
    return Path(settings.data_dir).joinpath("monitor", *parts)


# --- история ---------------------------------------------------------------------------------
class History:
    """Кольцевые буферы по уровням детализации. Точка уровня — среднее за его шаг."""

    def __init__(self, tiers: dict[str, tuple[int, int]] = TIERS):
        self.tiers = tiers
        self.data: dict[str, dict[str, list[array]]] = {}
        self.lock = threading.Lock()

    def _new(self) -> dict[str, list[array]]:
        return {t: [array("q", [-1]) * n, array("d", [0.0]) * n, array("l", [0]) * n]
                for t, (_, n) in self.tiers.items()}

    def add(self, ts: float, key: str, value: float | None) -> None:
        if value is None:
            return
        with self.lock:
            d = self.data.get(key)
            if d is None:
                d = self.data[key] = self._new()
            for t, (step, n) in self.tiers.items():
                b = int(ts // step)
                i = b % n
                buckets, sums, counts = d[t]
                if buckets[i] != b:
                    buckets[i], sums[i], counts[i] = b, 0.0, 0
                sums[i] += value
                counts[i] += 1

    def series(self, key: str, tier: str, now: float) -> dict:
        step, n = self.tiers[tier]
        end = int(now // step)
        out: list[float | None] = []
        with self.lock:
            d = self.data.get(key)
            for b in range(end - n + 1, end + 1):
                i = b % n
                if d and d[tier][0][i] == b and d[tier][2][i]:
                    out.append(round(d[tier][1][i] / d[tier][2][i], 4))
                else:
                    out.append(None)
        return {"start": (end - n + 1) * step, "step": step, "values": out}

    def keys(self) -> list[str]:
        with self.lock:
            return sorted(self.data)

    def dump(self) -> dict:
        with self.lock:
            return {"tiers": {t: list(v) for t, v in self.tiers.items()},
                    "data": {k: {t: [a.tolist() for a in arrs] for t, arrs in d.items()} for k, d in self.data.items()}}

    def load(self, raw: dict) -> None:
        if {t: tuple(v) for t, v in (raw.get("tiers") or {}).items()} != self.tiers:
            return          # другая сетка — начать заново
        with self.lock:
            for k, d in (raw.get("data") or {}).items():
                try:
                    self.data[k] = {t: [array("q", d[t][0]), array("d", d[t][1]), array("l", d[t][2])]
                                    for t, (_, n) in self.tiers.items() if len(d[t][0]) == n}
                except (KeyError, TypeError, ValueError, OverflowError):
                    continue
                if len(self.data[k]) != len(self.tiers):
                    del self.data[k]


# --- источники -------------------------------------------------------------------------------
def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _int(path: Path) -> int | None:
    v = _read(path)
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def cpu_times(stat: str | None) -> tuple[int, int] | None:
    """(простой, всего) из первой строки /proc/stat."""
    if not stat:
        return None
    parts = stat.splitlines()[0].split()
    if not parts or parts[0] != "cpu":
        return None
    vals = [int(x) for x in parts[1:9]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return idle, sum(vals)


def cpu_percent(prev: tuple[int, int] | None, now: tuple[int, int] | None) -> float | None:
    if not prev or not now or now[1] <= prev[1]:
        return None
    return round(max(0.0, min(100.0, 100 * (1 - (now[0] - prev[0]) / (now[1] - prev[1])))), 1)


def memory(text: str | None) -> dict:
    vals = {}
    for line in (text or "").splitlines():
        key, _, rest = line.partition(":")
        if rest.strip():
            vals[key] = int(rest.split()[0]) * 1024
    total = vals.get("MemTotal", 0)
    avail = vals.get("MemAvailable", vals.get("MemFree", 0))
    return {"total": total, "used": total - avail,
            "percent": round(100 * (total - avail) / total, 1) if total else None}


def interface_counters(names: list[str] | None = None) -> dict[str, dict]:
    out = {}
    try:
        all_names = sorted(os.listdir(SYS_NET))
    except OSError:
        return out
    for name in all_names:
        if SKIP_IF.match(name) or (names is not None and name not in names):
            continue
        base = SYS_NET / name
        st = base / "statistics"
        speed = _int(base / "speed")
        out[name] = {
            "rx_bytes": _int(st / "rx_bytes") or 0, "tx_bytes": _int(st / "tx_bytes") or 0,
            "rx_errors": _int(st / "rx_errors") or 0, "tx_errors": _int(st / "tx_errors") or 0,
            "rx_dropped": _int(st / "rx_dropped") or 0, "tx_dropped": _int(st / "tx_dropped") or 0,
            "up": (_read(base / "operstate") or "unknown") in ("up", "unknown")
                  and (_int(base / "carrier") or 0) == 1,
            "speed": speed * 1_000_000 if speed and speed > 0 else None,
            "mac": _read(base / "address"),
        }
    return out


def rate(prev: int | None, cur: int | None, dt: float) -> float | None:
    if prev is None or cur is None or dt <= 0 or cur < prev:
        return None          # первый замер или счётчик сброшен (интерфейс пересоздан)
    return round((cur - prev) / dt, 1)


PING_RE = re.compile(r"(\d+(?:\.\d+)?)% packet loss")
RTT_RE = re.compile(r"= [\d.]+/([\d.]+)/")


def parse_ping(out: str) -> tuple[float | None, float | None]:
    """(средняя задержка в мс, потери в %) из вывода ping -q."""
    loss = PING_RE.search(out or "")
    rtt = RTT_RE.search(out or "")
    return (float(rtt.group(1)) if rtt else None, float(loss.group(1)) if loss else None)


def ping(target: str) -> tuple[float | None, float | None]:
    try:
        r = subprocess.run(["ping", "-n", "-q", "-c", "3", "-i", "0.3", "-W", "1", target],
                           capture_output=True, text=True, timeout=6)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    rtt, loss = parse_ping(r.stdout)
    return rtt, (100.0 if loss is None and r.returncode else loss)


def disks() -> list[dict]:
    out, seen = [], set()
    data_dir = settings.data_dir if os.path.exists(settings.data_dir) else "/"
    paths = [("data", data_dir)]
    for line in (_read(PROC / "mounts") or "").splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[1].startswith("/mnt/disks/"):
            paths.append((parts[1].rsplit("/", 1)[-1], parts[1]))
    for name, path in paths:
        try:
            u = shutil.disk_usage(path)
            st = os.stat(path)
        except OSError:
            continue
        if st.st_dev in seen and name != "data":
            continue
        seen.add(st.st_dev)
        out.append({"name": name, "path": path, "total": u.total, "used": u.used,
                    "percent": round(100 * u.used / u.total, 1) if u.total else None})
    return out


# --- учёт трафика клиентов (nftables) ---------------------------------------------------------
ELEM_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+counter packets (\d+) bytes (\d+)")


def acct_ruleset(nets: list[str], variant: int = 0) -> str:
    """Своя таблица: две динамические таблицы адресов со счётчиком на каждый адрес LAN.
    policy accept — на пропуск трафика не влияет; таблица фаервола не трогается."""
    nets_s = "{ " + ", ".join(nets) + " }"
    set_flags = "flags dynamic; counter;" if variant else "flags dynamic;"
    return f"""add table inet {ACCT_TABLE}
delete table inet {ACCT_TABLE}
table inet {ACCT_TABLE} {{
    set up {{ type ipv4_addr; size 4096; {set_flags} }}
    set down {{ type ipv4_addr; size 4096; {set_flags} }}
    chain forward {{
        type filter hook forward priority filter - 1; policy accept;
        ip saddr {nets_s} update @up {{ ip saddr counter }}
        ip daddr {nets_s} update @down {{ ip daddr counter }}
    }}
}}
"""


def parse_acct(text: str) -> dict[str, int]:
    return {ip: int(b) for ip, _, b in ELEM_RE.findall(text or "")}


def _nft(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["nft", *args], input=stdin, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None


class Accounting:
    def __init__(self):
        self.nets: list[str] = []
        self.ok = False
        self.error: str | None = None

    def ensure(self, nets: list[str]) -> None:
        if nets == self.nets and (self.ok or not nets):
            return
        self.nets, self.ok = nets, False
        if not nets:
            _nft(["delete", "table", "inet", ACCT_TABLE])
            return
        last = None
        for variant in (0, 1):     # разные версии nft по-разному принимают счётчик в динамической таблице
            r = _nft(["-f", "-"], acct_ruleset(nets, variant))
            if r is None:
                self.error = "нет программы nft"
                return
            if r.returncode == 0:
                self.ok, self.error = True, None
                return
            last = r.stderr.strip()
        if self.error != last:
            print(f"[monitor] WARNING: учёт трафика клиентов недоступен: {last}")
        self.error = last

    def read(self) -> tuple[dict[str, int], dict[str, int]] | None:
        if not self.ok:
            return None
        res = []
        for s in ("up", "down"):
            r = _nft(["list", "set", "inet", ACCT_TABLE, s])
            if r is None or r.returncode != 0:
                self.ok = False         # таблицу удалили — пересоздать на следующем замере
                return None
            res.append(parse_acct(r.stdout))
        return res[0], res[1]

    def remove(self) -> None:
        _nft(["delete", "table", "inet", ACCT_TABLE])
        self.nets, self.ok = [], False


# --- сборщик --------------------------------------------------------------------------------
def _safe(fn, default=None):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 — один источник не должен ломать сбор
        print(f"[monitor] WARNING: {getattr(fn, '__name__', 'source')}: {e}")
        return default


def topology() -> dict:
    """Роли интерфейсов: WAN, мосты и порты сегментов, VLAN, VPN."""
    from app.services import lan, wan
    st = wan.load_state()
    roles: dict[str, tuple[str, str]] = {}
    multi = wan.multi()
    for name in (st.get("base"), st.get("interface")):
        if name:
            roles[name] = ("wan", "WAN1" if multi else "WAN")
    if multi:
        st2 = wan.load_state("wan2")
        for name in (st2.get("base"), st2.get("interface"), wan.get_config("wan2").interface):
            if name:
                roles.setdefault(name, ("wan", "WAN2"))
    segs = []
    for s in lan.segments():
        segs.append(s)
        if not s.enabled:
            continue
        roles[s.bridge] = ("lan", s.name)
        ls = lan.load_state(s.id)
        for p in ls.get("ports", []):
            roles.setdefault(p, ("port", s.name))
        for v in ls.get("vlans", []):
            roles.setdefault(v, ("vlan", s.name))
    for iface, label in VPN_IFACES.items():
        roles[iface] = ("vpn", label)
    nets = [str(s.network) for s in segs if s.enabled]
    return {"roles": roles, "wan": st.get("interface"), "segments": segs, "nets": nets}


class Collector:
    def __init__(self):
        self.history = History()
        self.acct = Accounting()
        self.snapshot: dict = {"time": None}
        self._prev_if: dict[str, dict] = {}
        self._prev_cpu = None
        self._prev_acct: tuple[dict, dict] | None = None
        self._prev_t: float | None = None
        self._slow: dict = {}
        self._tick = 0
        self._last_save = time.time()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=6, thread_name_prefix="og-ping")

    # --- жизненный цикл
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.load()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="og-monitor", daemon=True)
        self._thread.start()
        print("[monitor] сбор метрик запущен (раз в 10 с)")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        self.save()
        self.acct.remove()

    def _loop(self) -> None:
        while not self._stop.is_set():
            started = time.time()
            try:
                self.collect()
            except Exception as e:  # noqa: BLE001
                print(f"[monitor] ERROR: {e}")
            try:
                from app.services import dhcp
                dhcp.watch_interfaces()                  # Kea после пересоздания мостов
            except Exception as e:  # noqa: BLE001
                print(f"[dhcp] ERROR: {e}")
            if time.time() - self._last_save > SAVE_EVERY:
                self.save()
            self._stop.wait(max(1.0, INTERVAL - (time.time() - started)))

    # --- сохранение истории
    def save(self) -> None:
        try:
            _data().mkdir(parents=True, exist_ok=True)
            tmp = _data(".history.tmp")
            with gzip.open(tmp, "wt", encoding="utf-8") as f:
                json.dump(self.history.dump(), f, separators=(",", ":"))
            os.replace(tmp, _data("history.json.gz"))
            self._last_save = time.time()
        except OSError as e:
            print(f"[monitor] WARNING: история не сохранена: {e}")

    def load(self) -> None:
        try:
            with gzip.open(_data("history.json.gz"), "rt", encoding="utf-8") as f:
                self.history.load(json.load(f))
        except (OSError, ValueError, EOFError):
            pass

    # --- замер
    def collect(self, now: float | None = None) -> dict:
        now = now or time.time()
        dt = now - self._prev_t if self._prev_t else 0
        self._tick += 1
        topo = _safe(topology, {"roles": {}, "wan": None, "segments": [], "nets": []})
        roles = topo["roles"]

        # система
        cpu_now = cpu_times(_read(PROC / "stat"))
        cpu = cpu_percent(self._prev_cpu, cpu_now)
        self._prev_cpu = cpu_now
        mem = memory(_read(PROC / "meminfo"))
        load = None
        try:
            load = [round(x, 2) for x in os.getloadavg()]
        except OSError:
            pass
        up = _read(PROC / "uptime")
        from app.services import system
        temp = _safe(system.temperature)
        sysinfo = {"cpu": cpu, "cpu_count": os.cpu_count(), "memory": mem, "load": load,
                   "uptime": int(float(up.split()[0])) if up else None, "temperature": temp,
                   "disks": _safe(disks, [])}

        # интерфейсы
        counters = interface_counters()
        ifaces = []
        for name, c in counters.items():
            role, label = roles.get(name, ("", ""))
            prev = self._prev_if.get(name, {})
            item = {"name": name, "role": role, "label": label, **c,
                    "rx_rate": rate(prev.get("rx_bytes"), c["rx_bytes"], dt),
                    "tx_rate": rate(prev.get("tx_bytes"), c["tx_bytes"], dt)}
            ifaces.append(item)
        self._prev_if = counters
        order = {"wan": 0, "lan": 1, "vpn": 2, "vlan": 3, "port": 4, "": 5}
        ifaces.sort(key=lambda i: (order.get(i["role"], 9), i["name"]))

        # связь
        from app.services import wan
        gws = _safe(wan_gateways, []) if topo["wan"] else []
        gw = gws[0][1] if gws else None
        cfg = _safe(get_config)
        targets = list(gws)
        targets += [(t, t) for t in (cfg.ping_targets if cfg else []) if t not in {g for _, g in gws}]
        results = list(self._pool.map(lambda t: ping(t[1]), targets))
        pings = [{"name": n, "target": t, "rtt": r[0], "loss": r[1]} for (n, t), r in zip(targets, results)]

        # клиенты
        self.acct.ensure(topo["nets"])
        acct = self.acct.read()
        if self._tick % SLOW_EVERY == 1 or not self._slow:
            self._slow = self._collect_slow(topo)
        clients = self._clients(acct, dt, topo)
        self._prev_acct = acct

        wan_if = next((i for i in ifaces if i["role"] == "wan" and i["name"] == topo["wan"]), None)
        snap = {
            "time": now, "interval": INTERVAL, "system": sysinfo, "interfaces": ifaces, "ping": pings,
            "clients": clients, "accounting": self.acct.ok, "accounting_error": self.acct.error,
            "wan": {"interface": topo["wan"], "up": bool(wan_if and wan_if["up"]), "gateway": gw},
            "wans": _safe(wans_state, []),
            **self._slow,
        }
        self.snapshot = snap
        self._prev_t = now
        self._record(now, snap)
        _safe(lambda: write_current(snap))
        return snap

    def _collect_slow(self, topo: dict) -> dict:
        from app.services import files, lan, routing, vpn
        out: dict = {}
        now = time.time()
        leases = _safe(lan.leases, []) or []
        active = [x for x in leases if x.expires is None or x.expires > now]
        out["leases"] = [{"ip": x.ip, "mac": x.mac, "lan": x.lan, "name": x.name or x.hostname} for x in active]
        by_seg = {s.id: 0 for s in topo["segments"] if s.enabled}
        for x in active:
            by_seg[x.lan] = by_seg.get(x.lan, 0) + 1
        out["dhcp"] = [{"id": s.id, "name": s.name, "leases": by_seg.get(s.id, 0)}
                       for s in topo["segments"] if s.enabled]

        def _vpn():
            kind = vpn.enabled_kind()
            if not kind:
                return None
            st = vpn.status(kind)
            return {"kind": kind, "up": bool(st.connected)}
        out["vpn"] = _safe(_vpn)

        def _routing():
            if not routing.active():
                return None
            st = routing.status()
            return {"ospf_neighbors": sum(1 for n in st.ospf_neighbors if n.state.lower().startswith("full")),
                    "bgp": [{"peer": p.address, "remote_as": p.remote_as, "description": p.description,
                             "up": p.state.lower() == "established", "state": p.state,
                             "prefixes": p.prefixes_received} for p in st.bgp_peers]}
        out["routing"] = _safe(_routing)
        out["smb_sessions"] = _safe(lambda: len(files.sessions()) if files.running() else None)
        return out

    def _clients(self, acct, dt: float, topo: dict) -> list[dict]:
        if not acct:
            return []
        up, down = acct
        prev_up, prev_down = self._prev_acct or ({}, {})
        names = {x["ip"]: x for x in self._slow.get("leases", [])}
        nets = [(ipaddress.ip_network(str(s.network)), s.name) for s in topo["segments"] if s.enabled]
        out = []
        for ip in sorted(set(up) | set(down), key=lambda a: ipaddress.ip_address(a)):
            addr = ipaddress.ip_address(ip)
            seg = next((n for net, n in nets if addr in net), "")
            lease = names.get(ip, {})
            out.append({"ip": ip, "name": lease.get("name"), "mac": lease.get("mac"), "segment": seg,
                        "rx_bytes": down.get(ip, 0), "tx_bytes": up.get(ip, 0),
                        "rx_rate": rate(prev_down.get(ip), down.get(ip), dt) if self._prev_acct else None,
                        "tx_rate": rate(prev_up.get(ip), up.get(ip), dt) if self._prev_acct else None})
        return out

    def _record(self, now: float, snap: dict) -> None:
        h = self.history
        s = snap["system"]
        h.add(now, "cpu", s["cpu"])
        h.add(now, "mem", s["memory"].get("percent"))
        h.add(now, "temp", s["temperature"])
        h.add(now, "load", (s["load"] or [None])[0])
        for i in snap["interfaces"]:
            h.add(now, f"if:{i['name']}:rx", i["rx_rate"])
            h.add(now, f"if:{i['name']}:tx", i["tx_rate"])
        for p in snap["ping"]:
            h.add(now, f"ping:{p['name']}:rtt", p["rtt"])
            h.add(now, f"ping:{p['name']}:loss", p["loss"])
        if snap.get("leases") is not None:
            h.add(now, "clients", len(snap["leases"]))


collector = Collector()


def wan_gateways() -> list[tuple[str, str]]:
    """[("gateway", шлюз WAN1), ("gateway2", шлюз WAN2)] — до кого мерить задержку провайдера."""
    from app.services import multiwan, wan
    if not wan.multi():
        gw = wan.current_gateway()
        return [("gateway", gw)] if gw else []
    info = multiwan.wan_info()
    return [(name, info[w]["gateway"]) for w, name in (("wan1", "gateway"), ("wan2", "gateway2"))
            if info.get(w, {}).get("gateway")]


def wans_state() -> list[dict]:
    """Два провайдера: кто жив и через кого идёт трафик (один WAN — пусто)."""
    from app.services import multiwan, wan
    if not wan.multi():
        return []
    st = multiwan.status()
    return [{"id": w.id, "name": w.name, "interface": w.interface, "healthy": w.healthy, "active": w.active,
             "rtt": w.rtt, "gateway": w.gateway, "mode": st.config.mode} for w in st.wans]


# --- настройки -------------------------------------------------------------------------------
def get_config():
    from app.core.store import store
    from app.models.monitoring import MonitoringConfig
    return MonitoringConfig.model_validate(store.load().get("monitoring") or {})


def write_current(snap: dict) -> None:
    """Последний замер для Zabbix agent: плоские значения и списки для обнаружения (LLD)."""
    _data().mkdir(parents=True, exist_ok=True)
    os.chmod(_data(), 0o755)
    tmp = _data(".current.tmp")
    tmp.write_text(json.dumps(zabbix_values(snap), ensure_ascii=False))
    os.chmod(tmp, 0o644)
    os.replace(tmp, _data("current.json"))


def zabbix_values(snap: dict) -> dict:
    s = snap["system"]
    v: dict[str, object] = {
        "cpu": s["cpu"], "mem": s["memory"].get("percent"), "temp": s["temperature"],
        "load1": (s["load"] or [None])[0], "uptime": s["uptime"],
        "wan.up": int(snap["wan"]["up"]), "clients.active": len(snap.get("leases") or []),
        "wan2.healthy": next((int(bool(w["healthy"])) for w in snap.get("wans") or [] if w["id"] == "wan2"), -1),
        "wan.active": ",".join(w["name"] for w in snap.get("wans") or [] if w["active"]) or "WAN",
        "dhcp.leases": len(snap.get("leases") or []),
        "vpn.up": -1 if not snap.get("vpn") else int(snap["vpn"]["up"]),
        "smb.sessions": snap.get("smb_sessions") or 0,
    }
    r = snap.get("routing") or {}          # нет OSPF/BGP — нули, чтобы элементы Zabbix не были «не поддерживается»
    v["ospf.neighbors"] = r.get("ospf_neighbors") or 0
    v["bgp.peers"] = len(r.get("bgp") or [])
    v["bgp.up"] = sum(1 for p in r.get("bgp") or [] if p["up"])
    for d in s["disks"]:
        v[f"disk.pused:{d['name']}"] = d["percent"]
    ifs = []
    for i in snap["interfaces"]:
        if not i["role"]:
            continue
        ifs.append({"{#IFNAME}": i["name"], "{#ROLE}": i["role"], "{#LABEL}": i["label"] or i["name"]})
        v[f"if.rx:{i['name']}"] = i["rx_rate"]
        v[f"if.tx:{i['name']}"] = i["tx_rate"]
        v[f"if.up:{i['name']}"] = int(i["up"])
        v[f"if.errors:{i['name']}"] = i["rx_errors"] + i["tx_errors"]
    pings = []
    for p in snap["ping"]:
        pings.append({"{#TARGET}": p["target"], "{#NAME}": p["name"]})
        v[f"ping.rtt:{p['target']}"] = p["rtt"]
        v[f"ping.loss:{p['target']}"] = p["loss"]
    return {"time": snap["time"], "values": {k: x for k, x in v.items() if x is not None},
            "discovery": {"if": ifs, "ping": pings,
                          "disk": [{"{#DISK}": d["name"], "{#PATH}": d["path"]} for d in s["disks"]]}}


# --- выдача для веба -------------------------------------------------------------------------
def current() -> dict:
    snap = dict(collector.snapshot)
    snap.setdefault("interfaces", [])
    snap.pop("leases", None)
    return snap


def history(keys: list[str], tier: str, now: float | None = None) -> dict:
    if tier not in TIERS:
        raise ValueError("диапазон: 1h, 24h, 7d или 30d")
    now = now or time.time()
    return {"tier": tier, "series": {k: collector.history.series(k, tier, now) for k in keys[:40]}}
