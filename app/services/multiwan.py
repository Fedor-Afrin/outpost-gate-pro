"""
Два провайдера: резерв (failover) или балансировка (balance).

Как устроено (только когда включён второй WAN; с одним WAN всё как раньше):
  * у каждого канала своя таблица маршрутов (wan1 — 101, wan2 — 102) с маршрутом по умолчанию
    через его шлюз и правила (ip rule):
        1000  lookup main suppress_prefixlength 0   — сначала обычные маршруты (LAN, VPN, /32 до сервера),
                                                      кроме маршрутов по умолчанию
        1010+ from <адрес канала> lookup <таблица>  — ответы и трафик самого роутера уходят в «свой» канал
        1020+ oif <интерфейс> lookup <таблица>      — проверка связи: ping -I eth2 идёт именно через eth2
        1030+ fwmark <метка> lookup <таблица>       — соединение остаётся в канале, где началось
  * метки соединений ставит фаервол (ct mark): новое соединение получает метку канала, через который
    вышло (или пришло — проброс портов), и все его пакеты дальше идут тем же каналом. Поэтому при
    возврате основного канала текущие загрузки и звонки не рвутся;
  * маршрут по умолчанию в основной таблице:
        failover — через действующий канал (metric 0) и запасной (metric 1);
        balance  — один маршрут с двумя nexthop и весами (ядро делит соединения по адресам);
  * проверка связи: раз в interval секунд ping до check_targets через каждый канал;
    fail_after неудач подряд — канал «упал», recover_after удач подряд — «вернулся».
    Упал канал — соединения через него сбрасываются (conntrack), чтобы сразу пошли через живой.

Состояние: data/multiwan.json (что поставлено в ядро) и data/multiwan-health.json (проверки).
Изменять маршруты может и DHCP-клиент (отдельный процесс) — поэтому файловая блокировка.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from app.core.config import settings
from app.core.store import store
from app.models.wan import MultiWanConfig, MultiWanStatus, WanHealth

TABLES = {"wan1": 101, "wan2": 102}
MARKS = {"wan1": 0x101, "wan2": 0x102}
RULE_PREFS = range(1000, 1040)
# метрики маршрутов по умолчанию: 0 — действующий канал (заменяет и маршрут Docker/системы с метрикой 0),
# 1 — запасной в режиме резерва
M_ACTIVE, M_STANDBY = "0", "1"
WANS = ("wan1", "wan2")
NAMES = {"wan1": "WAN1", "wan2": "WAN2"}
MAX_EVENTS = 30


class MultiWanError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _data(name: str) -> Path:
    return Path(settings.data_dir) / name


def get_config() -> MultiWanConfig:
    return MultiWanConfig.model_validate(store.load().get("multiwan") or {})


def enabled() -> bool:
    from app.services import wan
    return wan.multi()


def _read(name: str) -> dict:
    try:
        return json.loads(_data(name).read_text())
    except (OSError, ValueError):
        return {}


def _write(name: str, data: dict) -> None:
    path = _data(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=1))
    os.replace(tmp, path)


@contextmanager
def _locked():
    path = _data("multiwan.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def ip(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    """Команда iproute2. Подменяется в тестах."""
    try:
        r = subprocess.run(["ip", *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise MultiWanError(500, f"ip {' '.join(args)}: {e}") from e
    if check and r.returncode != 0:
        raise MultiWanError(400, f"ip {' '.join(args)}: {r.stderr.strip()}")
    return r


# --- что известно о каналах ------------------------------------------------------------------
def wan_info() -> dict[str, dict]:
    """{wan1: {interface, address (без маски), gateway}, wan2: {...}} — только включённые."""
    from app.services import wan
    out = {}
    for wid in WANS:
        if wid == "wan2" and not enabled():
            continue
        st = wan.load_state(wid)
        cfg = wan.get_config(wid)
        ifname = st.get("interface")
        addr = st.get("address")
        gw = st.get("gateway") or (cfg.gateway if cfg.mode == "static" else None)
        if cfg.mode == "none" and wid == "wan1":
            gw = gw or _kernel_gateway(ifname)      # адрес задан системой (Docker): шлюз — из ядра
            addr = addr or _kernel_address(ifname)
        out[wid] = {"interface": ifname, "address": addr.split("/")[0] if addr else None, "gateway": gw}
    return out


def _kernel_gateway(ifname: str | None) -> str | None:
    if not ifname:
        return None
    try:
        from app.services import netlink
        routes = [r for r in netlink.kernel_ipv4_routes()
                  if r["dst"] == "0.0.0.0/0" and r["interface"] == ifname and r["gateway"]]
        return sorted(routes, key=lambda r: r["metric"])[0]["gateway"] if routes else None
    except Exception:  # noqa: BLE001
        return None


def _kernel_address(ifname: str | None) -> str | None:
    if not ifname:
        return None
    try:
        from app.services import netlink
        return next((a for i, a in netlink.kernel_ipv4_addresses() if i == ifname), None)
    except Exception:  # noqa: BLE001
        return None


def load_health() -> dict:
    return _read("multiwan-health.json")


def reset_health() -> None:
    _write("multiwan-health.json", {"wans": {}, "events": load_health().get("events", [])})


def _healthy(health: dict, wid: str) -> bool | None:
    return (health.get("wans", {}).get(wid) or {}).get("healthy")


# --- план: что должно стоять в ядре ---------------------------------------------------------
def active_wans(cfg: MultiWanConfig, info: dict, health: dict) -> list[str]:
    """Каналы, через которые сейчас идёт новый трафик (по порядку предпочтения)."""
    usable = [w for w in WANS if w in info and info[w]["gateway"] and info[w]["interface"]]
    alive = [w for w in usable if _healthy(health, w) is not False]
    if cfg.mode == "failover":
        order = [cfg.primary] + [w for w in WANS if w != cfg.primary]
        pick = [w for w in order if w in alive] or [w for w in order if w in usable]
        return pick[:1]
    return alive or usable


def plan(cfg: MultiWanConfig, info: dict, health: dict) -> dict:
    """Чистая функция: таблицы, правила и маршруты по умолчанию (аргументы `ip`)."""
    tables, rules = [], [(1000, ["lookup", "main", "suppress_prefixlength", "0"])]
    for i, wid in enumerate(WANS):
        w = info.get(wid)
        if not w or not w["interface"]:
            continue
        t = str(TABLES[wid])
        if w["gateway"]:
            tables.append(["route", "replace", "default", "via", w["gateway"], "dev", w["interface"], "table", t])
        else:
            tables.append(["route", "flush", "table", t])
        if w["address"]:
            rules.append((1010 + i, ["from", w["address"], "lookup", t]))
        rules.append((1020 + i, ["oif", w["interface"], "lookup", t]))
        rules.append((1030 + i, ["fwmark", hex(MARKS[wid]), "lookup", t]))

    active = active_wans(cfg, info, health)
    main: list[list[str]] = []
    if cfg.mode == "failover" and active:
        a = active[0]
        main.append(["default", "via", info[a]["gateway"], "dev", info[a]["interface"], "metric", M_ACTIVE])
        for w in WANS:
            if w != a and w in info and info[w]["gateway"] and info[w]["interface"]:
                main.append(["default", "via", info[w]["gateway"], "dev", info[w]["interface"], "metric", M_STANDBY])
    elif cfg.mode == "balance" and active:
        if len(active) == 1:
            a = active[0]
            main.append(["default", "via", info[a]["gateway"], "dev", info[a]["interface"], "metric", M_ACTIVE])
        else:
            spec = ["default", "metric", M_ACTIVE]
            for w in active:
                weight = cfg.weight1 if w == "wan1" else cfg.weight2
                spec += ["nexthop", "via", info[w]["gateway"], "dev", info[w]["interface"], "weight", str(weight)]
            main.append(spec)
    return {"tables": tables, "rules": rules, "main": main, "active": active}


def _metric(spec: list[str]) -> str:
    return spec[spec.index("metric") + 1] if "metric" in spec else "0"


def _apply(p: dict, old: dict) -> None:
    for args in p["tables"]:
        r = ip(*args)
        if r.returncode != 0 and args[1] != "flush":
            print(f"[multiwan] WARNING: ip {' '.join(args)}: {r.stderr.strip()}")
    _clear_rules()
    for pref, args in p["rules"]:
        r = ip("rule", "add", "pref", str(pref), *args)
        if r.returncode != 0:
            print(f"[multiwan] WARNING: ip rule {pref} {' '.join(args)}: {r.stderr.strip()}")
    new_metrics = {_metric(s) for s in p["main"]}
    for spec in old.get("main", []):
        if _metric(spec) not in new_metrics:
            ip("route", "del", *spec)
    for spec in p["main"]:
        r = ip("route", "replace", *spec)
        if r.returncode != 0:
            print(f"[multiwan] WARNING: ip route replace {' '.join(spec)}: {r.stderr.strip()}")


RULE_RE = re.compile(r"^(\d+):")


def _clear_rules() -> None:
    r = ip("rule", "show")
    for line in (r.stdout or "").splitlines():
        m = RULE_RE.match(line.strip())
        if m and int(m.group(1)) in RULE_PREFS:
            ip("rule", "del", "pref", m.group(1))


def sync() -> list[str]:
    """Привести таблицы, правила и маршруты по умолчанию к текущему состоянию каналов."""
    if not enabled():
        return []
    with _locked():
        cfg = get_config()
        info = wan_info()
        health = load_health()
        old = _read("multiwan.json")
        p = plan(cfg, info, health)
        _apply(p, old)
        _write("multiwan.json", {"main": p["main"], "active": p["active"], "time": time.time(),
                                 "gateways": {w: v["gateway"] for w, v in info.items()}})
    if p["active"] != old.get("active"):
        print(f"[multiwan] трафик идёт через: {', '.join(NAMES[w] for w in p['active']) or '—'}")
    return p["active"]


def forget(wid: str) -> None:
    """Канал потерял адрес или выключается: убрать его таблицу и пересобрать маршруты."""
    ip("route", "flush", "table", str(TABLES[wid]))
    sync()


def teardown() -> None:
    """Снова один WAN: убрать таблицы, правила, маршруты мульти-WAN; маршрут WAN1 — как раньше."""
    from app.services import wan
    with _locked():
        old = _read("multiwan.json")
        _clear_rules()
        for wid in WANS:
            ip("route", "flush", "table", str(TABLES[wid]))
        for spec in old.get("main", []):
            ip("route", "del", *spec)
        _write("multiwan.json", {"main": [], "active": []})
    st = wan.load_state()
    gw = st.get("gateway") or (old.get("gateways") or {}).get("wan1")
    if gw:
        metric = "0" if wan.get_config().mode == "none" else str(wan.WAN_METRIC)   # как ставила система / роутер
        ip("route", "replace", "default", "via", gw, "metric", metric)
    print("[multiwan] второй WAN выключен — один канал")


def installed() -> bool:
    """В ядре остались маршруты мульти-WAN (после выключения или восстановления конфигурации)."""
    return bool(_read("multiwan.json").get("main"))


def active_gateway() -> str | None:
    info = wan_info()
    act = _read("multiwan.json").get("active") or active_wans(get_config(), info, load_health())
    for w in act:
        if info.get(w, {}).get("gateway"):
            return info[w]["gateway"]
    return next((v["gateway"] for v in info.values() if v["gateway"]), None)


def dns_order() -> list[str]:
    act = _read("multiwan.json").get("active") or []
    return act + [w for w in WANS if w not in act and (w == "wan1" or enabled())]


# --- проверка связи ---------------------------------------------------------------------------
TIME_RE = re.compile(r"time[=<]([\d.]+)")


def probe(ifname: str, targets: list[str]) -> tuple[bool, float | None]:
    """ping через конкретный интерфейс; канал жив, если ответил хоть один адрес."""
    for t in targets:
        try:
            r = subprocess.run(["ping", "-n", "-c", "1", "-W", "2", "-I", ifname, t],
                               capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            m = TIME_RE.search(r.stdout)
            return True, float(m.group(1)) if m else None
    return False, None


def step(health: dict, wid: str, ok: bool, rtt: float | None, cfg: MultiWanConfig, now: float) -> str | None:
    """Учесть одну проверку. Возвращает 'up' / 'down', если состояние канала сменилось."""
    h = health.setdefault("wans", {}).setdefault(wid, {"healthy": None, "fails": 0, "oks": 0, "since": now})
    if ok:
        h["oks"], h["fails"], h["rtt"] = h.get("oks", 0) + 1, 0, rtt
        if h.get("healthy") is None or (h["healthy"] is False and h["oks"] >= cfg.recover_after):
            changed = h.get("healthy") is False
            h["healthy"], h["since"] = True, now
            return "up" if changed else None
    else:
        h["fails"], h["oks"] = h.get("fails", 0) + 1, 0
        if h.get("healthy") is not False and h["fails"] >= cfg.fail_after:
            h["healthy"], h["since"] = False, now
            return "down"
    return None


def flush_conntrack(wid: str) -> None:
    """Соединения упавшего канала — сбросить: клиенты сразу переподключатся через живой."""
    try:
        subprocess.run(["conntrack", "-D", "-m", hex(MARKS[wid])], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass


class Checker:
    def __init__(self):
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="og-multiwan", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            interval = 5
            try:
                if enabled():
                    cfg = get_config()
                    interval = cfg.interval
                    self.check_once(cfg)
            except Exception as e:  # noqa: BLE001 — проверка не должна падать
                print(f"[multiwan] ERROR: {e}")
            self._stop.wait(interval)

    def check_once(self, cfg: MultiWanConfig, now: float | None = None) -> list[tuple[str, str]]:
        from app.services import system, vpn, wan
        now = now or time.time()
        info = wan_info()
        health = load_health()
        changes = []
        for wid, w in info.items():
            if w["interface"] and w["address"]:
                ok, rtt = probe(w["interface"], cfg.check_targets)
            else:
                ok, rtt = False, None          # нет адреса — канала нет
            ch = step(health, wid, ok, rtt, cfg, now)
            if ch:
                changes.append((wid, ch))
        for wid in list(health.get("wans", {})):
            if wid not in info:
                del health["wans"][wid]
        if not changes:
            _write("multiwan-health.json", health)
            return []
        before = _read("multiwan.json").get("active", [])
        _write("multiwan-health.json", health)
        active = sync()
        events = health.get("events", [])
        for wid, ch in changes:
            msg = f"{NAMES[wid]} {'упал' if ch == 'down' else 'вернулся'}; трафик: {', '.join(NAMES[w] for w in active) or '—'}"
            print(f"[multiwan] {msg}")
            events.append({"time": now, "wan": wid, "state": ch, "active": active})
            system.audit("multiwan", "EVENT", msg, 200, "-")
            if ch == "down":
                flush_conntrack(wid)
        health["events"] = events[-MAX_EVENTS:]
        _write("multiwan-health.json", health)
        if active != before:
            for step_fn in (vpn.refresh_endpoint_route, wan.refresh_upstream_dns):
                try:
                    step_fn()
                except Exception as e:  # noqa: BLE001
                    print(f"[multiwan] WARNING: {e}")
        return changes


checker = Checker()


# --- настройки и состояние ----------------------------------------------------------------------
def update(new: MultiWanConfig) -> MultiWanStatus:
    with store.transaction() as data:
        data["multiwan"] = new.to_yaml()
    try:
        sync()
    except MultiWanError as e:
        print(f"[multiwan] WARNING: {e.message}")
    from app.services import vpn, wan
    for fn in (vpn.refresh_endpoint_route, wan.refresh_upstream_dns):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            print(f"[multiwan] WARNING: {e}")
    return status()


def status() -> MultiWanStatus:
    from app.services import netlink, wan
    cfg = get_config()
    on = enabled()
    info = wan_info()
    health = load_health()
    active = _read("multiwan.json").get("active", []) if on else ["wan1"]
    out = []
    for wid in WANS:
        w = info.get(wid, {})
        h = (health.get("wans") or {}).get(wid, {})
        try:
            link = bool(netlink.link_info(w["interface"]).get("link_up")) if w.get("interface") else False
        except Exception:  # noqa: BLE001
            link = False
        out.append(WanHealth(id=wid, name=NAMES[wid], enabled=wid == "wan1" or on,
                             interface=w.get("interface") or (wan.get_config(wid).interface or None),
                             address=w.get("address"), gateway=w.get("gateway"), link_up=link,
                             healthy=h.get("healthy") if on else None, active=wid in active,
                             rtt=h.get("rtt"), since=h.get("since"), fails=h.get("fails", 0), oks=h.get("oks", 0)))
    return MultiWanStatus(config=cfg, enabled=on, wans=out, events=list(reversed(health.get("events", [])))[:10])
