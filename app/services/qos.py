"""
QoS: ограничение скорости (сегменты, устройства) и приоритет голосу — Linux tc.

Загрузка (к устройствам) — очередь HTB на выходе моста сегмента (br-lan…):
    1:1   весь сегмент (его лимит или скорость провайдера)
    1:10  голос (DSCP EF) — prio 0, гарантированные 30 %
    1:1xx устройства со своим лимитом
    1:30  остальное
    в каждом классе fq_codel — без «раздутых» очередей (bufferbloat).
Отдача (от устройств) — ограничитель (police) на входе моста: сначала устройства, потом сегмент.
Голос в интернет — HTB на выходе WAN (если задана скорость отдачи провайдера), голос — первым.
Голос узнаётся по DSCP EF; фаервол сам ставит EF пакетам SIP и RTP (по портам) — так их видят
и телефоны, и очереди, и оборудование провайдера.
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
import threading

from app.core.store import store
from app.models.qos import QosClassStat, QosConfig, QosStatus

VOICE_SHARE = 0.3
LINK_MBIT = 10000           # «без лимита»: потолок очереди, когда скорость не задана
_lock = threading.RLock()
_error: str | None = None
_active = False


class QosError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def get_config() -> QosConfig:
    return QosConfig.model_validate(store.load().get("qos") or {})


def _rate(mbit: float) -> str:
    kbit = max(8, int(round(mbit * 1000)))
    return f"{kbit}kbit"


def _burst(mbit: float) -> str:
    return f"{max(16, int(mbit * 1000 / 8 / 10))}k"     # ~100 мс трафика, не меньше 16 КБ


def tc(*args: str) -> subprocess.CompletedProcess:
    """Команда tc. Подменяется в тестах."""
    try:
        return subprocess.run(["tc", *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise QosError(500, f"tc: {e}") from e


# --- план: команды tc -------------------------------------------------------------------------
def plan_segment(cfg: QosConfig, bridge: str, network: str, seg_id: str) -> list[list[str]]:
    """Очереди одного моста. Пусто — у сегмента нет ни лимитов, ни приоритета."""
    net = ipaddress.ip_network(network)
    lim = next((s for s in cfg.segments if s.lan == seg_id), None)
    devs = [d for d in cfg.devices if d.enabled and ipaddress.ip_address(d.ip) in net]
    down = (lim.down if lim and lim.down else None) or cfg.wan_down
    up = lim.up if lim else None
    cmds: list[list[str]] = []
    if down or cfg.voice or any(d.down for d in devs):
        total = down or LINK_MBIT
        cmds += [["qdisc", "add", "dev", bridge, "root", "handle", "1:", "htb", "default", "30"],
                 ["class", "add", "dev", bridge, "parent", "1:", "classid", "1:1", "htb",
                  "rate", _rate(total), "ceil", _rate(total)]]
        rest = total
        if cfg.voice:
            v = total * VOICE_SHARE
            rest = total - v
            cmds += [["class", "add", "dev", bridge, "parent", "1:1", "classid", "1:10", "htb",
                      "rate", _rate(v), "ceil", _rate(total), "prio", "0"],
                     ["qdisc", "add", "dev", bridge, "parent", "1:10", "handle", "10:", "fq_codel"],
                     ["filter", "add", "dev", bridge, "parent", "1:", "protocol", "ip", "prio", "1", "u32",
                      "match", "ip", "tos", "0xb8", "0xfc", "flowid", "1:10"]]
        for i, d in enumerate(devs):
            if not d.down:
                continue
            cid = f"{0x100 + i:x}"
            cmds += [["class", "add", "dev", bridge, "parent", "1:1", "classid", f"1:{cid}", "htb",
                      "rate", _rate(min(d.down, total)), "ceil", _rate(min(d.down, total)), "prio", "1"],
                     ["qdisc", "add", "dev", bridge, "parent", f"1:{cid}", "handle", f"{cid}:", "fq_codel"],
                     ["filter", "add", "dev", bridge, "parent", "1:", "protocol", "ip", "prio", "2", "u32",
                      "match", "ip", "dst", f"{d.ip}/32", "flowid", f"1:{cid}"]]
        cmds += [["class", "add", "dev", bridge, "parent", "1:1", "classid", "1:30", "htb",
                  "rate", _rate(max(rest, 0.1)), "ceil", _rate(total), "prio", "2"],
                 ["qdisc", "add", "dev", bridge, "parent", "1:30", "handle", "30:", "fq_codel"]]
    police = [d for d in devs if d.up]
    if police or up:
        cmds.append(["qdisc", "add", "dev", bridge, "handle", "ffff:", "ingress"])
        for d in police:
            cmds.append(["filter", "add", "dev", bridge, "parent", "ffff:", "protocol", "ip", "prio", "1", "u32",
                         "match", "ip", "src", f"{d.ip}/32", "police", "rate", _rate(d.up), "burst", _burst(d.up),
                         "drop", "flowid", ":1"])
        if up:
            cmds.append(["filter", "add", "dev", bridge, "parent", "ffff:", "protocol", "ip", "prio", "5", "u32",
                         "match", "ip", "src", str(net), "police", "rate", _rate(up), "burst", _burst(up),
                         "drop", "flowid", ":1"])
    return cmds


def plan_wan(cfg: QosConfig, iface: str) -> list[list[str]]:
    """Отдача в интернет: очередь чуть ниже скорости провайдера, голос — первым."""
    if not cfg.wan_up:
        return []
    u = cfg.wan_up
    cmds = [["qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "20"],
            ["class", "add", "dev", iface, "parent", "1:", "classid", "1:1", "htb", "rate", _rate(u), "ceil", _rate(u)]]
    rest = u
    if cfg.voice:
        rest = u * (1 - VOICE_SHARE)
        cmds += [["class", "add", "dev", iface, "parent", "1:1", "classid", "1:10", "htb",
                  "rate", _rate(u * VOICE_SHARE), "ceil", _rate(u), "prio", "0"],
                 ["qdisc", "add", "dev", iface, "parent", "1:10", "handle", "10:", "fq_codel"],
                 ["filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1", "u32",
                  "match", "ip", "tos", "0xb8", "0xfc", "flowid", "1:10"]]
    cmds += [["class", "add", "dev", iface, "parent", "1:1", "classid", "1:20", "htb",
              "rate", _rate(rest), "ceil", _rate(u), "prio", "1"],
             ["qdisc", "add", "dev", iface, "parent", "1:20", "handle", "20:", "fq_codel"]]
    return cmds


def _segments() -> list:
    from app.services import lan
    return [s for s in lan.segments() if s.enabled]


def _wans() -> list[str]:
    from app.services import wan
    try:
        return wan.active_interfaces()
    except Exception:  # noqa: BLE001
        return []


def firewall_ports(cfg: QosConfig | None = None) -> tuple[str, str] | None:
    """(порты SIP, порты RTP) — фаервол помечает их DSCP EF; None — приоритет голосу выключен."""
    try:
        cfg = cfg or get_config()
    except Exception:  # noqa: BLE001
        return None
    return (cfg.sip_ports, cfg.rtp_ports) if cfg.enabled and cfg.voice else None


# --- применение ---------------------------------------------------------------------------------
def clear(devs: list[str]) -> None:
    for d in devs:
        tc("qdisc", "del", "dev", d, "root")
        tc("qdisc", "del", "dev", d, "ingress")


def apply(cfg: QosConfig | None = None) -> None:
    """Пересобрать все очереди. Ошибки tc — в состояние (и docker logs), LAN от них не ломается."""
    global _error, _active
    cfg = cfg or get_config()
    with _lock:
        segs = _segments()
        wans = _wans()
        _active = False
        if not cfg.enabled:
            _error = None
            try:
                clear([s.bridge for s in segs] + wans)   # убрать очереди, если были
            except QosError:
                pass
            return
        clear([s.bridge for s in segs] + wans)
        cmds = []
        for s in segs:
            cmds += plan_segment(cfg, s.bridge, str(s.network), s.id)
        for w in wans:
            cmds += plan_wan(cfg, w)
        errors = []
        for args in cmds:
            r = tc(*args)
            if r.returncode != 0:
                errors.append(f"tc {' '.join(args[:5])}…: {(r.stderr or '').strip()[:150]}")
        _error = "; ".join(errors[:3]) or None
        _active = not errors
        if errors:
            print(f"[qos] ERROR: {_error}")
        else:
            print(f"[qos] очереди применены: команд tc — {len(cmds)}")


def update(new: QosConfig) -> QosStatus:
    from app.services import firewall
    with store.transaction() as data:
        data["qos"] = new.to_yaml()
    apply(new)
    try:
        firewall.refresh()            # метки DSCP для SIP и RTP
    except Exception as e:  # noqa: BLE001
        print(f"[qos] WARNING: фаервол: {e}")
    if _error:
        raise QosError(400, f"очереди не применились: {_error}")
    return status()


def set_device_enabled(ip: str, on: bool) -> str:
    cfg = get_config()
    dev = next((d for d in cfg.devices if d.ip == ip), None)
    if not dev:
        raise QosError(404, f"нет ограничения для {ip}")
    if dev.enabled == on:
        return f"ограничение {ip} уже {'включено' if on else 'выключено'}"
    dev.enabled = on
    update(cfg)
    return f"ограничение {ip}: {'включено' if on else 'выключено'}"


def apply_startup() -> None:
    try:
        apply()
    except QosError as e:
        print(f"[qos] ERROR: {e.message}")


# --- состояние -----------------------------------------------------------------------------------
def parse_class_stats(data: list, dev: str, labels: dict[str, tuple[str, str]]) -> list[QosClassStat]:
    out = []
    for c in data or []:
        h = c.get("handle")
        if h not in labels:
            continue
        kind, label = labels[h]
        st = c.get("stats") or {}
        rate = (c.get("rate_est") or {}).get("bps") if isinstance(c.get("rate_est"), dict) else None
        out.append(QosClassStat(dev=dev, kind=kind, label=label, bytes=st.get("bytes", 0),
                                packets=st.get("packets", 0), drops=st.get("drops", 0), rate=rate))
    return out


def stats(cfg: QosConfig) -> list[QosClassStat]:
    out = []
    for s in _segments():
        net = ipaddress.ip_network(str(s.network))
        devs = [d for d in cfg.devices if d.enabled and ipaddress.ip_address(d.ip) in net]
        labels = {"1:10": ("voice", f"{s.name}: голос"), "1:30": ("segment", f"{s.name}: остальное")}
        for i, d in enumerate(devs):
            labels[f"1:{0x100 + i:x}"] = ("device", d.name or d.ip)
        r = tc("-s", "-j", "class", "show", "dev", s.bridge)
        try:
            out += parse_class_stats(json.loads(r.stdout or "[]"), s.bridge, labels)
        except ValueError:
            pass
    for w in _wans():
        r = tc("-s", "-j", "class", "show", "dev", w)
        try:
            out += parse_class_stats(json.loads(r.stdout or "[]"), w,
                                     {"1:10": ("voice", f"{w}: голос"), "1:20": ("wan", f"{w}: остальное")})
        except ValueError:
            pass
    return out


def status() -> QosStatus:
    cfg = get_config()
    st = QosStatus(config=cfg, active=_active, error=_error)
    try:
        st.segments = [{"id": s.id, "name": s.name, "network": str(s.network), "bridge": s.bridge} for s in _segments()]
        if cfg.enabled:
            st.stats = stats(cfg)
    except Exception as e:  # noqa: BLE001
        st.error = st.error or str(e)
    return st
