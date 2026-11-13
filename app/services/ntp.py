"""
NTP: chrony синхронизирует время роутера и раздаёт его устройствам LAN.

Режим host — chrony сам подводит системные часы сервера. В Docker (dev, GNS3) часы общие
с хостом и менять их контейнеру нельзя: chrony работает с -x — следит за точностью и
раздаёт время LAN, а часы подводит сам хост.
Раздача в LAN — allow <сеть сегмента>; DHCP-опция 42 у сегментов без своих серверов
времени указывает на роутер. С WAN порт 123 закрыт фаерволом.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
from datetime import datetime
from pathlib import Path

from app.core.config import settings
from app.core.process import ManagedProcess
from app.core.store import store
from app.models.ntp import NtpConfig, NtpSource, NtpStatus

_chronyd = ManagedProcess("chronyd")
_lock = threading.RLock()
_error: str | None = None
RUN_DIR = Path(os.getenv("CHRONY_RUN_DIR", "/run/chrony"))


class NtpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _data(*parts: str) -> Path:
    return Path(settings.data_dir).joinpath("ntp", *parts)


def get_config() -> NtpConfig:
    return NtpConfig.model_validate(store.load().get("ntp") or {})


def clock_control() -> bool:
    return settings.mode == "host" or os.getenv("NTP_SET_CLOCK") == "1"


def lan_networks() -> list[str]:
    from app.services import lan
    try:
        return [str(s.network) for s in lan.segments() if s.enabled]
    except Exception:  # noqa: BLE001
        return []


def serves_lan(cfg: NtpConfig | None = None) -> bool:
    try:
        cfg = cfg or get_config()
    except Exception:  # noqa: BLE001
        return False
    return cfg.enabled and cfg.serve_lan


def chrony_conf(cfg: NtpConfig, nets: list[str], drift: Path) -> str:
    out = ["# сгенерировано OutpostGate Pro — не редактировать вручную"]
    for s in cfg.servers:
        kind = "pool" if "pool" in s.split(".")[0] or s.endswith("pool.ntp.org") else "server"
        out.append(f"{kind} {s} iburst")
    out += [f"driftfile {drift}",
            "makestep 1.0 3                  # большое расхождение при старте — сразу шагом",
            "maxupdateskew 100.0"]
    if cfg.serve_lan:
        out += [f"allow {n}" for n in nets]
        if cfg.orphan:
            out.append("local stratum 10 orphan        # без интернета — раздавать свои часы")
    out.append("cmdallow 127.0.0.1")
    return "\n".join(out) + "\n"


def installed() -> bool:
    return shutil.which("chronyd") is not None


def running() -> bool:
    return _chronyd.running()


def apply_timezone(tz: str | None) -> None:
    """Часовой пояс процесса роутера: время в журнале, вебе и расписании планировщика."""
    if not tz or os.environ.get("TZ") == tz:
        return
    os.environ["TZ"] = tz
    try:
        import time as _time
        _time.tzset()
    except AttributeError:
        pass
    print(f"[ntp] часовой пояс: {tz}")


def current_timezone() -> str:
    tz = os.environ.get("TZ")
    if tz:
        return tz
    try:
        link = os.readlink("/etc/localtime")
        return link.split("zoneinfo/", 1)[1]
    except (OSError, IndexError):
        return "UTC"


def apply(cfg: NtpConfig | None = None) -> None:
    global _error
    cfg = cfg or get_config()
    apply_timezone(cfg.timezone)
    with _lock:
        _chronyd.stop()
        if not cfg.enabled:
            _error = None
            return
        if not installed():
            raise NtpError(500, "нет chrony в образе — пересоберите образ (docker compose build)")
        _data().mkdir(parents=True, exist_ok=True)
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        conf = _data("chrony.conf")
        conf.write_text(chrony_conf(cfg, lan_networks(), _data("chrony.drift")))
        r = subprocess.run(["chronyd", "-p", "-f", str(conf)], capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            msg = " ".join((r.stderr or r.stdout).split())[-300:]
            raise NtpError(400, f"chrony не принял настройки: {msg}")
        cmd = ["chronyd", "-d", "-u", "root", "-f", str(conf)] + ([] if clock_control() else ["-x"])
        _chronyd.start(cmd)
        _error = None


def _refresh_dhcp() -> None:
    """Опция 42 зависит от раздачи времени — пересобрать конфиг DHCP."""
    from app.services import lan
    try:
        lan.reload_dhcp()
    except Exception as e:  # noqa: BLE001
        print(f"[ntp] WARNING: DHCP: {e}")


def update(new: NtpConfig) -> NtpStatus:
    old = get_config()
    raw_old = store.load().get("ntp")
    with store.transaction() as data:
        data["ntp"] = new.to_yaml()
    try:
        apply(new)
    except NtpError:
        with store.transaction() as data:
            if raw_old is None:
                data.pop("ntp", None)
            else:
                data["ntp"] = raw_old
        try:
            apply(old)
        except NtpError as e:
            print(f"[ntp] ERROR: откат не удался: {e.message}")
        raise
    if serves_lan(new) != serves_lan(old):
        _refresh_dhcp()
    return status()


def apply_startup() -> None:
    global _error
    try:
        apply()
    except NtpError as e:
        _error = e.message
        print(f"[ntp] ERROR: {e.message}")


def stop() -> None:
    _chronyd.stop()


def _zones() -> list[str]:
    try:
        from zoneinfo import available_timezones
        return sorted(z for z in available_timezones() if "/" in z and not z.startswith(("Etc/", "SystemV/", "posix/", "right/")))
    except Exception:  # noqa: BLE001
        return []


# --- состояние (chronyc) ----------------------------------------------------------------------
def parse_tracking(csv: str) -> dict:
    """chronyc -c tracking: RefID,имя,stratum,время,смещение системы,…,leap."""
    parts = (csv or "").strip().split(",")
    if len(parts) < 14:
        return {}
    try:
        stratum = int(parts[2])
        offset = float(parts[4])
    except ValueError:
        return {}
    leap = parts[13].strip().lower()
    return {"reference": parts[1] or None, "stratum": stratum, "offset": offset,
            "synced": stratum > 0 and leap != "not synchronised"}


def parse_sources(csv: str) -> list[NtpSource]:
    """chronyc -c sources: режим,состояние,адрес,stratum,poll,reach,lastrx,смещение,…"""
    out = []
    for line in (csv or "").splitlines():
        p = line.split(",")
        if len(p) < 8:
            continue
        try:
            out.append(NtpSource(address=p[2], state=p[1], stratum=int(p[3]), reach=int(p[5], 8),
                                 offset=float(p[7])))
        except ValueError:
            continue
    return out


def _chronyc(*args: str) -> str:
    try:
        r = subprocess.run(["chronyc", "-n", "-c", *args], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return r.stdout if r.returncode == 0 else ""


def status() -> NtpStatus:
    cfg = get_config()
    st = NtpStatus(config=cfg, installed=installed(), running=running(), clock_control=clock_control(),
                   serving=lan_networks() if serves_lan(cfg) else [],
                   time=datetime.now().astimezone().isoformat(timespec="seconds"), error=_error,
                   timezone=current_timezone(), timezones=_zones())
    if st.running:
        tr = parse_tracking(_chronyc("tracking"))
        st.synced, st.stratum = tr.get("synced", False), tr.get("stratum")
        st.reference, st.offset = tr.get("reference"), tr.get("offset")
        st.sources = parse_sources(_chronyc("sources"))
    elif cfg.enabled and not st.error:
        st.error = "chrony не запущен — см. docker logs"
    return st
