"""
System: ресурсы устройства, имя роутера, резервные копии и откат, Safe Mode, журнал действий.

Safe Mode (как в MikroTik): перед рискованными изменениями включаете режим — роутер
запоминает текущий router.yaml. Пока веб-интерфейс открыт, он раз в несколько секунд
сообщает «я на связи». Если связь пропала дольше заданного времени (например, неудачное
правило фаервола отрезало доступ) — роутер сам возвращает запомненную конфигурацию.
«Подтвердить» — оставить изменения, «Откатить» — вернуть сразу. Если роутер
перезапустился посреди Safe Mode — при старте тоже откат.
"""
from __future__ import annotations

import glob
import json
import os
import platform
import shutil
import signal
import socket
import threading
import time
from datetime import datetime
from pathlib import Path

import yaml

from app.core.config import settings
from app.core.store import store

AUDIT_MAX_LINES = 5000


class SysError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _data(name: str) -> Path:
    return Path(settings.data_dir) / name


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


# --- ресурсы ---------------------------------------------------------------------------------
_cpu_last: tuple[int, int] | None = None


def _cpu_times(stat: str) -> tuple[int, int]:
    """(idle, total) из первой строки /proc/stat."""
    nums = [int(x) for x in stat.splitlines()[0].split()[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    return idle, sum(nums)


def cpu_percent(stat: str | None = None) -> float | None:
    """Загрузка CPU с прошлого запроса (веб опрашивает раз в несколько секунд)."""
    global _cpu_last
    stat = stat or _read("/proc/stat")
    if not stat:
        return None
    now = _cpu_times(stat)
    last, _cpu_last = _cpu_last, now
    if not last or now[1] == last[1]:
        return None
    return round(100 * (1 - (now[0] - last[0]) / (now[1] - last[1])), 1)


def parse_meminfo(text: str) -> dict:
    vals = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if rest.strip():
            vals[key] = int(rest.split()[0]) * 1024
    total = vals.get("MemTotal", 0)
    avail = vals.get("MemAvailable", vals.get("MemFree", 0))
    return {"total": total, "used": total - avail, "percent": round(100 * (total - avail) / total, 1) if total else None}


def device_model() -> str | None:
    for path in ("/sys/firmware/devicetree/base/model", "/sys/class/dmi/id/product_name"):
        if v := _read(path):
            return v.strip("\x00")
    for line in (_read("/proc/cpuinfo") or "").splitlines():
        if line.lower().startswith(("model name", "hardware")):
            return line.split(":", 1)[1].strip()
    return None


def temperature() -> float | None:
    temps = []
    for path in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            temps.append(int(_read(path)) / 1000)
        except (TypeError, ValueError):
            pass
    return round(max(temps), 1) if temps else None


def identity() -> str:
    return (store.load().get("system") or {}).get("identity") or "outpost-gate-pro"


def set_identity(name: str) -> str:
    name = (name or "").strip()
    if not 1 <= len(name) <= 48 or any(c in name for c in "<>\"'\n"):
        raise SysError(422, "имя: от 1 до 48 символов, без кавычек и < >")
    with store.transaction() as data:
        sysd = data.get("system") or {}
        sysd["identity"] = name
        data["system"] = sysd
    return name


def resource() -> dict:
    from app.services import sysctl
    uptime = _read("/proc/uptime")
    disk = shutil.disk_usage(settings.data_dir if os.path.exists(settings.data_dir) else "/")
    return {
        "identity": identity(),
        "hostname": socket.gethostname(),
        "version": settings.version,
        "mode": settings.mode,
        "kernel": platform.release(),
        "arch": platform.machine(),
        "model": device_model(),
        "cpu_count": os.cpu_count(),
        "cpu_percent": cpu_percent(),
        "load": [round(x, 2) for x in os.getloadavg()],
        "memory": parse_meminfo(_read("/proc/meminfo") or ""),
        "disk": {"total": disk.total, "used": disk.used, "percent": round(100 * disk.used / disk.total, 1)},
        "uptime": int(float(uptime.split()[0])) if uptime else None,
        "temperature": temperature(),
        "time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "ip_forward": sysctl.get_ip_forward(),
    }


# --- проверка и применение конфигурации -----------------------------------------------------------------
def validate_config(data) -> None:
    """Проверить весь router.yaml теми же моделями, что и API. Ошибка -> SysError 422."""
    from app.models.l2tp import L2tpConfig
    from app.models.lan import LanConfig, StaticLease
    from app.models.monitoring import MonitoringConfig
    from app.models.dns import DnsConfig
    from app.models.files import FilesConfig
    from app.models.routing import RoutingConfig
    from app.models.wan import MultiWanConfig, Wan2Config, WanConfig
    from app.models.ntp import NtpConfig
    from app.models.qos import QosConfig
    from app.models.scheduler import Task
    from app.models.wireguard import WgConfig
    from app.services import firewall_rules
    if not isinstance(data, dict):
        raise SysError(422, "это не конфигурация роутера (ожидается YAML-словарь)")
    try:
        WanConfig(**(data.get("wan") or {}))
        Wan2Config(**(data.get("wan2") or {}))
        MultiWanConfig.model_validate(data.get("multiwan") or {})
        NtpConfig.model_validate(data.get("ntp") or {})
        QosConfig.model_validate(data.get("qos") or {})
        for t in (data.get("scheduler") or {}).get("tasks") or []:
            Task.model_validate(t)
        LanConfig.from_yaml(data.get("lan"), data.get("firewall"))
        for s in (((data.get("lan") or {}).get("dhcp-server") or {}).get("static-leases") or []):
            StaticLease(**s)
        vpn = data.get("vpn") or {}
        WgConfig.from_yaml(vpn.get("wireguard"))
        WgConfig.from_yaml(vpn.get("amneziawg"))
        L2tpConfig.from_yaml(vpn.get("l2tp"))
        fw = data.get("firewall") or {}
        for d in fw.get("rules") or []:
            firewall_rules.FirewallRule(**firewall_rules._from_yaml(d, firewall_rules._RULE_KEYS))
        for d in fw.get("forwards") or []:
            firewall_rules.PortForward(**firewall_rules._from_yaml(d, firewall_rules._FWD_KEYS))
        RoutingConfig.model_validate(data.get("routing") or {})
        for item in data.get("lans") or []:
            LanConfig.from_yaml(item, data.get("firewall"))
        if data.get("dns") is not None:
            DnsConfig.model_validate(data["dns"])
        FilesConfig.model_validate(data.get("files") or {})
        MonitoringConfig.model_validate(data.get("monitoring") or {})
        for section in ("addresses", "routes"):
            items = (data.get("ip") or {}).get(section) or []
            if not isinstance(items, list):
                raise ValueError(f"ip.{section} должен быть списком")
    except SysError:
        raise
    except Exception as e:
        raise SysError(422, f"конфигурация не прошла проверку: {e}") from e


def reapply() -> None:
    """Привести систему к текущему router.yaml (как при старте роутера)."""
    from app.agent import apply as agent
    agent.apply_startup()


def restore_text(text: str, source: str) -> None:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SysError(422, f"файл не читается как YAML: {e}") from e
    validate_config(data)
    store.save(data)                     # текущая версия уходит в снимки — откат возможен
    print(f"[system] конфигурация восстановлена из: {source}")
    reapply()


def backup_text() -> str:
    return store.path.read_text() if store.path.exists() else ""


def snapshots() -> list[dict]:
    out = []
    for p in sorted(store.snapshots_dir.glob("router-*.yaml"), reverse=True):
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size,
                    "time": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(timespec="seconds")})
    return out


def snapshot_path(name: str) -> Path:
    p = store.snapshots_dir / name
    if "/" in name or not name.startswith("router-") or not p.exists():
        raise SysError(404, "нет такого снимка")
    return p


def restore_snapshot(name: str) -> None:
    restore_text(snapshot_path(name).read_text(), f"снимок {name}")


# --- Safe Mode ------------------------------------------------------------------------------------------
class SafeMode:
    def __init__(self):
        self._lock = threading.RLock()
        self.active = False
        self.timeout = 60
        self.deadline = 0.0
        self.started = None
        self.user = None
        self.last_event: dict | None = None

    def file(self) -> Path:
        return _data("safe-mode.yaml")

    def status(self, heartbeat: bool = False) -> dict:
        with self._lock:
            if heartbeat and self.active:
                self.deadline = time.time() + self.timeout
            return {"active": self.active, "timeout": self.timeout, "user": self.user, "started": self.started,
                    "seconds_left": max(0, int(self.deadline - time.time())) if self.active else None,
                    "last_event": self.last_event}

    def start(self, timeout: int, user: str) -> dict:
        if not 15 <= timeout <= 900:
            raise SysError(422, "время ожидания связи: от 15 до 900 секунд")
        with self._lock:
            if self.active:
                raise SysError(409, f"Safe Mode уже включён ({self.user})")
            self.file().parent.mkdir(parents=True, exist_ok=True)
            self.file().write_text(backup_text())
            self.active, self.timeout, self.user = True, timeout, user
            self.started = datetime.now().astimezone().isoformat(timespec="seconds")
            self.deadline = time.time() + timeout
            self.last_event = None
            threading.Thread(target=self._watch, daemon=True).start()
            print(f"[safe-mode] включён ({user}), откат при потере связи на {timeout} с")
            return self.status()

    def _watch(self) -> None:
        while True:
            time.sleep(1)
            with self._lock:
                if not self.active:
                    return
                if time.time() > self.deadline:
                    self._rollback(f"нет связи с веб-интерфейсом дольше {self.timeout} с")
                    return

    def commit(self) -> dict:
        with self._lock:
            if not self.active:
                raise SysError(409, "Safe Mode не включён")
            self.active = False
            self.file().unlink(missing_ok=True)
            self.last_event = {"type": "commit", "time": datetime.now().astimezone().isoformat(timespec="seconds")}
            print("[safe-mode] изменения подтверждены")
            return self.status()

    def rollback(self, reason: str = "откат вручную") -> dict:
        with self._lock:
            if not self.active:
                raise SysError(409, "Safe Mode не включён")
            self._rollback(reason)
            return self.status()

    def _rollback(self, reason: str) -> None:
        """Режим считается выключенным только ПОСЛЕ того, как конфигурация вернулась."""
        text = self.file().read_text() if self.file().exists() else None
        print(f"[safe-mode] ОТКАТ: {reason}")
        audit("safe-mode", "ROLLBACK", reason, 200, "-")
        try:
            if text is not None:
                restore_text(text, "Safe Mode")
        finally:
            self.file().unlink(missing_ok=True)
            self.last_event = {"type": "rollback", "reason": reason,
                               "time": datetime.now().astimezone().isoformat(timespec="seconds")}
            self.active = False

    def recover_on_startup(self) -> None:
        """Роутер перезапустился посреди Safe Mode — вернуть запомненную конфигурацию до применения."""
        if self.file().exists():
            print("[safe-mode] найден незавершённый Safe Mode — возвращаю конфигурацию")
            try:
                store.save(yaml.safe_load(self.file().read_text()))
            finally:
                self.file().unlink(missing_ok=True)
            self.last_event = {"type": "rollback", "reason": "перезапуск роутера в Safe Mode",
                               "time": datetime.now().astimezone().isoformat(timespec="seconds")}


safe_mode = SafeMode()


# --- журнал действий (аудит) ----------------------------------------------------------------------------------
_audit_lock = threading.Lock()


def audit(user: str, method: str, path: str, status: int, ip: str) -> None:
    """Кто, когда, что изменил. JSON по строке; старые записи отрезаются."""
    entry = {"time": datetime.now().astimezone().isoformat(timespec="seconds"), "user": user,
             "method": method, "path": path, "status": status, "ip": ip}
    f = _data("audit.log")
    with _audit_lock:
        try:
            f.parent.mkdir(parents=True, exist_ok=True)
            with f.open("a") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            if f.stat().st_size > AUDIT_MAX_LINES * 200:
                lines = f.read_text().splitlines()[-AUDIT_MAX_LINES:]
                f.write_text("\n".join(lines) + "\n")
        except OSError as e:
            print(f"[audit] WARNING: {e}")


def audit_log(limit: int = 200) -> list[dict]:
    try:
        lines = _data("audit.log").read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in reversed(lines[-limit:]):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


# --- перезапуск ------------------------------------------------------------------------------------------------
def restart_service() -> None:
    """Завершить процесс: uvicorn корректно остановит DHCP, DNS и VPN, Docker запустит контейнер заново."""
    def later():
        time.sleep(1)
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=later, daemon=True).start()
