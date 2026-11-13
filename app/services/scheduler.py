"""
Планировщик (/system scheduler): действия роутера по расписанию.

Поток раз в 15 секунд смотрит, не началась ли новая минута, и запускает задачи, расписание
которых совпало с этой минутой (местное время роутера). Пропущенные минуты (роутер был
выключен) не догоняются — как в RouterOS. Задача «один раз» после запуска выключается.
Журнал запусков — data/scheduler-log.json (последние 200 записей), он же в журнале действий.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from app.core.config import settings
from app.core.store import store
from app.models.scheduler import ACTIONS, RunRecord, SchedulerStatus, Task, TaskView

MAX_LOG = 200
KEEP_BACKUPS = 30
_lock = threading.RLock()
DAYS = ["пн", "вт", "ср", "чт", "пт", "сб", "вс"]


class SchedulerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _data(name: str) -> Path:
    return Path(settings.data_dir) / name


# --- задачи в router.yaml ------------------------------------------------------------------------
def tasks(data: dict | None = None) -> list[Task]:
    data = store.load() if data is None else data
    return [Task.model_validate(x) for x in (data.get("scheduler") or {}).get("tasks") or []]


def _save(items: list[Task]) -> None:
    with store.transaction() as data:
        data["scheduler"] = {"tasks": [t.model_dump(exclude_none=True) for t in items]}


def _find(items: list[Task], tid: int) -> int:
    for i, t in enumerate(items):
        if t.id == tid:
            return i
    raise SchedulerError(404, f"нет задачи {tid}")


def add(task: Task) -> Task:
    with _lock:
        items = tasks()
        task.id = max((t.id or 0 for t in items), default=0) + 1
        items.append(task)
        _save(items)
    return task


def update(tid: int, task: Task) -> Task:
    with _lock:
        items = tasks()
        task.id = tid
        items[_find(items, tid)] = task
        _save(items)
    return task


def delete(tid: int) -> None:
    with _lock:
        items = tasks()
        items.pop(_find(items, tid))
        _save(items)


# --- журнал ---------------------------------------------------------------------------------------
def log() -> list[dict]:
    try:
        return json.loads(_data("scheduler-log.json").read_text())
    except (OSError, ValueError):
        return []


def _log(rec: RunRecord) -> None:
    items = (log() + [rec.model_dump()])[-MAX_LOG:]
    path = _data("scheduler-log.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(".scheduler-log.tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False))
    os.replace(tmp, path)


# --- действия --------------------------------------------------------------------------------------
def _set_enabled_text(on: bool) -> str:
    return "включено" if on else "выключено"


def run_action(task: Task) -> str:
    """Выполнить действие задачи; текст — для журнала. Ошибка — исключение."""
    a = task.action
    if a.type == "wol":
        from app.services import tools
        r = tools.wol(a.mac, a.lan)
        return f"пакет отправлен на {r['mac']} ({', '.join(x['name'] for x in r['sent'])})"
    if a.type == "lan_segment":
        from app.services import lan
        seg = next((s for s in lan.segments() if a.lan in (s.id, s.name)), None)
        if not seg:
            raise SchedulerError(404, f"нет сегмента LAN «{a.lan}»")
        if seg.enabled == a.enabled:
            return f"сегмент {seg.name} уже {_set_enabled_text(a.enabled)}"
        lan.update_segment(seg.id, seg.model_copy(update={"enabled": a.enabled}))
        return f"сегмент {seg.name}: {_set_enabled_text(a.enabled)}"
    if a.type in ("firewall_rule", "port_forward"):
        from app.services import firewall_rules as fr
        items = fr.rules() if a.type == "firewall_rule" else fr.forwards()
        item = next((x for i, x in items if i == a.target), None)
        if item is None:
            raise SchedulerError(404, f"нет {'правила' if a.type == 'firewall_rule' else 'проброса'} {a.target}")
        new = item.model_copy(update={"enabled": a.enabled})
        (fr.update_rule if a.type == "firewall_rule" else fr.update_forward)(a.target, new)
        return f"{'правило' if a.type == 'firewall_rule' else 'проброс'} {a.target}: {_set_enabled_text(a.enabled)}"
    if a.type == "vpn":
        from app.services import vpn
        kind = vpn.enabled_kind() or _last_vpn_kind()
        if not kind:
            raise SchedulerError(400, "VPN не настроен")
        cfg = vpn.get_config(kind)
        if cfg.enabled == a.enabled:
            return f"VPN уже {_set_enabled_text(a.enabled)}"
        vpn.update(kind, cfg.model_copy(update={"enabled": a.enabled}))
        return f"VPN ({kind}): {_set_enabled_text(a.enabled)}"
    if a.type == "qos_device":
        from app.services import qos
        return qos.set_device_enabled(a.device, a.enabled)
    if a.type == "backup":
        return backup()
    if a.type == "wan_renew":
        from app.services import wan
        wan.renew(a.wan)
        return f"{a.wan.upper()}: запрошено обновление аренды"
    if a.type == "multiwan_primary":
        from app.services import multiwan
        cfg = multiwan.get_config()
        multiwan.update(cfg.model_copy(update={"primary": a.wan}))
        return f"основной канал — {a.wan.upper()}"
    if a.type == "restart":
        from app.services import system
        system.restart_service()
        return "сервис перезапускается"
    raise SchedulerError(400, f"неизвестное действие {a.type}")


def _last_vpn_kind() -> str | None:
    """VPN выключен — включать тот, что настроен (есть ключ или сервер)."""
    from app.services import vpn
    for kind in ("wireguard", "amneziawg", "l2tp"):
        cfg = vpn.get_config(kind)
        if getattr(cfg, "private_key", None) or getattr(cfg, "server", None):
            return kind
    return None


def backup() -> str:
    src = store.path
    if not src.exists():
        raise SchedulerError(400, "конфигурации ещё нет")
    d = _data("backups")
    d.mkdir(parents=True, exist_ok=True)
    name = f"router-{datetime.now().strftime('%Y%m%d-%H%M')}.yaml"
    shutil.copy2(src, d / name)
    for old in sorted(d.glob("router-*.yaml"))[:-KEEP_BACKUPS]:
        old.unlink(missing_ok=True)
    return f"резервная копия data/backups/{name}"


def execute(task: Task, manual: bool = False) -> RunRecord:
    try:
        msg = run_action(task)
        ok = True
    except Exception as e:  # noqa: BLE001 — любая ошибка — в журнал, планировщик продолжает работу
        msg = str(getattr(e, "message", None) or e)
        ok = False
    rec = RunRecord(time=datetime.now().astimezone().isoformat(timespec="seconds"), task=task.id,
                    name=task.name, ok=ok, message=msg, manual=manual)
    _log(rec)
    print(f"[scheduler] {task.name}: {'OK' if ok else 'ОШИБКА'} — {msg}")
    try:
        from app.services import system
        system.audit("scheduler", "RUN" if ok else "FAIL", f"{task.name}: {msg}", 200 if ok else 500, "-")
    except Exception:  # noqa: BLE001
        pass
    return rec


def run_now(tid: int) -> RunRecord:
    items = tasks()
    return execute(items[_find(items, tid)], manual=True)


def due(items: list[Task], minute: datetime) -> list[Task]:
    return [t for t in items if t.enabled and t.schedule.matches(minute)]


def tick(minute: datetime) -> list[RunRecord]:
    """Запустить задачи этой минуты. Задачи «один раз» — выключить."""
    items = tasks()
    out = []
    for t in due(items, minute):
        out.append(execute(t))
        if t.schedule.kind == "once":
            with _lock:
                cur = tasks()
                try:
                    i = _find(cur, t.id)
                except SchedulerError:
                    continue
                cur[i].enabled = False
                _save(cur)
    return out


def next_run(task: Task, after: datetime, horizon_days: int = 366) -> datetime | None:
    if not task.enabled:
        return None
    s = task.schedule
    dt = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    if s.kind == "once":
        at = datetime.fromisoformat(s.at)
        return at if at >= dt.replace(tzinfo=None) else None
    if s.kind == "interval":
        mins = dt.hour * 60 + dt.minute
        add_m = (-mins) % s.every
        cand = dt + timedelta(minutes=add_m)
        if cand.date() != dt.date():                      # шаг не делит сутки — с полуночи заново
            cand = (dt + timedelta(days=1)).replace(hour=0, minute=0)
        return cand
    if s.kind in ("daily", "weekly"):
        h, m = map(int, s.time.split(":"))
        for d in range(0, 8):
            cand = (dt + timedelta(days=d)).replace(hour=h, minute=m)
            if cand >= dt and (s.kind == "daily" or cand.weekday() in s.days):
                return cand
        return None
    end = dt + timedelta(days=horizon_days)          # cron — перебором минут, но с пропуском часов
    while dt < end:
        if s.matches(dt):
            return dt
        dt += timedelta(minutes=1)
    return None


def describe(task: Task, names: dict | None = None) -> str:
    s, a = task.schedule, task.action
    when = {"daily": f"каждый день в {s.time}",
            "weekly": f"{','.join(DAYS[d] for d in s.days)} в {s.time}",
            "interval": f"каждые {s.every} мин",
            "once": f"один раз {s.at.replace('T', ' ') if s.at else ''}",
            "cron": f"cron {s.cron}"}[s.kind]
    what = ACTIONS.get(a.type, a.type)
    detail = {"wol": a.mac, "lan_segment": a.lan, "firewall_rule": f"#{a.target}", "port_forward": f"#{a.target}",
              "qos_device": a.device, "wan_renew": a.wan.upper(), "multiwan_primary": a.wan.upper()}.get(a.type)
    onoff = {"lan_segment", "firewall_rule", "port_forward", "vpn", "qos_device"}
    if a.type in onoff:
        what = f"{'включить' if a.enabled else 'выключить'}"
        what += {"lan_segment": " сегмент", "firewall_rule": " правило", "port_forward": " проброс",
                 "vpn": " VPN", "qos_device": " ограничение"}[a.type]
    return f"{when} → {what}" + (f" {detail}" if detail else "")


# --- поток -------------------------------------------------------------------------------------------
class Runner:
    def __init__(self):
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last: str | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._last = datetime.now().strftime("%Y-%m-%dT%H:%M")    # текущую минуту не запускать при старте
        self._thread = threading.Thread(target=self._loop, name="og-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            now = datetime.now()
            key = now.strftime("%Y-%m-%dT%H:%M")
            if key != self._last:
                self._last = key
                try:
                    threading.Thread(target=tick, args=(now.replace(second=0, microsecond=0),),
                                     name="og-scheduler-tick", daemon=True).start()
                except Exception as e:  # noqa: BLE001
                    print(f"[scheduler] ERROR: {e}")
            self._stop.wait(15 - time.time() % 15 + 0.2)


runner = Runner()


# --- состояние для веба ------------------------------------------------------------------------------
def targets() -> dict:
    """Из чего выбирать в форме: сегменты, правила, проброс, устройства для WoL и QoS."""
    out: dict = {"segments": [], "rules": [], "forwards": [], "devices": [], "qos_devices": []}
    try:
        from app.services import lan
        segs = lan.segments()
        out["segments"] = [{"id": s.id, "name": s.name, "enabled": s.enabled} for s in segs]
        seen = set()
        for s in segs:
            for x in lan.static_leases(s.id):
                seen.add(x.mac)
                out["devices"].append({"mac": x.mac, "ip": x.ip, "name": x.name, "lan": s.id})
        for x in lan.leases():
            if x.mac not in seen:
                out["devices"].append({"mac": x.mac, "ip": x.ip, "name": x.name or x.hostname, "lan": x.lan})
    except Exception:  # noqa: BLE001
        pass
    try:
        from app.services import firewall_rules as fr
        out["rules"] = [{"id": i, "name": r.description or f"{r.chain} {r.action}", "enabled": r.enabled} for i, r in fr.rules()]
        out["forwards"] = [{"id": i, "name": f.description or f"{f.protocol} {f.wan_port} → {f.to_ip}", "enabled": f.enabled}
                           for i, f in fr.forwards()]
    except Exception:  # noqa: BLE001
        pass
    try:
        from app.services import qos
        out["qos_devices"] = [{"ip": d.ip, "name": d.name, "enabled": d.enabled} for d in qos.get_config().devices]
    except Exception:  # noqa: BLE001
        pass
    return out


def status() -> SchedulerStatus:
    from app.services import ntp
    now = datetime.now()
    last: dict[int, dict] = {}
    for r in log():
        last[r.get("task")] = r
    views = []
    for t in tasks():
        nr = next_run(t, now)
        lr = last.get(t.id) or {}
        views.append(TaskView(**t.model_dump(), next_run=nr.isoformat(timespec="minutes") if nr else None,
                              last_run=lr.get("time"), last_ok=lr.get("ok"), last_message=lr.get("message"),
                              description=describe(t)))
    return SchedulerStatus(tasks=views, log=[RunRecord(**r) for r in reversed(log()[-50:])],
                           timezone=ntp.current_timezone(), now=now.astimezone().isoformat(timespec="seconds"),
                           targets=targets())
