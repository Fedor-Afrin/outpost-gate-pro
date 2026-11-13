"""Схемы планировщика (секция scheduler: в router.yaml), как /system scheduler в RouterOS.

Расписание:
  daily    — каждый день в time (ЧЧ:ММ)
  weekly   — в выбранные дни недели (0 — понедельник … 6 — воскресенье) в time
  interval — каждые every минут, считая от полуночи (every=15 → 00:00, 00:15, 00:30…)
  once     — один раз: at (ГГГГ-ММ-ДДTЧЧ:ММ), потом задача выключается
  cron     — выражение cron из 5 полей: минута час день месяц день-недели (0/7 — воскресенье)
Время — по часовому поясу роутера (System → Время).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
NAME_RE = re.compile(r"^[^\n\r\"\\]{1,64}$")

ACTIONS = {
    "wol": "Разбудить компьютер (Wake-on-LAN)",
    "lan_segment": "Включить или выключить сегмент LAN",
    "firewall_rule": "Включить или выключить правило фаервола",
    "port_forward": "Включить или выключить проброс порта",
    "vpn": "Включить или выключить VPN",
    "qos_device": "Включить или выключить ограничение устройства (QoS)",
    "backup": "Сохранить резервную копию конфигурации",
    "wan_renew": "Обновить аренду DHCP на WAN",
    "multiwan_primary": "Сделать основным WAN1 или WAN2",
    "restart": "Перезапустить сервис роутера",
}


# --- cron -----------------------------------------------------------------------------------
def _cron_field(text: str, lo: int, hi: int) -> set[int]:
    out: set[int] = set()
    for part in text.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            if not s.isdigit() or int(s) < 1:
                raise ValueError(f"cron: неверный шаг '{s}'")
            step = int(s)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            x, y = part.split("-", 1)
            if not (x.isdigit() and y.isdigit()):
                raise ValueError(f"cron: неверный диапазон '{part}'")
            a, b = int(x), int(y)
        elif part.isdigit():
            a = b = int(part)
            if step > 1:
                b = hi
        else:
            raise ValueError(f"cron: неверное значение '{part}'")
        if a < lo or b > hi or a > b:
            raise ValueError(f"cron: значение '{part}' вне диапазона {lo}–{hi}")
        out.update(range(a, b + 1, step))
    return out


def parse_cron(expr: str) -> tuple[set[int], ...]:
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError("cron: нужно 5 полей — минута час день месяц день-недели, например 0 8 * * 1-5")
    minute = _cron_field(parts[0], 0, 59)
    hour = _cron_field(parts[1], 0, 23)
    dom = _cron_field(parts[2], 1, 31)
    month = _cron_field(parts[3], 1, 12)
    dow = {d % 7 for d in _cron_field(parts[4], 0, 7)}
    return minute, hour, dom, month, dow, (parts[2] == "*", parts[4] == "*")


def cron_match(expr: str, dt: datetime) -> bool:
    minute, hour, dom, month, dow, (dom_any, dow_any) = parse_cron(expr)
    if dt.minute not in minute or dt.hour not in hour or dt.month not in month:
        return False
    cron_dow = (dt.weekday() + 1) % 7            # cron: 0 — воскресенье
    day_ok = dt.day in dom
    dow_ok = cron_dow in dow
    if dom_any and dow_any:
        return True
    if dom_any:
        return dow_ok
    if dow_any:
        return day_ok
    return day_ok or dow_ok                       # как в cron: любое из двух условий


# --- задача -----------------------------------------------------------------------------------
class Schedule(BaseModel):
    kind: Literal["daily", "weekly", "interval", "once", "cron"] = "daily"
    time: str = Field("08:00", description="ЧЧ:ММ для daily и weekly")
    days: list[int] = Field(default_factory=lambda: [0, 1, 2, 3, 4], description="0 — понедельник … 6 — воскресенье")
    every: int = Field(60, ge=1, le=1440, description="Минуты для interval")
    at: str | None = Field(None, examples=["2026-12-31T23:59"], description="Дата и время для once")
    cron: str | None = Field(None, examples=["*/15 8-18 * * 1-5"])

    @field_validator("time")
    @classmethod
    def _time(cls, v):
        if not TIME_RE.match(v or ""):
            raise ValueError("время: ЧЧ:ММ, например 08:00")
        return v

    @field_validator("days")
    @classmethod
    def _days(cls, v):
        out = sorted({int(d) for d in v})
        if any(d < 0 or d > 6 for d in out):
            raise ValueError("дни недели: 0 (понедельник) … 6 (воскресенье)")
        return out

    @model_validator(mode="after")
    def _check(self):
        if self.kind == "weekly" and not self.days:
            raise ValueError("выберите хотя бы один день недели")
        if self.kind == "once":
            try:
                self.at = datetime.fromisoformat((self.at or "").strip()).strftime("%Y-%m-%dT%H:%M")
            except ValueError:
                raise ValueError("дата и время запуска: ГГГГ-ММ-ДД ЧЧ:ММ") from None
        if self.kind == "cron":
            self.cron = " ".join((self.cron or "").split())
            parse_cron(self.cron)
        return self

    def matches(self, dt: datetime) -> bool:
        """Совпадает ли минута dt (местное время) с расписанием."""
        hm = dt.strftime("%H:%M")
        if self.kind == "daily":
            return hm == self.time
        if self.kind == "weekly":
            return hm == self.time and dt.weekday() in self.days
        if self.kind == "interval":
            return (dt.hour * 60 + dt.minute) % self.every == 0
        if self.kind == "once":
            return dt.strftime("%Y-%m-%dT%H:%M") == self.at
        return cron_match(self.cron, dt)


class Action(BaseModel):
    type: str = Field(examples=list(ACTIONS))
    mac: str | None = None            # wol
    lan: str | None = None            # wol (сегмент), lan_segment
    target: int | None = None         # firewall_rule / port_forward — id правила
    device: str | None = None         # qos_device — IP устройства
    enabled: bool = True              # включить или выключить
    wan: Literal["wan1", "wan2"] = "wan1"   # wan_renew, multiwan_primary

    @model_validator(mode="after")
    def _check(self):
        if self.type not in ACTIONS:
            raise ValueError(f"неизвестное действие '{self.type}'")
        need = {"wol": "mac", "lan_segment": "lan", "firewall_rule": "target", "port_forward": "target",
                "qos_device": "device"}.get(self.type)
        if need and getattr(self, need) in (None, ""):
            raise ValueError(f"для действия «{ACTIONS[self.type]}» не указано, к чему оно относится")
        return self


class Task(BaseModel):
    id: int | None = None
    name: str = Field(examples=["Разбудить ПК бухгалтера"])
    enabled: bool = True
    schedule: Schedule = Field(default_factory=Schedule)
    action: Action

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        v = (v or "").strip()
        if not NAME_RE.match(v):
            raise ValueError("название задачи: от 1 до 64 символов, без кавычек")
        return v


class TaskView(Task):
    next_run: str | None = None       # ISO, местное время
    last_run: str | None = None
    last_ok: bool | None = None
    last_message: str | None = None
    description: str = ""             # «каждый будний день в 08:00 → разбудить …»


class RunRecord(BaseModel):
    time: str
    task: int | None
    name: str
    ok: bool
    message: str
    manual: bool = False


class SchedulerStatus(BaseModel):
    tasks: list[TaskView]
    log: list[RunRecord]
    timezone: str
    now: str
    actions: dict[str, str] = ACTIONS
    targets: dict = Field(default_factory=dict)   # из чего выбирать: сегменты, правила, устройства
