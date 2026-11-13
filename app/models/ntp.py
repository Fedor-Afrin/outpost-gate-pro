"""Схемы NTP (секция ntp: в router.yaml): синхронизация времени роутера и раздача его в LAN."""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator

HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*$")


class NtpConfig(BaseModel):
    enabled: bool = Field(False, description="Включить NTP (chrony): синхронизация с серверами времени")
    servers: list[str] = Field(default_factory=lambda: ["pool.ntp.org"],
                               examples=[["pool.ntp.org", "time.google.com"]],
                               description="Серверы или пулы времени (имя или IPv4)")
    serve_lan: bool = Field(True, description="Раздавать время устройствам LAN (UDP 123), DHCP-опция 42 — роутер")
    orphan: bool = Field(False, description="Раздавать время, даже когда нет связи с серверами (stratum 10)")
    timezone: str | None = Field(None, examples=["Asia/Jerusalem"],
                                 description="Часовой пояс роутера (журнал, планировщик); пусто — как у системы")

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v):
        v = (v or "").strip() or None
        if v:
            from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
            try:
                ZoneInfo(v)
            except (ZoneInfoNotFoundError, ValueError):
                raise ValueError(f"часовой пояс '{v}' неизвестен — например Asia/Jerusalem или Europe/Moscow") from None
        return v

    @field_validator("servers")
    @classmethod
    def _servers(cls, v: list[str]) -> list[str]:
        out = []
        for x in v:
            x = (x or "").strip().lower()
            if not x:
                continue
            try:
                x = str(ipaddress.IPv4Address(x))
            except ValueError:
                if not HOST_RE.match(x):
                    raise ValueError(f"сервер времени '{x}': нужно имя (pool.ntp.org) или IPv4-адрес") from None
            if x not in out:
                out.append(x)
        if len(out) > 6:
            raise ValueError("серверов времени — не больше 6")
        return out

    def to_yaml(self) -> dict:
        return self.model_dump(exclude_none=True)


class NtpSource(BaseModel):
    address: str
    state: str = ""            # * — выбран, + — используется, - — отброшен, ? — нет связи, x — врёт, ~ — нестабилен
    stratum: int | None = None
    reach: int | None = None   # восьмеричная маска последних 8 опросов (377 — все ответили)
    offset: float | None = None  # секунды


class NtpStatus(BaseModel):
    config: NtpConfig
    installed: bool = True
    running: bool = False
    synced: bool = False
    stratum: int | None = None
    reference: str | None = None
    offset: float | None = None        # секунды: насколько часы системы расходятся с эталоном
    sources: list[NtpSource] = Field(default_factory=list)
    clock_control: bool = False        # роутер сам ставит часы системы (режим host); иначе — только раздаёт
    serving: list[str] = Field(default_factory=list)   # сети LAN, которым раздаётся время
    time: str | None = None
    timezone: str | None = None        # действующий часовой пояс
    timezones: list[str] = Field(default_factory=list)
    error: str | None = None
