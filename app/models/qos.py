"""Схемы QoS (секция qos: в router.yaml): ограничения скорости и приоритет голосу.

Скорости — в Мбит/с. «Загрузка» (down) — к устройствам, «отдача» (up) — от устройств в интернет.
"""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator, model_validator

PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")
NAME_RE = re.compile(r"^[^\n\r\"\\]{0,64}$")


def _ports(v: str, what: str) -> str:
    parts = [p.strip() for p in (v or "").replace(";", ",").split(",") if p.strip()]
    if not parts:
        raise ValueError(f"{what}: укажите порты, например 5060-5061")
    for p in parts:
        if not PORTS_RE.match(p):
            raise ValueError(f"{what}: '{p}' — нужен порт или диапазон, например 10000-20000")
        lo, _, hi = p.partition("-")
        if not 1 <= int(lo) <= 65535 or (hi and not int(lo) <= int(hi) <= 65535):
            raise ValueError(f"{what}: '{p}' — порты от 1 до 65535")
    return ", ".join(parts)


class SegmentLimit(BaseModel):
    lan: str = Field(examples=["lan2"], description="Сегмент LAN")
    down: float | None = Field(None, gt=0, le=100000, description="Загрузка всего сегмента, Мбит/с")
    up: float | None = Field(None, gt=0, le=100000, description="Отдача всего сегмента, Мбит/с")


class DeviceLimit(BaseModel):
    ip: str = Field(examples=["192.168.88.20"])
    name: str | None = None
    down: float | None = Field(None, gt=0, le=100000)
    up: float | None = Field(None, gt=0, le=100000)
    enabled: bool = True

    @field_validator("ip")
    @classmethod
    def _ip(cls, v):
        try:
            return str(ipaddress.IPv4Address(v.strip()))
        except ValueError:
            raise ValueError(f"устройство: '{v}' — нужен IPv4-адрес") from None

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        v = (v or "").strip() or None
        if v and not NAME_RE.match(v):
            raise ValueError("имя: до 64 символов, без кавычек")
        return v

    @model_validator(mode="after")
    def _some(self):
        if self.down is None and self.up is None:
            raise ValueError(f"устройство {self.ip}: укажите загрузку или отдачу")
        return self


class QosConfig(BaseModel):
    enabled: bool = False
    wan_down: float | None = Field(None, gt=0, le=100000, description="Скорость провайдера: загрузка, Мбит/с")
    wan_up: float | None = Field(None, gt=0, le=100000, description="Скорость провайдера: отдача, Мбит/с")
    voice: bool = Field(True, description="Приоритет голосу: SIP и RTP вперёд остального трафика")
    sip_ports: str = "5060-5061"
    rtp_ports: str = "10000-20000"
    segments: list[SegmentLimit] = Field(default_factory=list)
    devices: list[DeviceLimit] = Field(default_factory=list)

    _s = field_validator("sip_ports")(classmethod(lambda cls, v: _ports(v, "порты SIP")))
    _r = field_validator("rtp_ports")(classmethod(lambda cls, v: _ports(v, "порты RTP")))

    @model_validator(mode="after")
    def _unique(self):
        ips = [d.ip for d in self.devices]
        dup = {x for x in ips if ips.count(x) > 1}
        if dup:
            raise ValueError(f"устройство {sorted(dup)[0]} указано дважды")
        self.segments = [s for s in self.segments if s.down or s.up]
        lans = [s.lan for s in self.segments]
        if len(lans) != len(set(lans)):
            raise ValueError("ограничение для сегмента указано дважды")
        return self

    def to_yaml(self) -> dict:
        return self.model_dump(exclude_none=True)


class QosClassStat(BaseModel):
    dev: str
    kind: str                       # voice / device / segment / default / wan
    label: str
    bytes: int = 0
    packets: int = 0
    drops: int = 0
    rate: float | None = None       # байт/с, по данным tc


class QosStatus(BaseModel):
    config: QosConfig
    active: bool = False
    error: str | None = None
    segments: list[dict] = Field(default_factory=list)    # id, name, network, bridge
    stats: list[QosClassStat] = Field(default_factory=list)
