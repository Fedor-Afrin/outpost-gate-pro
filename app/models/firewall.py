"""
Схемы раздела Firewall — в духе Security Lists Oracle Cloud:
у правила есть источник (CIDR), протокол, порты источника и назначения, описание.

  input    — входящие на сам роутер (веб, SSH, ping…)
  forward  — транзит через роутер: LAN ↔ WAN ↔ VPN
  Проброс портов (DNAT) — отдельный список: порт на WAN → устройство в LAN.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Zone = Literal["any", "wan", "lan", "vpn"]
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")


def normalize_ports(v: str | None) -> str | None:
    """'22' | '1000-2000' | '80, 443' -> канонический вид; пусто = все порты."""
    if not v or not v.strip():
        return None
    items = [x.strip() for x in v.split(",") if x.strip()]
    for item in items:
        if not PORTS_RE.match(item):
            raise ValueError(f"порт '{item}': ожидается 22, 1000-2000 или 80, 443")
        nums = [int(x) for x in item.split("-")]
        if not all(1 <= n <= 65535 for n in nums) or (len(nums) == 2 and nums[0] >= nums[1]):
            raise ValueError(f"порт '{item}' вне диапазона 1–65535")
    return ", ".join(items)


def port_set(v: str) -> str:
    """Порты в синтаксисе nft: 80 | 1000-2000 | { 80, 443 }."""
    return v if "," not in v else "{ " + v + " }"


def ports_cover(v: str | None, port: int) -> bool:
    if not v:
        return True
    for item in v.split(","):
        nums = [int(x) for x in item.strip().split("-")]
        if nums[0] <= port <= nums[-1]:
            return True
    return False


def normalize_cidr(v: str | None, what: str) -> str | None:
    if not v or not v.strip() or v.strip() in ("0.0.0.0/0", "any"):
        return None
    try:
        net = ipaddress.ip_network(v.strip(), strict=False)
    except ValueError as e:
        raise ValueError(f"{what}: неверная сеть '{v}' (пример: 203.0.113.0/24 или 192.168.88.20)") from e
    if net.version != 4:
        raise ValueError(f"{what}: нужен IPv4")
    return str(net)


class FirewallRule(BaseModel):
    chain: Literal["input", "forward"] = Field(description="input — на роутер, forward — транзит")
    enabled: bool = True
    action: Literal["accept", "drop", "reject"] = "accept"
    in_zone: Zone = Field("any", description="Откуда пришёл пакет")
    out_zone: Zone = Field("any", description="Куда уходит (только для транзита)")
    src: str | None = Field(None, description="Источник CIDR; пусто = 0.0.0.0/0", examples=["203.0.113.0/24"])
    dst: str | None = Field(None, description="Назначение CIDR (только для транзита)", examples=["192.168.88.20"])
    protocol: Literal["all", "tcp", "udp", "icmp"] = "all"
    src_ports: str | None = Field(None, examples=["1024-65535"])
    dst_ports: str | None = Field(None, examples=["22", "80, 443"])
    description: str | None = Field(None, max_length=120)

    @field_validator("src")
    @classmethod
    def _src(cls, v):
        return normalize_cidr(v, "источник")

    @field_validator("dst")
    @classmethod
    def _dst(cls, v):
        return normalize_cidr(v, "назначение")

    @field_validator("src_ports", "dst_ports")
    @classmethod
    def _ports(cls, v):
        return normalize_ports(v)

    @field_validator("description")
    @classmethod
    def _desc(cls, v):
        if v and ('"' in v or "\n" in v):
            raise ValueError("в описании нельзя кавычки и переводы строк")
        return v.strip() or None if v else None

    @model_validator(mode="after")
    def _consistent(self):
        if (self.src_ports or self.dst_ports) and self.protocol not in ("tcp", "udp"):
            raise ValueError("порты задаются только для TCP или UDP")
        if self.chain == "input":
            self.out_zone, self.dst = "any", None   # на роутер: назначение — сам роутер
        return self


class FirewallRuleView(FirewallRule):
    id: int
    packets: int = 0       # счётчик срабатываний правила
    bytes: int = 0


class PortForward(BaseModel):
    enabled: bool = True
    protocol: Literal["tcp", "udp", "tcp+udp"] = "tcp"
    wan_port: str = Field(examples=["8080", "5060-5070"])
    to_ip: str = Field(examples=["192.168.88.20"])
    to_port: int | None = Field(None, ge=1, le=65535, description="Пусто = тот же порт")
    src: str | None = Field(None, description="Разрешённые источники; пусто = все")
    description: str | None = Field(None, max_length=120)

    @field_validator("wan_port")
    @classmethod
    def _wan_port(cls, v):
        v = normalize_ports(v)
        if not v or "," in v:
            raise ValueError("порт WAN: один порт или диапазон, например 8080 или 5060-5070")
        return v

    @field_validator("to_ip")
    @classmethod
    def _to_ip(cls, v):
        ip = ipaddress.ip_address(v.strip())
        if ip.version != 4:
            raise ValueError("нужен IPv4-адрес устройства в LAN")
        return str(ip)

    @field_validator("src")
    @classmethod
    def _src(cls, v):
        return normalize_cidr(v, "источник")

    @field_validator("description")
    @classmethod
    def _desc(cls, v):
        if v and ('"' in v or "\n" in v):
            raise ValueError("в описании нельзя кавычки и переводы строк")
        return v.strip() or None if v else None

    @model_validator(mode="after")
    def _range(self):
        if "-" in self.wan_port and self.to_port:
            raise ValueError("для диапазона портов порт назначения не задаётся — порты сохраняются")
        return self


class PortForwardView(PortForward):
    id: int
    packets: int = 0
    bytes: int = 0


class FirewallStatus(BaseModel):
    active: bool                      # таблица применена (фаервол работает вместе с LAN)
    zones: dict[str, str | None]      # wan -> eth1, lan -> br-lan, vpn -> wg0 | None
    rules: list[FirewallRuleView]
    forwards: list[PortForwardView]
    system: dict[str, list[str]]      # автоматические правила человеческим языком
    management_ports: list[int]
