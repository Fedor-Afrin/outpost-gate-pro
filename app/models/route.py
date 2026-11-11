"""Схемы раздела IP → Routes (аналог /ip route)."""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator

IFNAME_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,15}$")


def normalize_dst(value: str) -> str:
    """'10.1.2.3/8' -> '10.0.0.0/8'; без маски -> /32; 'default' -> 0.0.0.0/0."""
    value = value.strip()
    if value in ("default", "0.0.0.0/0", ""):
        return "0.0.0.0/0"
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as e:
        raise ValueError(f"неверная сеть назначения '{value}': ожидается формат 10.0.0.0/8") from e
    if net.version != 4:
        raise ValueError("здесь только IPv4 (IPv6 будет в разделе /ipv6 route)")
    return str(net)


def normalize_gateway(value: str) -> str:
    """Шлюз — IPv4-адрес (192.168.1.1) или имя интерфейса (eth1, wg0)."""
    value = value.strip()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        if IFNAME_RE.match(value):
            return value
        raise ValueError(f"шлюз '{value}': нужен IPv4-адрес или имя интерфейса")
    if ip.version != 4:
        raise ValueError("здесь только IPv4-шлюз")
    return str(ip)


def gateway_is_ip(gateway: str) -> bool:
    try:
        ipaddress.ip_address(gateway)
        return True
    except ValueError:
        return False


class RouteCreate(BaseModel):
    """/ip route add dst-address=... gateway=... distance=..."""
    dst_address: str = Field("0.0.0.0/0", examples=["0.0.0.0/0", "10.0.0.0/8"])
    gateway: str = Field(examples=["192.168.1.1", "eth1"])
    distance: int = Field(1, ge=1, le=255)
    comment: str | None = None
    disabled: bool = False

    @field_validator("dst_address")
    @classmethod
    def _dst(cls, v: str) -> str:
        return normalize_dst(v)

    @field_validator("gateway")
    @classmethod
    def _gw(cls, v: str) -> str:
        return normalize_gateway(v)


class RouteUpdate(BaseModel):
    """/ip route set / enable / disable."""
    dst_address: str | None = None
    gateway: str | None = None
    distance: int | None = Field(None, ge=1, le=255)
    comment: str | None = None
    disabled: bool | None = None

    @field_validator("dst_address")
    @classmethod
    def _dst(cls, v: str | None) -> str | None:
        return None if v is None else normalize_dst(v)

    @field_validator("gateway")
    @classmethod
    def _gw(cls, v: str | None) -> str | None:
        return None if v is None else normalize_gateway(v)


class Route(BaseModel):
    """Строка вывода /ip route print."""
    id: int | None              # None — динамический маршрут (не из конфига)
    dst_address: str
    gateway: str
    distance: int
    interface: str | None = None  # через какой интерфейс реально уходит
    comment: str | None = None
    disabled: bool = False      # X
    active: bool = False        # A — маршрут стоит в ядре
    dynamic: bool = False       # D — не из router.yaml
    connected: bool = False     # C — подключённая сеть (создана ядром)
    static: bool = False        # S — из router.yaml
    ospf: bool = False          # o — получен по OSPF
    bgp: bool = False           # b — получен по BGP
