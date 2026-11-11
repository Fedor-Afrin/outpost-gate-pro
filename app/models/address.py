"""Схемы раздела IP → Addresses (аналог /ip address)."""
from __future__ import annotations

import ipaddress

from pydantic import BaseModel, Field, field_validator


def _normalize(value: str) -> str:
    """'192.168.88.1/24' -> проверка и нормализация. Без маски — /32, как в RouterOS."""
    try:
        iface = ipaddress.ip_interface(value.strip())
    except ValueError as e:
        raise ValueError(f"неверный адрес '{value}': ожидается формат 192.168.88.1/24") from e
    if iface.version != 4:
        raise ValueError("здесь только IPv4 (IPv6 будет в разделе /ipv6 address)")
    return str(iface)


class AddressCreate(BaseModel):
    """Тело запроса: /ip address add address=... interface=..."""
    address: str = Field(examples=["192.168.88.1/24"])
    interface: str = Field(examples=["eth1"])
    comment: str | None = None
    disabled: bool = False

    @field_validator("address")
    @classmethod
    def _check_address(cls, v: str) -> str:
        return _normalize(v)


class AddressUpdate(BaseModel):
    """Тело запроса: /ip address set / enable / disable."""
    address: str | None = None
    interface: str | None = None
    comment: str | None = None
    disabled: bool | None = None

    @field_validator("address")
    @classmethod
    def _check_address(cls, v: str | None) -> str | None:
        return None if v is None else _normalize(v)


class Address(BaseModel):
    """Строка вывода /ip address print."""
    id: int | None            # None — динамический адрес (не из конфига)
    address: str
    network: str
    interface: str
    comment: str | None = None
    disabled: bool = False    # флаг X
    dynamic: bool = False     # флаг D — адрес есть в системе, но не в router.yaml
    invalid: bool = False     # флаг I — интерфейса нет / адрес не применился
