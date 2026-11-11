"""Схемы раздела WAN."""
from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


def _ipv4(value: str, what: str) -> ipaddress.IPv4Address:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as e:
        raise ValueError(f"{what}: неверный адрес '{value}'") from e
    if ip.version != 4:
        raise ValueError(f"{what}: нужен IPv4")
    return ip


class WanConfig(BaseModel):
    """Настройки WAN (секция wan: в router.yaml)."""
    interface: str = Field("auto", description="Имя интерфейса или auto — по маршруту по умолчанию")
    mode: Literal["dhcp", "static", "none"] = Field(
        "none", description="dhcp — получить автоматически, static — вручную, none — не трогать")
    address: str | None = Field(None, examples=["203.0.113.10/24"])
    gateway: str | None = Field(None, examples=["203.0.113.1"])
    dns: list[str] = Field(default_factory=list, max_length=3, examples=[["1.1.1.1", "8.8.8.8"]])

    @field_validator("address")
    @classmethod
    def _address(cls, v: str | None) -> str | None:
        if not v:
            return None
        if "/" not in v:
            raise ValueError("укажите маску: 203.0.113.10/24")
        try:
            iface = ipaddress.ip_interface(v.strip())
        except ValueError as e:
            raise ValueError(f"неверный адрес '{v}': ожидается 203.0.113.10/24") from e
        if iface.version != 4:
            raise ValueError("нужен IPv4-адрес")
        return str(iface)

    @field_validator("gateway")
    @classmethod
    def _gateway(cls, v: str | None) -> str | None:
        return str(_ipv4(v, "шлюз")) if v else None

    @field_validator("dns")
    @classmethod
    def _dns(cls, v: list[str]) -> list[str]:
        return [str(_ipv4(x, "DNS")) for x in v if x and x.strip()]

    @model_validator(mode="after")
    def _static_complete(self):
        if self.mode == "static":
            if not self.address or not self.gateway:
                raise ValueError("для ручной настройки нужны IP-адрес с маской и шлюз")
            iface = ipaddress.ip_interface(self.address)
            gw = ipaddress.ip_address(self.gateway)
            if gw not in iface.network:
                raise ValueError(f"шлюз {gw} не входит в сеть {iface.network}")
            if gw == iface.ip:
                raise ValueError("шлюз совпадает с адресом роутера")
        return self

    def to_yaml(self) -> dict:
        data: dict = {"interface": self.interface, "mode": self.mode}
        if self.mode == "static":
            data["address"] = self.address
            data["gateway"] = self.gateway
        if self.dns:
            data["dns"] = self.dns
        return data


class WanStatus(BaseModel):
    """Что сейчас происходит на WAN."""
    config: WanConfig
    interface: str | None          # фактический интерфейс (auto уже разрешён)
    mac: str | None = None
    link_up: bool = False          # есть ли линк (кабель)
    addresses: list[str] = []      # все IPv4-адреса на интерфейсе
    gateway: str | None = None     # шлюз маршрута по умолчанию через WAN
    dns: list[str] = []            # DNS: заданные вручную или полученные по DHCP
    dhcp_running: bool = False
    dhcp_state: str | None = None  # bound / searching / static / none
    lease_expires: float | None = None  # unix time
    interfaces: list[str] = []     # кандидаты для выбора WAN
