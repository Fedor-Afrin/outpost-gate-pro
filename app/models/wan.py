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
    vlan_id: int | None = Field(None, ge=1, le=4094, description="VLAN провайдера: WAN идёт с этим тегом")

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
        if self.vlan_id:
            data["vlan_id"] = self.vlan_id
        return data


class WanStatus(BaseModel):
    """Что сейчас происходит на WAN."""
    config: "Wan2Config | WanConfig"
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
    multi: bool = False            # включён второй WAN


# --- второй WAN и мульти-WAN -----------------------------------------------------------------
class Wan2Config(WanConfig):
    """Второй провайдер (секция wan2: в router.yaml). Интерфейс задаётся явно."""
    enabled: bool = False
    interface: str = Field("", description="Порт второго провайдера, например eth2")
    mode: Literal["dhcp", "static", "none"] = "dhcp"

    @model_validator(mode="after")
    def _need_interface(self):
        self.interface = (self.interface or "").strip()
        if self.enabled and (not self.interface or self.interface == "auto"):
            raise ValueError("WAN2: выберите порт второго провайдера")
        return self

    def to_yaml(self) -> dict:
        return {"enabled": self.enabled, **super().to_yaml()}


class MultiWanConfig(BaseModel):
    """Как работают два WAN (секция multiwan: в router.yaml)."""
    mode: Literal["failover", "balance"] = Field(
        "failover", description="failover — резерв; balance — оба канала сразу, соединения по весам")
    primary: Literal["wan1", "wan2"] = Field("wan1", description="Основной канал в режиме резерва")
    weight1: int = Field(1, ge=1, le=10, description="Вес WAN1 при балансировке")
    weight2: int = Field(1, ge=1, le=10, description="Вес WAN2 при балансировке")
    check_targets: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"],
                                     description="Куда проверять связь через каждый канал (ping)")
    interval: int = Field(5, ge=2, le=60, description="Секунд между проверками")
    fail_after: int = Field(3, ge=1, le=20, description="Сколько проверок подряд без ответа — канал упал")
    recover_after: int = Field(5, ge=1, le=60, description="Сколько удачных проверок подряд — канал вернулся")

    @field_validator("check_targets")
    @classmethod
    def _targets(cls, v: list[str]) -> list[str]:
        out = []
        for x in v:
            if x and x.strip():
                ip = str(_ipv4(x, "адрес проверки"))
                if ip not in out:
                    out.append(ip)
        if not out:
            raise ValueError("укажите хотя бы один адрес для проверки связи")
        if len(out) > 4:
            raise ValueError("адресов проверки — не больше 4")
        return out

    def to_yaml(self) -> dict:
        return self.model_dump()


class WanHealth(BaseModel):
    id: str                          # wan1 / wan2
    name: str                        # WAN1 / WAN2
    enabled: bool = True
    interface: str | None = None
    address: str | None = None
    gateway: str | None = None
    link_up: bool = False
    healthy: bool | None = None      # None — ещё не проверяли / проверка не нужна
    active: bool = False             # через него сейчас идёт трафик (в балансировке — все живые)
    rtt: float | None = None         # мс, последняя удачная проверка
    since: float | None = None       # когда сменилось состояние
    fails: int = 0
    oks: int = 0


class MultiWanStatus(BaseModel):
    config: MultiWanConfig
    enabled: bool                    # второй WAN включён
    wans: list[WanHealth]
    events: list[dict] = Field(default_factory=list)   # последние переключения


WanStatus.model_rebuild()
