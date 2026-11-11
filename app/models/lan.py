"""Схемы раздела LAN."""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator, model_validator

LEASE_RE = re.compile(r"^\d+[mhd]$")


class LanConfig(BaseModel):
    """Настройки LAN (секции lan: и firewall: в router.yaml)."""
    enabled: bool = False
    address: str = Field("192.168.88.1/24", description="Адрес роутера в LAN — шлюз и DNS для клиентов")
    ports: list[str] = Field(default_factory=list, description="Порты в мосту; пусто = все, кроме WAN")
    dhcp_enabled: bool = True
    pool_start: str | None = Field(None, examples=["192.168.88.10"])
    pool_end: str | None = Field(None, examples=["192.168.88.254"])
    lease_time: str = Field("12h", examples=["1h", "12h", "1d"])
    wan_management: bool = Field(True, description="Разрешить веб и SSH со стороны WAN")

    @field_validator("address")
    @classmethod
    def _address(cls, v: str) -> str:
        if "/" not in v:
            raise ValueError("укажите маску: 192.168.88.1/24")
        try:
            iface = ipaddress.ip_interface(v.strip())
        except ValueError as e:
            raise ValueError(f"неверный адрес '{v}'") from e
        if iface.version != 4 or iface.network.prefixlen > 30:
            raise ValueError("нужен IPv4-адрес с маской не уже /30")
        if iface.ip in (iface.network.network_address, iface.network.broadcast_address):
            raise ValueError("адрес роутера не может быть адресом сети или broadcast")
        return str(iface)

    @field_validator("lease_time")
    @classmethod
    def _lease(cls, v: str) -> str:
        if not LEASE_RE.match(v):
            raise ValueError("срок аренды: число и m/h/d, например 12h")
        return v

    @model_validator(mode="after")
    def _pool(self):
        iface = ipaddress.ip_interface(self.address)
        hosts = list(iface.network.hosts())
        # по умолчанию: от .10 (или первого) до последнего адреса сети
        start = ipaddress.ip_address(self.pool_start) if self.pool_start else (
            hosts[9] if len(hosts) > 20 and iface.ip < hosts[9] else iface.ip + 1)
        end = ipaddress.ip_address(self.pool_end) if self.pool_end else hosts[-1]
        for ip, what in ((start, "начало"), (end, "конец")):
            if ip not in iface.network:
                raise ValueError(f"{what} диапазона {ip} вне сети {iface.network}")
        if start > end:
            raise ValueError("начало диапазона больше конца")
        if self.dhcp_enabled and start <= iface.ip <= end:
            raise ValueError(f"диапазон DHCP включает адрес роутера {iface.ip} — сдвиньте его")
        self.pool_start, self.pool_end = str(start), str(end)
        return self

    def to_yaml(self) -> tuple[dict, dict]:
        lan = {
            "enabled": self.enabled,
            "address": self.address,
            "ports": self.ports or "auto",
            "dhcp-server": {
                "enabled": self.dhcp_enabled,
                "pool": f"{self.pool_start}-{self.pool_end}",
                "lease-time": self.lease_time,
            },
        }
        return lan, {"wan-management": self.wan_management}

    @classmethod
    def from_yaml(cls, lan: dict | None, firewall: dict | None) -> "LanConfig":
        lan = lan or {}
        dhcp = lan.get("dhcp-server") or {}
        pool = (dhcp.get("pool") or "").split("-")
        ports = lan.get("ports")
        return cls(
            enabled=lan.get("enabled", False),
            address=lan.get("address", "192.168.88.1/24"),
            ports=[] if ports in (None, "auto") else list(ports),
            dhcp_enabled=dhcp.get("enabled", True),
            pool_start=pool[0] if len(pool) == 2 else None,
            pool_end=pool[1] if len(pool) == 2 else None,
            lease_time=str(dhcp.get("lease-time", "12h")),
            wan_management=(firewall or {}).get("wan-management", True),
        )


class Port(BaseModel):
    name: str
    mac: str | None = None
    link_up: bool = False
    role: str            # wan / lan / none


class Lease(BaseModel):
    ip: str
    mac: str
    hostname: str | None = None
    vendor: str | None = None
    expires: float | None = None   # unix time; None — бессрочно
    static: bool = False           # адрес закреплён за этим MAC
    name: str | None = None        # имя из закреплённых адресов


class LanStatus(BaseModel):
    config: LanConfig
    active: bool = False           # мост поднят и адрес назначен
    bridge: str
    wan_interface: str | None = None
    ports: list[Port] = []
    dns_dhcp_running: bool = False
    leases: list[Lease] = []
    static_leases: list["StaticLeaseView"] = []


MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$")


class StaticLease(BaseModel):
    """Закреплённый адрес: устройство с этим MAC всегда получает этот IP (dhcp-host)."""
    mac: str = Field(examples=["00:0b:82:aa:bb:cc"])
    ip: str = Field(examples=["192.168.88.20"])
    name: str | None = Field(None, max_length=64, examples=["Телефон бухгалтера"])

    @field_validator("mac")
    @classmethod
    def _mac(cls, v: str) -> str:
        v = v.strip().lower()
        if not MAC_RE.match(v):
            raise ValueError(f"неверный MAC '{v}': ожидается 00:0b:82:aa:bb:cc")
        return v.replace("-", ":")

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        try:
            ip = ipaddress.ip_address(v.strip())
        except ValueError as e:
            raise ValueError(f"неверный IP '{v}'") from e
        if ip.version != 4:
            raise ValueError("нужен IPv4")
        return str(ip)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        return v.strip() or None if v else None

    def dnsmasq_line(self) -> str:
        """Имя передаём в dnsmasq, только если оно годится как hostname (латиница, цифры, -)."""
        if self.name and HOSTNAME_RE.match(self.name):
            return f"{self.mac},{self.ip},{self.name}"
        return f"{self.mac},{self.ip}"


class StaticLeaseView(StaticLease):
    in_pool: bool = False      # адрес внутри динамического диапазона (работает, но лучше вне пула)
    valid: bool = True         # адрес в сети LAN и не совпадает с адресом роутера


LanStatus.model_rebuild()
