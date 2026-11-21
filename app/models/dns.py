"""Схемы DNS-сервера (BIND 9): настройки, зоны, записи (секция dns: в router.yaml)."""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator, model_validator

from app.models.lan import check_domain

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "NS", "CAA")
LABEL_RE = re.compile(r"^(\*|[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?)$")
HOST_RE = re.compile(r"^([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9])?\.?$")


def reverse_zone_for(network: str) -> str:
    """192.168.1.0/24 -> 1.168.192.in-addr.arpa (только границы октетов: /8, /16, /24)."""
    net = ipaddress.IPv4Network(network, strict=False)
    if net.prefixlen not in (8, 16, 24):
        raise ValueError("обратная зона строится для сети /8, /16 или /24")
    octets = str(net.network_address).split(".")[: net.prefixlen // 8]
    return ".".join(reversed(octets)) + ".in-addr.arpa"


def reverse_network(zone: str) -> ipaddress.IPv4Network | None:
    """1.168.192.in-addr.arpa -> 192.168.1.0/24; не обратная зона — None."""
    if not zone.endswith(".in-addr.arpa"):
        return None
    parts = zone[: -len(".in-addr.arpa")].split(".")
    if not 1 <= len(parts) <= 3 or not all(p.isdigit() and int(p) < 256 for p in parts):
        return None
    octets = list(reversed(parts)) + ["0"] * (4 - len(parts))
    return ipaddress.IPv4Network(f"{'.'.join(octets)}/{len(parts) * 8}")


def _host(v: str, what: str) -> str:
    v = v.strip()
    if v == "@":
        return v
    if not HOST_RE.match(v) or len(v) > 253:
        raise ValueError(f"{what} '{v}': нужно имя, например mail или mail.office.lan.")
    return v


class DnsRecord(BaseModel):
    name: str = Field(examples=["www", "@", "_sip._udp"], description="Имя внутри зоны; @ — сама зона")
    type: str = Field("A")
    value: str = Field(examples=["192.168.1.20"])
    ttl: int | None = Field(None, ge=0, le=604800, description="Пусто — TTL зоны")
    priority: int | None = Field(None, ge=0, le=65535, description="MX и SRV")
    weight: int | None = Field(None, ge=0, le=65535, description="SRV")
    port: int | None = Field(None, ge=0, le=65535, description="SRV")
    comment: str | None = Field(None, max_length=80)

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        v = v.strip().upper()
        if v not in RECORD_TYPES:
            raise ValueError(f"тип записи: {', '.join(RECORD_TYPES)}")
        return v

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if v == "@":
            return v
        labels = v.rstrip(".").split(".")
        if not v or not all(LABEL_RE.match(x) for x in labels) or len(v) > 253:
            raise ValueError(f"имя записи '{v}': латиница, цифры, дефис, _ ; @ — сама зона")
        return v

    @field_validator("comment")
    @classmethod
    def _comment(cls, v: str | None) -> str | None:
        return v.replace("\n", " ").strip() or None if v else None

    @model_validator(mode="after")
    def _check(self):
        t, v = self.type, self.value.strip()
        if t == "A":
            try:
                self.value = str(ipaddress.IPv4Address(v))
            except ValueError:
                raise ValueError(f"A: нужен IPv4-адрес, а не '{v}'") from None
        elif t == "AAAA":
            try:
                self.value = str(ipaddress.IPv6Address(v))
            except ValueError:
                raise ValueError(f"AAAA: нужен IPv6-адрес, а не '{v}'") from None
        elif t in ("CNAME", "PTR", "NS"):
            self.value = _host(v, t)
            if t == "CNAME" and self.name == "@":
                raise ValueError("CNAME нельзя на саму зону (@) — используйте A")
        elif t == "MX":
            self.value = _host(v, "MX")
            if self.priority is None:
                self.priority = 10
        elif t == "SRV":
            self.value = _host(v, "SRV")
            if self.port is None:
                raise ValueError("SRV: укажите порт")
            self.priority = 10 if self.priority is None else self.priority
            self.weight = 0 if self.weight is None else self.weight
        elif t == "TXT":
            if not v or len(v) > 2000 or "\n" in v:
                raise ValueError("TXT: текст до 2000 символов, одной строкой")
            self.value = v
        elif t == "CAA":
            m = re.fullmatch(r'(\d{1,3})\s+(issue|issuewild|iodef)\s+"?([^"\s]+)"?', v)
            if not m or int(m[1]) > 255:
                raise ValueError('CAA: нужен вид 0 issue "letsencrypt.org"')
            self.value = f'{m[1]} {m[2]} "{m[3]}"'
        return self

    def rdata(self) -> str:
        """Правая часть строки зоны."""
        if self.type == "MX":
            return f"{self.priority} {self.value}"
        if self.type == "SRV":
            return f"{self.priority} {self.weight} {self.port} {self.value}"
        if self.type == "TXT":
            text = self.value.replace("\\", "\\\\").replace('"', '\\"')
            return " ".join(f'"{text[i:i + 255]}"' for i in range(0, len(text), 255))
        return self.value


class DnsZone(BaseModel):
    name: str = Field(examples=["office.lan", "1.168.192.in-addr.arpa"])
    ttl: int = Field(3600, ge=60, le=604800)
    dhcp_names: bool = Field(True, description="Добавлять имена устройств из DHCP (сегменты с этим доменом)")
    auto_ptr: bool = Field(True, description="Обратная зона: PTR для всех A-записей из её сети")
    records: list[DnsRecord] = Field(default_factory=list)
    hidden: list[str] = Field(default_factory=list,
                              description="Автоматические имена (DHCP, router), которые в зону не добавлять")

    @field_validator("hidden")
    @classmethod
    def _hidden(cls, v: list[str]) -> list[str]:
        out = []
        for n in v:
            n = n.strip().lower().rstrip(".")
            if not n or not re.fullmatch(r"[a-z0-9_.-]{1,253}", n):
                raise ValueError(f"скрытое имя '{n}': буквы, цифры, - _ .")
            if n == "ns":
                raise ValueError("ns — имя DNS-сервера зоны (запись NS), его скрыть нельзя")
            if n not in out:
                out.append(n)
        return out

    @field_validator("name")
    @classmethod
    def _zname(cls, v: str) -> str:
        v = v.strip().lower().rstrip(".")
        if v.endswith(".in-addr.arpa"):
            if reverse_network(v) is None:
                raise ValueError(f"обратная зона '{v}': нужен вид 1.168.192.in-addr.arpa")
            return v
        return check_domain(v, "зона")

    @property
    def reverse(self) -> bool:
        return self.name.endswith(".in-addr.arpa")


class DnsConfig(BaseModel):
    forwarders: list[str] = Field(default_factory=list, description="Пусто — DNS провайдера (или туннеля в режиме «весь трафик»)")
    forward_only: bool = Field(False, description="Только через forwarders (не ходить к корневым серверам)")
    dnssec: bool = Field(False, description="Проверять DNSSEC")
    allow: list[str] = Field(default_factory=list, description="Кто ещё может спрашивать (кроме сетей LAN), например сеть VPN")
    cache_mb: int = Field(64, ge=8, le=2048)
    zones: list[DnsZone] = Field(default_factory=list)

    @field_validator("forwarders")
    @classmethod
    def _fwd(cls, v: list[str]) -> list[str]:
        out = []
        for x in v:
            x = x.strip()
            if not x:
                continue
            try:
                out.append(str(ipaddress.ip_address(x)))
            except ValueError:
                raise ValueError(f"forwarder: неверный адрес '{x}'") from None
        return out

    @field_validator("allow")
    @classmethod
    def _allow(cls, v: list[str]) -> list[str]:
        out = []
        for x in v:
            x = x.strip()
            if not x:
                continue
            try:
                out.append(str(ipaddress.ip_network(x, strict=False)))
            except ValueError:
                raise ValueError(f"разрешённые сети: неверная сеть '{x}'") from None
        return out

    @model_validator(mode="after")
    def _unique(self):
        names = [z.name for z in self.zones]
        if len(names) != len(set(names)):
            raise ValueError("зона указана дважды")
        return self

    def zone(self, name: str) -> DnsZone | None:
        return next((z for z in self.zones if z.name == name), None)

    def to_yaml(self) -> dict:
        return self.model_dump(exclude_none=True)


DEFAULT_ZONE = "office.lan"


def default_config() -> DnsConfig:
    """Первый запуск Pro: зона office.lan, куда попадают имена устройств из DHCP."""
    return DnsConfig(zones=[DnsZone(name=DEFAULT_ZONE)])


# --- состояние -----------------------------------------------------------------------------------
class ZoneInfo(BaseModel):
    name: str
    reverse: bool = False
    records: int = 0               # своих записей
    dhcp_names: int = 0            # имён из DHCP
    segments: list[str] = []       # какие LAN пользуются этим доменом
    serial: int | None = None


class DnsName(BaseModel):
    """Имя, которое роутер добавил в зону сам (из DHCP или PTR)."""
    zone: str
    name: str
    type: str
    value: str
    source: str                    # dhcp | static-lease | ptr


class DnsStatus(BaseModel):
    config: DnsConfig
    running: bool = False
    installed: bool = True
    error: str | None = None
    listen: list[str] = []         # на каких адресах отвечает
    forwarders: list[str] = []     # фактические
    zones: list[ZoneInfo] = []
    auto_names: list[DnsName] = []
    segments: list[dict] = []      # [{id, name, domain, dns_enabled}] — подсказка для формы
