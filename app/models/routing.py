"""Схемы динамической маршрутизации: OSPF и BGP (секция routing: в router.yaml).

Демон — FRRouting (zebra + ospfd + bgpd). Роутер генерирует /etc/frr/frr.conf целиком
из этих настроек; вручную frr.conf не редактируется (как и nftables).
"""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator, model_validator

IFNAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
PREFIX_RE = re.compile(r"^(\S+)(?:\s+ge\s+(\d+))?(?:\s+le\s+(\d+))?$")
REDISTRIBUTE = ("connected", "static", "kernel", "ospf", "bgp")


def _ipv4(v: str, what: str) -> str:
    try:
        return str(ipaddress.IPv4Address(v.strip()))
    except ValueError as e:
        raise ValueError(f"{what}: нужен IPv4-адрес, например 10.255.0.1") from e


def _network(v: str) -> str:
    try:
        return str(ipaddress.IPv4Network(v.strip(), strict=False))
    except ValueError as e:
        raise ValueError(f"неверная сеть '{v}': нужен вид 192.168.1.0/24") from e


def _area(v: str | int) -> str:
    """Область OSPF: 0, 1 или 0.0.0.1 -> всегда в виде адреса (как пишет FRR)."""
    s = str(v).strip()
    if s.isdigit():
        n = int(s)
        if n > 0xFFFFFFFF:
            raise ValueError("номер области слишком большой")
        return str(ipaddress.IPv4Address(n))
    return _ipv4(s, "область")


def _secret(v: str | None) -> str | None:
    if v is None or v == "":
        return v
    if not re.fullmatch(r"[!-~]{1,80}", v) or any(c in v for c in "\"'\\"):
        raise ValueError("пароль: латиница, цифры и знаки без пробелов и кавычек, до 80 символов")
    return v


def _redistribute(v: list[str], own: str) -> list[str]:
    out = []
    for x in v:
        x = x.strip().lower()
        if x not in REDISTRIBUTE or x == own:
            raise ValueError(f"redistribute: одно из {', '.join(r for r in REDISTRIBUTE if r != own)}")
        if x not in out:
            out.append(x)
    return out


def check_prefix(v: str) -> str:
    """Строка prefix-list: «10.0.0.0/8», «10.0.0.0/8 le 24», «0.0.0.0/0 ge 8 le 24»."""
    m = PREFIX_RE.match(" ".join(v.split()))
    if not m:
        raise ValueError(f"фильтр '{v}': нужен вид 10.0.0.0/8 или 10.0.0.0/8 le 24")
    net = ipaddress.IPv4Network(m[1], strict=False) if "/" in m[1] else None
    if not net:
        raise ValueError(f"фильтр '{v}': укажите сеть с маской")
    ge, le = (int(m[2]) if m[2] else None), (int(m[3]) if m[3] else None)
    for x in (ge, le):
        if x is not None and not net.prefixlen < x <= 32:
            raise ValueError(f"фильтр '{v}': ge/le — от {net.prefixlen + 1} до 32")
    if ge and le and ge > le:
        raise ValueError(f"фильтр '{v}': ge больше le")
    return " ".join([str(net)] + ([f"ge {ge}"] if ge else []) + ([f"le {le}"] if le else []))


# --- OSPF ----------------------------------------------------------------------------------------
class OspfNetwork(BaseModel):
    network: str = Field(examples=["192.168.1.0/24"], description="Сеть, интерфейсы которой участвуют в OSPF")
    area: str = Field("0.0.0.0", examples=["0", "0.0.0.0"])

    _n = field_validator("network")(classmethod(lambda cls, v: _network(v)))
    _a = field_validator("area", mode="before")(classmethod(lambda cls, v: _area(v)))


class OspfInterface(BaseModel):
    name: str = Field(examples=["wg0"], description="Интерфейс роутера")
    cost: int | None = Field(None, ge=1, le=65535, description="Стоимость; пусто — по скорости канала")
    passive: bool = Field(False, description="Объявлять сеть, но не искать соседей (LAN)")
    network_type: str = Field("auto", description="auto | broadcast | point-to-point | non-broadcast")
    neighbor: str | None = Field(None, description="Сосед для non-broadcast: hello идут unicast")
    hello: int = Field(10, ge=1, le=65535)
    dead: int = Field(40, ge=1, le=65535)
    priority: int | None = Field(None, ge=0, le=255)
    auth_key: str | None = Field(None, description="Ключ MD5; пусто — без аутентификации")

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not IFNAME_RE.match(v):
            raise ValueError(f"неверное имя интерфейса '{v}'")
        return v

    @field_validator("network_type")
    @classmethod
    def _type(cls, v: str) -> str:
        if v not in ("auto", "broadcast", "point-to-point", "non-broadcast"):
            raise ValueError("тип сети: auto, broadcast, point-to-point или non-broadcast")
        return v

    @field_validator("neighbor")
    @classmethod
    def _neighbor(cls, v: str | None) -> str | None:
        return _ipv4(v, "сосед") if v else None

    _k = field_validator("auth_key")(classmethod(lambda cls, v: _secret(v)))

    @model_validator(mode="after")
    def _check(self):
        if self.dead <= self.hello:
            raise ValueError(f"{self.name}: dead-интервал должен быть больше hello")
        if self.network_type == "non-broadcast" and not self.neighbor:
            raise ValueError(f"{self.name}: для non-broadcast укажите соседа")
        return self


class OspfConfig(BaseModel):
    enabled: bool = False
    networks: list[OspfNetwork] = Field(default_factory=list)
    interfaces: list[OspfInterface] = Field(default_factory=list, description="Настройки интерфейсов")
    passive_default: bool = Field(False, description="Все интерфейсы пассивные, кроме перечисленных активных")
    redistribute: list[str] = Field(default_factory=list, examples=[["connected", "static"]])
    default_route: str = Field("none", description="none | if-installed | always — раздавать маршрут по умолчанию")

    @field_validator("redistribute")
    @classmethod
    def _red(cls, v: list[str]) -> list[str]:
        return _redistribute(v, "ospf")

    @field_validator("default_route")
    @classmethod
    def _def(cls, v: str) -> str:
        if v not in ("none", "if-installed", "always"):
            raise ValueError("маршрут по умолчанию: none, if-installed или always")
        return v

    @model_validator(mode="after")
    def _unique(self):
        names = [i.name for i in self.interfaces]
        if len(names) != len(set(names)):
            raise ValueError("интерфейс OSPF указан дважды")
        nets = [n.network for n in self.networks]
        if len(nets) != len(set(nets)):
            raise ValueError("сеть OSPF указана дважды")
        if self.enabled and not self.networks:
            raise ValueError("OSPF: добавьте хотя бы одну сеть")
        return self


# --- BGP -----------------------------------------------------------------------------------------
class BgpNeighbor(BaseModel):
    address: str = Field(examples=["10.8.0.1"])
    remote_as: int = Field(ge=1, le=4294967295, examples=[65000])
    description: str | None = Field(None, max_length=80)
    password: str | None = Field(None, description="MD5 (TCP-MD5); пусто — без пароля")
    enabled: bool = True
    multihop: int | None = Field(None, ge=2, le=255, description="eBGP через несколько хопов (TTL)")
    update_source: str | None = Field(None, description="Интерфейс или адрес источника (iBGP по loopback)")
    keepalive: int = Field(60, ge=1, le=65535)
    hold: int = Field(180, ge=3, le=65535)
    prefix_in: list[str] = Field(default_factory=list, description="Принимать только эти сети; пусто — всё")
    prefix_out: list[str] = Field(default_factory=list, description="Отдавать только эти сети; пусто — всё")

    _a = field_validator("address")(classmethod(lambda cls, v: _ipv4(v, "адрес соседа")))
    _p = field_validator("password")(classmethod(lambda cls, v: _secret(v)))

    @field_validator("description")
    @classmethod
    def _desc(cls, v: str | None) -> str | None:
        if v and any(c in v for c in "\"\\\n"):
            raise ValueError("описание: без кавычек и переводов строки")
        return v or None

    @field_validator("update_source")
    @classmethod
    def _src(cls, v: str | None) -> str | None:
        if not v:
            return None
        try:
            return str(ipaddress.IPv4Address(v))
        except ValueError:
            if not IFNAME_RE.match(v):
                raise ValueError("источник: интерфейс или IPv4-адрес") from None
            return v

    @field_validator("prefix_in", "prefix_out")
    @classmethod
    def _prefixes(cls, v: list[str]) -> list[str]:
        return [check_prefix(x) for x in v if x.strip()]

    @model_validator(mode="after")
    def _timers(self):
        if self.hold < 3 * self.keepalive and self.hold != 0:
            raise ValueError(f"{self.address}: hold должен быть не меньше 3 × keepalive")
        return self


class BgpConfig(BaseModel):
    enabled: bool = False
    asn: int = Field(65001, ge=1, le=4294967295, description="Номер своей автономной системы")
    neighbors: list[BgpNeighbor] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list, description="Сети, которые роутер объявляет")
    redistribute: list[str] = Field(default_factory=list)

    @field_validator("networks")
    @classmethod
    def _nets(cls, v: list[str]) -> list[str]:
        out = [_network(x) for x in v if x.strip()]
        if len(out) != len(set(out)):
            raise ValueError("сеть BGP указана дважды")
        return out

    @field_validator("redistribute")
    @classmethod
    def _red(cls, v: list[str]) -> list[str]:
        return _redistribute(v, "bgp")

    @model_validator(mode="after")
    def _unique(self):
        addrs = [n.address for n in self.neighbors]
        if len(addrs) != len(set(addrs)):
            raise ValueError("сосед BGP указан дважды")
        if self.enabled and not self.neighbors:
            raise ValueError("BGP: добавьте хотя бы одного соседа")
        return self


# --- вместе --------------------------------------------------------------------------------------
class RoutingConfig(BaseModel):
    router_id: str | None = Field(None, description="Общий для OSPF и BGP; пусто — выберет FRR")
    ospf: OspfConfig = Field(default_factory=OspfConfig)
    bgp: BgpConfig = Field(default_factory=BgpConfig)

    @field_validator("router_id")
    @classmethod
    def _rid(cls, v: str | None) -> str | None:
        return _ipv4(v, "router-id") if v else None

    def to_yaml(self) -> dict:
        return self.model_dump(exclude_none=True)


# --- состояние -----------------------------------------------------------------------------------
class OspfNeighborView(BaseModel):
    router_id: str
    address: str | None = None
    interface: str | None = None
    state: str = ""
    priority: int | None = None
    uptime: str | None = None
    dead_time: str | None = None


class BgpPeerView(BaseModel):
    address: str
    remote_as: int | None = None
    description: str | None = None
    state: str = ""
    uptime: str | None = None
    prefixes_received: int | None = None
    prefixes_sent: int | None = None
    enabled: bool = True


class RouteView(BaseModel):
    prefix: str
    protocol: str
    nexthop: str | None = None
    interface: str | None = None
    distance: int | None = None
    metric: int | None = None
    selected: bool = False


class RoutingStatus(BaseModel):
    config: RoutingConfig
    running: bool = False
    installed: bool = True             # есть ли FRR в образе
    error: str | None = None
    router_id: str | None = None       # фактический (может выбрать FRR)
    ospf_neighbors: list[OspfNeighborView] = Field(default_factory=list)
    bgp_peers: list[BgpPeerView] = Field(default_factory=list)
    routes: list[RouteView] = Field(default_factory=list)
    interfaces: list[str] = Field(default_factory=list)   # подсказка для формы
