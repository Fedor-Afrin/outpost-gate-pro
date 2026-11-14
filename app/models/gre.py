"""Схемы VPN → GRE: туннели «роутер — роутер» поверх другого туннеля (AmneziaWG, WireGuard) или WAN.

Зачем: сервер AmneziaWG знает у каждого клиента только его адрес /32 и сети за роутерами не
маршрутизирует. GRE между двумя роутерами идёт как обычный трафик «10.8.1.2 → 10.8.1.3» (это сервер
пропускает), а внутри GRE ходят любые сети: статические маршруты или OSPF — как в Cisco
(interface Tunnel0 / tunnel source / tunnel destination). Сервер Amnezia при этом не трогаем.
"""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator, model_validator

NAME_RE = re.compile(r"^gre[1-9][0-9]?$")          # gre0 — служебное устройство ядра, его не трогаем
IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}$")


def _ipv4(v: str, what: str) -> str:
    try:
        return str(ipaddress.IPv4Address(v.strip()))
    except ValueError as e:
        raise ValueError(f"{what}: нужен адрес IPv4, например 10.8.1.3") from e


def _area(v: str | int) -> str:
    v = str(v).strip()
    if v.isdigit():
        return str(ipaddress.IPv4Address(int(v)))
    return _ipv4(v, "область OSPF")


class GreTunnel(BaseModel):
    name: str = Field("gre1", examples=["gre1"], description="Имя интерфейса: gre1 … gre99")
    enabled: bool = True
    comment: str | None = Field(None, max_length=80)
    remote: str = Field(examples=["10.8.1.3"],
                        description="Адрес второго роутера (tunnel destination): обычно его адрес в AmneziaWG")
    local: str | None = Field(None, examples=["10.8.1.2"],
                              description="Свой адрес (tunnel source); пусто — выберет ядро по маршруту")
    underlay: str | None = Field(None, examples=["awg0"],
                                 description="Через какой интерфейс идти к второму роутеру: awg0, wg0 …; "
                                             "пусто — по обычной таблице маршрутов")
    address: str = Field(examples=["172.16.0.1/30"], description="Адрес внутри GRE (у второго роутера — .2/30)")
    mtu: int = Field(1380, ge=576, le=1476, description="AmneziaWG 1420 − 24 байта GRE − запас под обфускацию")
    ttl: int = Field(64, ge=1, le=255)
    routes: list[str] = Field(default_factory=list, examples=[["192.168.20.0/24"]],
                              description="Сети за вторым роутером — статические маршруты в этот туннель")
    ospf: bool = Field(False, description="Включить туннель в OSPF (point-to-point): сети обменяются сами")
    ospf_area: str = Field("0.0.0.0", examples=["0", "0.0.0.0"])
    ospf_cost: int | None = Field(None, ge=1, le=65535)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip().lower()
        if not NAME_RE.match(v):
            raise ValueError("имя туннеля: gre1 … gre99")
        return v

    @field_validator("comment")
    @classmethod
    def _comment(cls, v: str | None) -> str | None:
        v = (v or "").strip()
        if any(c in v for c in "\n\r\"'"):
            raise ValueError("в комментарии не должно быть кавычек и переносов строк")
        return v or None

    @field_validator("remote")
    @classmethod
    def _remote(cls, v: str) -> str:
        return _ipv4(v, "адрес второго роутера")

    @field_validator("local")
    @classmethod
    def _local(cls, v: str | None) -> str | None:
        return _ipv4(v, "свой адрес") if v and v.strip() else None

    @field_validator("underlay")
    @classmethod
    def _underlay(cls, v: str | None) -> str | None:
        v = (v or "").strip()
        if v and (not IFACE_RE.match(v) or NAME_RE.match(v)):
            raise ValueError(f"интерфейс {v}: нужен туннель или порт (awg0, wg0, enp1s0), не сам GRE")
        return v or None

    @field_validator("address")
    @classmethod
    def _address(cls, v: str) -> str:
        try:
            iface = ipaddress.IPv4Interface(v.strip())
        except ValueError as e:
            raise ValueError("адрес в туннеле: IPv4 с маской, например 172.16.0.1/30") from e
        if iface.network.prefixlen > 31:
            raise ValueError("адрес в туннеле: маска /30 или /31 (общая сеть с вторым роутером)")
        if iface.network.prefixlen < 31 and iface.ip in (iface.network.network_address,
                                                         iface.network.broadcast_address):
            raise ValueError(f"{iface.ip} — адрес сети или broadcast, возьмите, например, "
                             f"{iface.network.network_address + 1}/{iface.network.prefixlen}")
        return str(iface)

    @field_validator("routes")
    @classmethod
    def _routes(cls, v: list[str]) -> list[str]:
        out = []
        for r in v:
            try:
                n = ipaddress.IPv4Network(r.strip(), strict=False)
            except ValueError as e:
                raise ValueError(f"маршрут {r}: нужна сеть IPv4, например 192.168.20.0/24") from e
            if n.prefixlen == 0:
                raise ValueError("маршрут по умолчанию в GRE не поддерживается — укажите сети за вторым роутером")
            if str(n) not in out:
                out.append(str(n))
        return out

    @field_validator("ospf_area")
    @classmethod
    def _oarea(cls, v: str) -> str:
        return _area(v)

    @model_validator(mode="after")
    def _check(self):
        net = ipaddress.IPv4Interface(self.address).network
        remote = ipaddress.IPv4Address(self.remote)
        if remote in net:
            raise ValueError(f"{self.name}: адрес второго роутера {remote} не может быть внутри GRE ({net}) — "
                             "это адрес снаружи туннеля (например, в AmneziaWG)")
        for r in self.routes:
            if remote in ipaddress.IPv4Network(r):
                raise ValueError(f"{self.name}: маршрут {r} включает адрес второго роутера {remote} — "
                                 "GRE пошёл бы сам в себя")
        if self.local and self.local == self.remote:
            raise ValueError(f"{self.name}: свой адрес и адрес второго роутера совпадают")
        return self

    @property
    def network(self) -> str:
        return str(ipaddress.IPv4Interface(self.address).network)

    @property
    def peer_hint(self) -> str:
        """Какой адрес поставить на втором роутере."""
        iface = ipaddress.IPv4Interface(self.address)
        hosts = list(iface.network.hosts()) if iface.network.prefixlen < 31 else list(iface.network)
        other = next((h for h in hosts if h != iface.ip), iface.ip)
        return f"{other}/{iface.network.prefixlen}"


class GreConfig(BaseModel):
    tunnels: list[GreTunnel] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self):
        names, pairs, nets = set(), set(), []
        for t in self.tunnels:
            if t.name in names:
                raise ValueError(f"туннель {t.name} указан дважды")
            names.add(t.name)
            pair = (t.local or "", t.remote)
            if pair in pairs:
                raise ValueError(f"два туннеля к {t.remote} с одинаковым своим адресом — ядро так не умеет")
            pairs.add(pair)
            n = ipaddress.IPv4Interface(t.address).network
            for other, on in nets:
                if n.overlaps(on):
                    raise ValueError(f"сети внутри {t.name} ({n}) и {other} ({on}) пересекаются")
            nets.append((t.name, n))
        return self

    def to_yaml(self) -> dict:
        return {"tunnels": [t.model_dump(exclude_none=True) for t in self.tunnels]}

    @classmethod
    def from_yaml(cls, d: dict | None) -> "GreConfig":
        return cls.model_validate(d or {})


class GreTunnelStatus(BaseModel):
    name: str
    enabled: bool
    exists: bool = False             # интерфейс есть в системе
    up: bool = False
    rx_bytes: int = 0
    tx_bytes: int = 0
    underlay_ok: bool | None = None  # маршрут ко второму роутеру через underlay на месте (None — не задан)
    peer_hint: str = ""              # что поставить адресом на втором роутере
    error: str | None = None


class GreStatus(BaseModel):
    config: GreConfig
    tunnels: list[GreTunnelStatus] = Field(default_factory=list)
    ospf_enabled: bool = False       # OSPF включён в «Маршрутизации» (без него галочка OSPF не действует)
    interfaces: list[str] = Field(default_factory=list, description="Интерфейсы для underlay")
    warnings: list[str] = Field(default_factory=list)
