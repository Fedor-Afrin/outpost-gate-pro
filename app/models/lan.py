"""Схемы раздела LAN."""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator, model_validator

LEASE_RE = re.compile(r"^\d+[mhd]$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
SEGMENT_ID_RE = re.compile(r"^lan([1-9]|[1-9][0-9])$")
CUSTOM_TYPES = ("ip", "text", "hex", "uint8", "uint16", "uint32", "bool")


def check_domain(v: str, what: str = "домен") -> str:
    v = v.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(v):
        raise ValueError(f"{what} '{v}': латиница, цифры, точки и дефисы, например office.lan")
    if v == "local" or v.endswith(".local"):
        raise ValueError(f"{what} '{v}': .local занят mDNS (Bonjour) — выберите другой, например office.lan")
    return v


def _ips(v: list[str], what: str) -> list[str]:
    out = []
    for x in v:
        x = x.strip()
        if not x:
            continue
        try:
            ip = ipaddress.IPv4Address(x)
        except ValueError as e:
            raise ValueError(f"{what}: неверный IPv4-адрес '{x}'") from e
        out.append(str(ip))
    return out


class CustomOption(BaseModel):
    """Любая опция DHCP по коду: значение кодируется роутером в байты (как в RFC 2132)."""
    code: int = Field(ge=1, le=254)
    type: str = Field("text", description="ip | text | hex | uint8 | uint16 | uint32 | bool")
    value: str
    comment: str | None = Field(None, max_length=80)

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        if v not in CUSTOM_TYPES:
            raise ValueError(f"тип опции: {', '.join(CUSTOM_TYPES)}")
        return v

    @model_validator(mode="after")
    def _value(self):
        if self.code in (1, 3, 6, 15, 51, 53, 54, 55, 58, 59, 61, 82):
            raise ValueError(f"опцию {self.code} роутер задаёт сам — её нельзя переопределить")
        self.hex()        # проверить, что значение кодируется
        return self

    def hex(self) -> str:
        v = self.value.strip()
        try:
            if self.type == "ip":
                return "".join(ipaddress.IPv4Address(x.strip()).packed.hex() for x in v.split(",") if x.strip())
            if self.type == "text":
                b = v.encode()
                if not b or len(b) > 255:
                    raise ValueError
                return b.hex()
            if self.type == "hex":
                h = v.replace(":", "").replace(" ", "").lower()
                bytes.fromhex(h)
                if not h or len(h) > 510:
                    raise ValueError
                return h
            if self.type == "bool":
                return "01" if v.lower() in ("1", "yes", "true", "on", "да") else "00"
            size = {"uint8": 1, "uint16": 2, "uint32": 4}[self.type]
            return int(v, 0).to_bytes(size, "big").hex()
        except (ValueError, OverflowError):
            raise ValueError(f"опция {self.code}: значение '{v}' не подходит для типа {self.type}") from None


class DhcpOptions(BaseModel):
    """Опции, которые DHCP раздаёт клиентам сегмента. Пусто — опция не отправляется
    (кроме DNS и домена: по умолчанию — роутер и домен сегмента)."""
    dns_servers: list[str] = Field(default_factory=list, description="6: пусто — роутер (или DNS провайдера, если DNS на LAN выключен)")
    domain_search: list[str] = Field(default_factory=list, description="119: суффиксы поиска")
    ntp_servers: list[str] = Field(default_factory=list, description="42: серверы времени")
    time_offset: int | None = Field(None, ge=-43200, le=50400, description="2: смещение времени, с")
    mtu: int | None = Field(None, ge=576, le=9000, description="26: MTU интерфейса")
    wins_servers: list[str] = Field(default_factory=list, description="44: NetBIOS (WINS)")
    tftp_server: str | None = Field(None, description="66: TFTP-сервер (имя или адрес) — автонастройка IP-телефонов")
    boot_file: str | None = Field(None, description="67: файл загрузки (PXE, конфиг телефона)")
    tftp_servers_150: list[str] = Field(default_factory=list, description="150: TFTP-серверы (Cisco, Grandstream, Yealink)")
    sip_servers: list[str] = Field(default_factory=list, description="120: SIP-серверы (IP-адреса)")
    provisioning_url: str | None = Field(None, description="Опция 160/66 в виде URL автонастройки (Polycom, Yealink)")
    static_routes: list[str] = Field(default_factory=list, description="121/249: «10.0.0.0/8 via 192.168.88.254»")
    wpad_url: str | None = Field(None, description="252: автонастройка прокси (WPAD)")
    vendor_43: str | None = Field(None, description="43: vendor-specific, hex (точки доступа, телефоны)")
    custom: list[CustomOption] = Field(default_factory=list)

    @field_validator("dns_servers", "ntp_servers", "wins_servers", "tftp_servers_150", "sip_servers")
    @classmethod
    def _iplists(cls, v: list[str], info) -> list[str]:
        return _ips(v, info.field_name)

    @field_validator("domain_search")
    @classmethod
    def _search(cls, v: list[str]) -> list[str]:
        return [check_domain(x, "суффикс поиска") for x in v if x.strip()]

    @field_validator("tftp_server", "boot_file", "provisioning_url", "wpad_url")
    @classmethod
    def _text(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        v = v.strip()
        if len(v.encode()) > 255 or any(c in v for c in "\"\n,"):
            raise ValueError(f"значение '{v}': до 255 байт, без кавычек и запятых")
        return v

    @field_validator("vendor_43")
    @classmethod
    def _hex(cls, v: str | None) -> str | None:
        if not v or not v.strip():
            return None
        return CustomOption(code=43, type="hex", value=v).hex()

    @field_validator("static_routes")
    @classmethod
    def _routes(cls, v: list[str]) -> list[str]:
        out = []
        for r in v:
            r = " ".join(r.split())
            if not r:
                continue
            m = re.fullmatch(r"(\S+)\s+(?:via\s+)?(\S+)", r)
            try:
                net = ipaddress.IPv4Network(m[1], strict=False)
                gw = ipaddress.IPv4Address(m[2])
            except (TypeError, ValueError):
                raise ValueError(f"маршрут '{r}': нужен вид 10.0.0.0/8 via 192.168.88.254") from None
            out.append(f"{net} via {gw}")
        return out

    @model_validator(mode="after")
    def _unique_custom(self):
        codes = [c.code for c in self.custom]
        if len(codes) != len(set(codes)):
            raise ValueError("своя опция с одним кодом указана дважды")
        return self

    def classless_routes_hex(self) -> str:
        """RFC 3442: <маска><значимые октеты сети><шлюз> подряд."""
        out = ""
        for r in self.static_routes:
            net_s, gw_s = r.split(" via ")
            net, gw = ipaddress.IPv4Network(net_s), ipaddress.IPv4Address(gw_s)
            significant = (net.prefixlen + 7) // 8
            out += f"{net.prefixlen:02x}" + net.network_address.packed[:significant].hex() + gw.packed.hex()
        return out




class LanConfig(BaseModel):
    """Сегмент LAN: свой мост, адрес, порты, DHCP, DNS и домен.
    Первый сегмент (lan1, мост br-lan) — секция lan: в router.yaml, остальные — lans:."""
    id: str = Field("lan1", description="lan1 — основной сегмент; lan2, lan3… — дополнительные")
    name: str = Field("LAN", max_length=32, description="Имя для людей")
    enabled: bool = False
    address: str = Field("192.168.88.1/24", description="Адрес роутера в LAN — шлюз и DNS для клиентов")
    ports: list[str] = Field(default_factory=list, description="Порты в мосту; пусто = все, кроме WAN")
    dhcp_enabled: bool = True
    pool_start: str | None = Field(None, examples=["192.168.88.10"])
    pool_end: str | None = Field(None, examples=["192.168.88.254"])
    lease_time: str = Field("12h", examples=["1h", "12h", "1d"])
    wan_management: bool = Field(True, description="Разрешить веб и SSH со стороны WAN")
    dns_enabled: bool = Field(True, description="Роутер — DNS-сервер для этого сегмента")
    domain: str | None = Field("office.lan", description="Домен сегмента: имена устройств из DHCP попадают в эту зону")
    forward_to: list[str] = Field(default_factory=list, description="В какие сегменты разрешён транзит из этого")
    dhcp_options: DhcpOptions = Field(default_factory=DhcpOptions)
    vlan_id: int | None = Field(None, ge=1, le=4094, description="802.1Q: сегмент приходит с этим тегом на trunk-порты")
    trunk_ports: list[str] = Field(default_factory=list, description="Порты, где сегмент идёт с тегом vlan_id")

    @field_validator("trunk_ports")
    @classmethod
    def _trunks(cls, v: list[str]) -> list[str]:
        out = []
        for p in v:
            p = p.strip()
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", p):
                raise ValueError(f"неверный порт '{p}' (VLAN ставится на физический порт, например eth1)")
            if p not in out:
                out.append(p)
        return out

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not SEGMENT_ID_RE.match(v):
            raise ValueError("id сегмента: lan1 … lan99")
        return v

    @field_validator("name")
    @classmethod
    def _seg_name(cls, v: str) -> str:
        v = v.strip()
        if not v or any(c in v for c in "<>\"\n"):
            raise ValueError("имя сегмента: 1–32 символа, без кавычек и < >")
        return v

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str | None) -> str | None:
        return check_domain(v) if v and v.strip() else None

    @field_validator("forward_to")
    @classmethod
    def _fwd(cls, v: list[str]) -> list[str]:
        out = []
        for x in v:
            if not SEGMENT_ID_RE.match(x):
                raise ValueError(f"неверный сегмент '{x}'")
            if x not in out:
                out.append(x)
        return out

    @property
    def bridge(self) -> str:
        return "br-lan" if self.id == "lan1" else f"br-{self.id}"

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_interface(self.address).network

    @property
    def router_ip(self) -> str:
        return str(ipaddress.ip_interface(self.address).ip)

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

    @model_validator(mode="after")
    def _self_forward(self):
        if self.id in self.forward_to:
            raise ValueError("сегмент не может пересылать сам в себя")
        if self.trunk_ports and not self.vlan_id:
            raise ValueError(f"{self.name}: для тегированных портов укажите VLAN ID")
        return self

    def to_yaml(self) -> tuple[dict, dict]:
        lan = {
            "enabled": self.enabled,
            "name": self.name,
            "address": self.address,
            "ports": self.ports or ("auto" if self.id == "lan1" else []),
            "dns": self.dns_enabled,
            "domain": self.domain,
            "forward-to": self.forward_to,
            "dhcp-server": {
                "enabled": self.dhcp_enabled,
                "pool": f"{self.pool_start}-{self.pool_end}",
                "lease-time": self.lease_time,
                "options": self.dhcp_options.model_dump(exclude_defaults=True),
            },
        }
        if self.vlan_id:
            lan["vlan"] = {"id": self.vlan_id, "trunk-ports": self.trunk_ports}
        if self.id != "lan1":
            lan = {"id": self.id, **lan}
        return lan, {"wan-management": self.wan_management}

    @classmethod
    def from_yaml(cls, lan: dict | None, firewall: dict | None = None, seg_id: str | None = None) -> "LanConfig":
        lan = lan or {}
        dhcp = lan.get("dhcp-server") or {}
        pool = (dhcp.get("pool") or "").split("-")
        ports = lan.get("ports")
        sid = seg_id or lan.get("id") or "lan1"
        return cls(
            id=sid,
            name=lan.get("name") or ("LAN" if sid == "lan1" else sid.upper()),
            enabled=lan.get("enabled", False),
            address=lan.get("address", "192.168.88.1/24"),
            ports=[] if ports in (None, "auto") else list(ports),
            dhcp_enabled=dhcp.get("enabled", True),
            pool_start=pool[0] if len(pool) == 2 else None,
            pool_end=pool[1] if len(pool) == 2 else None,
            lease_time=str(dhcp.get("lease-time", "12h")),
            wan_management=(firewall or {}).get("wan-management", True),
            dns_enabled=lan.get("dns", True),
            domain=lan.get("domain", "office.lan") if "domain" in lan or sid == "lan1" else None,
            forward_to=list(lan.get("forward-to") or []),
            vlan_id=(lan.get("vlan") or {}).get("id"),
            trunk_ports=list((lan.get("vlan") or {}).get("trunk-ports") or []),
            dhcp_options=DhcpOptions.model_validate(dhcp.get("options") or {}),
        )


class Port(BaseModel):
    name: str
    mac: str | None = None
    link_up: bool = False
    role: str            # wan / lan / none
    segment: str | None = None   # lan1, lan2… — в каком сегменте порт (без тега)
    vlans: list[str] = []        # «10 (Guests)» — сегменты, которые идут через порт с тегом


class Lease(BaseModel):
    ip: str
    mac: str
    lan: str = "lan1"              # сегмент, из пула которого выдан адрес
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
    segments: list["SegmentStatus"] = []        # все сегменты (для вкладки LAN)


class SegmentStatus(BaseModel):
    config: LanConfig
    bridge: str
    active: bool = False
    ports: list[str] = []          # фактически в мосту
    clients: int = 0


class DhcpSettings(BaseModel):
    """Вкладка DHCP: только настройки раздачи адресов сегмента (мост и порты не трогаются)."""
    dhcp_enabled: bool = True
    pool_start: str | None = None
    pool_end: str | None = None
    lease_time: str = "12h"
    dhcp_options: DhcpOptions = Field(default_factory=DhcpOptions)


class DhcpSegmentView(BaseModel):
    id: str
    name: str
    bridge: str
    enabled: bool                  # сегмент включён
    address: str
    network: str
    domain: str | None = None
    dns_enabled: bool = True
    settings: DhcpSettings
    static_leases: list["StaticLeaseView"] = []


class DhcpStatus(BaseModel):
    running: bool = False
    installed: bool = True
    error: str | None = None
    segments: list[DhcpSegmentView] = []
    leases: list[Lease] = []


MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")
HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$")


class StaticLease(BaseModel):
    """Закреплённый адрес: устройство с этим MAC всегда получает этот IP (reservation в Kea)."""
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
        """Строка dhcp-host (формат dnsmasq; Pro его не использует, оставлено для совместимости)."""
        if self.name and HOSTNAME_RE.match(self.name):
            return f"{self.mac},{self.ip},{self.name}"
        return f"{self.mac},{self.ip}"


class StaticLeaseView(StaticLease):
    in_pool: bool = False      # адрес внутри динамического диапазона (работает, но лучше вне пула)
    valid: bool = True         # адрес в сети LAN и не совпадает с адресом роутера


LanStatus.model_rebuild()
DhcpSegmentView.model_rebuild()
