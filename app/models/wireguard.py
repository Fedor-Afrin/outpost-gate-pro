"""Схемы VPN → WireGuard и AmneziaWG (клиент).

AmneziaWG — тот же WireGuard плюс параметры обфускации в [Interface]
(Jc, Jmin, Jmax, S1–S4, H1–H4, I1–I5, J1–J3, Itime): мусорные пакеты и
изменённые заголовки, чтобы DPI не узнавал протокол. AmneziaWG 3.x добавил
HeaderProtectionKey, ContentPaddingAddition, RandomTrailers, DisableCookies и
тайминги диапазонами (RekeyAfterTime = 100-120 …).

Импорт: текст .conf (wg-quick) или ссылка / файл vpn:// из приложения Amnezia.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import zlib
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$")   # 32 байта в base64
# AmneziaWG 3.x: параметры устройства, пишутся в [Interface] — имя -> как его пишет awg
AWG3_KEYS = {k.lower(): k for k in (
    "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies")}
AWG_KEY_RE = re.compile(r"^(jc|jmin|jmax|s[1-4]|h[1-4]|i[1-5]|j[1-3]|itime|" + "|".join(AWG3_KEYS) + r")$",
                        re.IGNORECASE)
ENDPOINT_RE = re.compile(r"^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):(\d{1,5})$")


def _key(v: str | None, what: str) -> str | None:
    if not v:
        return None
    v = v.strip()
    if not KEY_RE.match(v):
        raise ValueError(f"{what}: неверный ключ WireGuard (44 символа base64)")
    return v


class WgConfig(BaseModel):
    """Настройки клиента WireGuard (секция vpn.wireguard в router.yaml)."""
    enabled: bool = False
    private_key: str | None = Field(None, description="Пусто при сохранении = оставить прежний")
    addresses: list[str] = Field(default_factory=list, examples=[["10.8.0.2/32"]])
    dns: list[str] = Field(default_factory=list, examples=[["10.8.0.1"]])
    mtu: int = Field(1420, ge=1280, le=1500)
    peer_public_key: str | None = None
    preshared_key: str | None = None
    endpoint: str | None = Field(None, examples=["vpn.example.com:51820"])
    allowed_ips: list[str] = Field(default_factory=list, examples=[["10.0.0.0/8", "192.168.10.0/24"]])
    keepalive: int = Field(25, ge=0, le=3600)
    mode: Literal["full", "split"] = Field(
        "full", description="full — весь трафик в туннель; split — только сети компании (allowed_ips)")
    nat: bool = Field(True, description="Маскировать LAN за адресом туннеля (нужно, если сервер не знает сеть LAN)")
    killswitch: bool = Field(True, description="В режиме full: без туннеля — без интернета")
    obfuscation: dict[str, str] = Field(
        default_factory=dict, description="Только AmneziaWG: Jc, Jmin, Jmax, S1, S2, H1–H4 …",
        examples=[{"Jc": "4", "Jmin": "40", "Jmax": "70", "S1": "0", "S2": "0", "H1": "1"}])

    @field_validator("obfuscation")
    @classmethod
    def _obf(cls, v: dict[str, str]) -> dict[str, str]:
        out = {}
        for key, value in v.items():
            key, value = key.strip(), str(value).strip()
            if not AWG_KEY_RE.match(key):
                raise ValueError(f"неизвестный параметр AmneziaWG: {key}")
            if not value or "\n" in value:
                raise ValueError(f"пустое или многострочное значение {key}")
            low = key.lower()
            canon = (AWG3_KEYS[low] if low in AWG3_KEYS
                     else key[0].upper() + key[1:].lower() if low in ("jc", "jmin", "jmax", "itime") else key.upper())
            out[canon] = value
        return out

    @field_validator("private_key")
    @classmethod
    def _pk(cls, v):
        return _key(v, "PrivateKey")

    @field_validator("peer_public_key")
    @classmethod
    def _pub(cls, v):
        return _key(v, "PublicKey сервера")

    @field_validator("preshared_key")
    @classmethod
    def _psk(cls, v):
        return _key(v, "PresharedKey")

    @field_validator("addresses")
    @classmethod
    def _addresses(cls, v: list[str]) -> list[str]:
        out = []
        for a in v:
            a = a.strip()
            if not a:
                continue
            iface = ipaddress.ip_interface(a if "/" in a else f"{a}/32")
            if iface.version == 4:          # IPv6-адреса туннеля пока пропускаем
                out.append(str(iface))
        return out

    @field_validator("dns")
    @classmethod
    def _dns(cls, v: list[str]) -> list[str]:
        out = []
        for d in v:
            d = d.strip()
            if not d:
                continue
            try:
                ip = ipaddress.ip_address(d)
            except ValueError:
                continue                     # в DNS бывают домены поиска — пропускаем
            if ip.version == 4:
                out.append(str(ip))
        return out

    @field_validator("allowed_ips")
    @classmethod
    def _allowed(cls, v: list[str]) -> list[str]:
        out = []
        for n in v:
            n = n.strip()
            if not n:
                continue
            net = ipaddress.ip_network(n, strict=False)
            if net.version == 4:
                out.append(str(net))
        return out

    @field_validator("endpoint")
    @classmethod
    def _endpoint(cls, v: str | None) -> str | None:
        if not v:
            return None
        v = v.strip()
        m = ENDPOINT_RE.match(v)
        if not m or not 0 < int(m.group(2)) < 65536:
            raise ValueError(f"Endpoint '{v}': ожидается адрес:порт, например vpn.example.com:51820")
        return v

    @model_validator(mode="after")
    def _complete(self):
        if self.enabled:
            missing = [n for n, val in (("Address", self.addresses), ("PublicKey сервера", self.peer_public_key),
                                        ("Endpoint", self.endpoint)) if not val]
            if missing:
                raise ValueError("для включения не хватает: " + ", ".join(missing))
            if self.mode == "split" and not self.split_networks():
                raise ValueError("режим split: укажите сети компании (AllowedIPs), кроме 0.0.0.0/0")
        return self

    def split_networks(self) -> list[str]:
        return [n for n in self.allowed_ips if ipaddress.ip_network(n).prefixlen > 0]

    def endpoint_host_port(self) -> tuple[str, int]:
        m = ENDPOINT_RE.match(self.endpoint or "")
        return m.group(1).strip("[]"), int(m.group(2))

    # --- router.yaml ---
    def to_yaml(self) -> dict:
        return {
            "enabled": self.enabled,
            "private-key": self.private_key,
            "address": self.addresses,
            "dns": self.dns,
            "mtu": self.mtu,
            "peer": {
                "public-key": self.peer_public_key,
                "preshared-key": self.preshared_key,
                "endpoint": self.endpoint,
                "allowed-ips": self.allowed_ips,
                "persistent-keepalive": self.keepalive,
            },
            "mode": self.mode,
            "nat": self.nat,
            "killswitch": self.killswitch,
            **({"obfuscation": self.obfuscation} if self.obfuscation else {}),
        }

    @classmethod
    def from_yaml(cls, d: dict | None) -> "WgConfig":
        d = d or {}
        p = d.get("peer") or {}
        return cls(
            enabled=d.get("enabled", False), private_key=d.get("private-key"),
            addresses=d.get("address") or [], dns=d.get("dns") or [], mtu=d.get("mtu", 1420),
            peer_public_key=p.get("public-key"), preshared_key=p.get("preshared-key"),
            endpoint=p.get("endpoint"), allowed_ips=p.get("allowed-ips") or [],
            keepalive=p.get("persistent-keepalive", 25),
            mode=d.get("mode", "full"), nat=d.get("nat", True), killswitch=d.get("killswitch", True),
            obfuscation=d.get("obfuscation") or {},
        )


def decode_vpn_link(text: str) -> str:
    """vpn://… (ссылка или файл .vpn из приложения Amnezia) -> текст конфига wg-quick.

    Внутри: base64url( 4 байта длины + zlib(JSON) ) — формат qCompress. В JSON — контейнеры
    (amnezia-awg2, amnezia-wireguard …), у каждого last_config с полем config = готовый .conf;
    $PRIMARY_DNS / $SECONDARY_DNS в нём — подставить из dns1 / dns2."""
    s = "".join(text.split())
    b64 = s[len("vpn://"):]
    try:
        raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    except (ValueError, TypeError) as e:
        raise ValueError("ссылка vpn:// повреждена (не base64)") from e
    try:
        data = zlib.decompress(raw[4:])
    except zlib.error:
        data = raw                                   # старые версии: JSON без сжатия
    try:
        j = json.loads(data)
    except ValueError as e:
        raise ValueError("ссылка vpn:// повреждена (внутри не JSON)") from e
    containers = j.get("containers") or []
    default = j.get("defaultContainer")
    for c in sorted(containers, key=lambda c: c.get("container") != default):
        for v in c.values():
            if not isinstance(v, dict) or not v.get("last_config"):
                continue
            lc = v["last_config"]
            try:
                lc = json.loads(lc) if isinstance(lc, str) else lc
            except ValueError:
                continue
            conf = lc.get("config") if isinstance(lc, dict) else None
            if conf and "[Interface]" in conf:
                dns = [x for x in (j.get("dns1"), j.get("dns2")) if x]
                return (conf.replace("$PRIMARY_DNS", dns[0] if dns else "")
                            .replace("$SECONDARY_DNS", dns[1] if len(dns) > 1 else ""))
    kinds = ", ".join(c.get("container", "?") for c in containers) or "нет"
    raise ValueError(f"в ссылке vpn:// нет готового конфига WireGuard / AmneziaWG (контейнеры: {kinds}). "
                     "В приложении Amnezia: «Поделиться» → протокол AmneziaWG → формат AmneziaWG или WireGuard")


def _first(v: str | None, default: int) -> int:
    """PersistentKeepalive = 25 или диапазон AmneziaWG 3 «25-35» -> 25."""
    if not v:
        return default
    m = re.match(r"^\s*(\d+)", v)
    if not m:
        raise ValueError(f"неверное значение PersistentKeepalive: {v}")
    return int(m.group(1))


def parse_wg_quick(text: str) -> WgConfig:
    """Разобрать конфиг wg-quick (.conf от сервера WireGuard / Amnezia) или ссылку vpn:// в WgConfig."""
    if text.strip().lower().startswith("vpn://"):
        text = decode_vpn_link(text)
    section, iface, peer, obf = None, {}, {}, {}
    for raw in text.splitlines():
        # комментарий # отрезаем, кроме I1–I5 у AmneziaWG: там # — часть значения
        line = raw.strip() if re.match(r"^\s*I[1-5]\s*=", raw, re.IGNORECASE) else raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").lower()
            if section == "peer" and peer:
                raise ValueError("в конфиге несколько [Peer] — клиенту нужен один сервер")
            continue
        if "=" not in line:
            continue
        key, value = (x.strip() for x in line.split("=", 1))
        if section == "interface" and AWG_KEY_RE.match(key):
            if value:                                  # Amnezia пишет пустые I1 = … — пропускаем
                obf[key] = value
            continue
        target = iface if section == "interface" else peer if section == "peer" else None
        if target is not None:
            target[key.lower()] = value
    if not iface or not peer:
        raise ValueError("не найдены секции [Interface] и [Peer]")

    split = lambda v: [x.strip() for x in (v or "").split(",") if x.strip()]
    allowed = split(peer.get("allowedips"))
    full = any(a in ("0.0.0.0/0", "::/0") for a in allowed)
    return WgConfig(
        private_key=iface.get("privatekey"),
        addresses=split(iface.get("address")),
        dns=split(iface.get("dns")),
        mtu=int(iface.get("mtu", 1420)),
        peer_public_key=peer.get("publickey"),
        preshared_key=peer.get("presharedkey"),
        endpoint=peer.get("endpoint"),
        allowed_ips=allowed,
        keepalive=_first(peer.get("persistentkeepalive"), 25),
        mode="full" if full else "split",
        obfuscation=obf,
    )


class WgStatus(BaseModel):
    kind: str = "wireguard"           # wireguard / amneziawg
    config: WgConfig                  # private_key в ответе всегда пустой
    private_key_set: bool = False
    public_key: str | None = None     # публичный ключ роутера — отдать администратору сервера
    interface: str = "wg0"            # wg0 / awg0
    active: bool = False              # интерфейс поднят
    connected: bool = False           # handshake был не дольше 3 минут назад
    endpoint_ip: str | None = None
    latest_handshake: int | None = None   # unix time
    rx_bytes: int = 0
    tx_bytes: int = 0
    error: str | None = None
