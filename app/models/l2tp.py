"""Схемы VPN → L2TP/IPsec (клиент): совместимость с серверами MikroTik, Windows, Cisco."""
from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
SAFE_RE = re.compile(r'^[^"\\\n\r]*$')        # без кавычек, \ и переводов строки — пишем в конфиги


class L2tpConfig(BaseModel):
    """Настройки клиента L2TP/IPsec (секция vpn.l2tp в router.yaml)."""
    enabled: bool = False
    server: str | None = Field(None, examples=["vpn.example.com"])
    psk: str | None = Field(None, description="IPsec pre-shared key; пусто при сохранении = прежний")
    username: str | None = None
    password: str | None = Field(None, description="Пусто при сохранении = прежний")
    mode: Literal["full", "split"] = "full"
    networks: list[str] = Field(default_factory=list, description="Сети компании для режима split",
                                examples=[["192.168.10.0/24"]])
    nat: bool = True
    killswitch: bool = True
    mtu: int = Field(1400, ge=1280, le=1460)

    @field_validator("server")
    @classmethod
    def _server(cls, v: str | None) -> str | None:
        if not v:
            return None
        v = v.strip()
        if not HOST_RE.match(v):
            raise ValueError(f"сервер '{v}': нужен IP-адрес или имя")
        return v

    @field_validator("psk", "username", "password")
    @classmethod
    def _safe(cls, v: str | None) -> str | None:
        if not v:
            return None
        if not SAFE_RE.match(v):
            raise ValueError("нельзя использовать кавычки \", обратную косую черту и переводы строк")
        return v

    @field_validator("networks")
    @classmethod
    def _networks(cls, v: list[str]) -> list[str]:
        out = []
        for n in v:
            n = n.strip()
            if n:
                net = ipaddress.ip_network(n, strict=False)
                if net.version == 4 and net.prefixlen > 0:
                    out.append(str(net))
        return out

    @model_validator(mode="after")
    def _complete(self):
        if self.enabled:
            missing = [n for n, v in (("сервер", self.server), ("имя пользователя", self.username)) if not v]
            if missing:
                raise ValueError("для включения не хватает: " + ", ".join(missing))
            if self.mode == "split" and not self.networks:
                raise ValueError("режим split: укажите сети компании")
        return self

    def to_yaml(self) -> dict:
        return {"enabled": self.enabled, "server": self.server, "psk": self.psk,
                "username": self.username, "password": self.password, "mode": self.mode,
                "networks": self.networks, "nat": self.nat, "killswitch": self.killswitch, "mtu": self.mtu}

    @classmethod
    def from_yaml(cls, d: dict | None) -> "L2tpConfig":
        return cls(**(d or {}))


class L2tpStatus(BaseModel):
    config: L2tpConfig            # psk и password в ответе всегда пустые
    psk_set: bool = False
    password_set: bool = False
    interface: str = "l2tp0"
    ipsec_up: bool = False        # IPsec SA установлена
    connected: bool = False       # PPP поднят, адрес получен
    local_ip: str | None = None
    remote_ip: str | None = None
    endpoint_ip: str | None = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    error: str | None = None
