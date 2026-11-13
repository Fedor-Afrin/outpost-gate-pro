"""Схемы мониторинга (секция monitoring: в router.yaml).

Сбор метрик для встроенного дашборда работает всегда. Экспорт наружу — по галочкам:
  prometheus — адрес /metrics (формат Prometheus) для Prometheus + Grafana;
  snmp       — snmpd внутри роутера (v2c или v3): Zabbix, PRTG, LibreNMS, The Dude…;
  zabbix     — Zabbix agent внутри роутера (пассивные и активные проверки).
По умолчанию доступ — только из сегментов LAN; «откуда ещё» — список allowed / server.
"""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator, model_validator

COMMUNITY_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,32}$")
SNMP_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.~+/=-]{16,128}$")
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})(:\d{1,5})?$")
ZBX_NAME_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,128}$")
TEXT_RE = re.compile(r"^[^\"\\\n\r]{0,80}$")


def _networks(v: list[str], what: str) -> list[str]:
    out = []
    for x in v:
        x = (x or "").strip()
        if not x:
            continue
        try:
            n = ipaddress.ip_network(x, strict=False)
            net = str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)   # 10.0.0.5, а не 10.0.0.5/32
        except ValueError:
            raise ValueError(f"{what}: '{x}' — нужен IP-адрес или сеть, например 10.0.0.5 или 10.0.0.0/24") from None
        if ipaddress.ip_network(net).version != 4:
            raise ValueError(f"{what}: '{x}' — пока только IPv4")
        if net not in out:
            out.append(net)
    return out


def _text(v: str | None, what: str) -> str | None:
    v = (v or "").strip() or None
    if v and not TEXT_RE.match(v):
        raise ValueError(f"{what}: до 80 символов, без кавычек и обратной косой черты")
    return v


class PrometheusConfig(BaseModel):
    enabled: bool = False
    token: str | None = Field(None, description="Bearer-токен; пусто — без токена (только по адресу)")
    allowed: list[str] = Field(default_factory=list, examples=[["10.0.0.5", "172.16.0.0/12"]],
                               description="Откуда ещё можно читать /metrics, кроме LAN")

    @field_validator("token")
    @classmethod
    def _tok(cls, v):
        v = (v or "").strip() or None
        if v and not TOKEN_RE.match(v):
            raise ValueError("токен: от 16 до 128 символов — латиница, цифры, - _ . ~ + / =")
        return v

    _a = field_validator("allowed")(classmethod(lambda cls, v: _networks(v, "Prometheus")))


class SnmpConfig(BaseModel):
    enabled: bool = False
    version: str = Field("v2c", description="v2c (community) или v3 (пользователь и пароли)")
    community: str = Field("public", description="Community для v2c — лучше сменить")
    user: str | None = Field(None, description="Пользователь SNMPv3")
    auth_password: str | None = Field(None, description="Пароль аутентификации v3 (SHA), от 8 символов")
    priv_password: str | None = Field(None, description="Пароль шифрования v3 (AES), от 8 символов")
    location: str | None = None
    contact: str | None = None
    allowed: list[str] = Field(default_factory=list, description="Откуда ещё можно опрашивать, кроме LAN")

    _a = field_validator("allowed")(classmethod(lambda cls, v: _networks(v, "SNMP")))
    _l = field_validator("location")(classmethod(lambda cls, v: _text(v, "SNMP location")))
    _c = field_validator("contact")(classmethod(lambda cls, v: _text(v, "SNMP contact")))

    @model_validator(mode="after")
    def _check(self):
        if self.version not in ("v2c", "v3"):
            raise ValueError("SNMP: версия v2c или v3")
        if not COMMUNITY_RE.match(self.community or ""):
            raise ValueError("SNMP community: 1–32 символа — латиница, цифры, _ . @ -")
        for k in ("user", "auth_password", "priv_password"):
            setattr(self, k, (getattr(self, k) or "").strip() or None)
        if self.enabled and self.version == "v3":
            if not self.user or not SNMP_USER_RE.match(self.user):
                raise ValueError("SNMPv3: укажите пользователя (латиница, цифры, _ . -)")
            for k, what in (("auth_password", "аутентификации"), ("priv_password", "шифрования")):
                p = getattr(self, k)
                if not p or len(p) < 8 or not TEXT_RE.match(p):
                    raise ValueError(f"SNMPv3: пароль {what} — от 8 символов, без кавычек")
        return self


class ZabbixConfig(BaseModel):
    enabled: bool = False
    server: list[str] = Field(default_factory=list, examples=[["10.0.0.5"]],
                              description="Zabbix server / proxy: кто может опрашивать агент (пассивные проверки)")
    server_active: str | None = Field(None, examples=["10.0.0.5", "zabbix.example.com:10051"],
                                      description="Куда агент сам отправляет данные (активные проверки); пусто — нет")
    hostname: str | None = Field(None, description="Имя узла в Zabbix; пусто — имя роутера")
    metadata: str | None = Field(None, description="HostMetadata для авторегистрации")

    _s = field_validator("server")(classmethod(lambda cls, v: _networks(v, "Zabbix server")))

    @field_validator("server_active")
    @classmethod
    def _sa(cls, v):
        v = (v or "").strip() or None
        if v and not HOST_RE.match(v):
            raise ValueError("Zabbix ServerActive: адрес или имя, при необходимости с портом (zabbix.lan:10051)")
        return v

    @field_validator("hostname", "metadata")
    @classmethod
    def _name(cls, v):
        v = (v or "").strip() or None
        if v and not ZBX_NAME_RE.match(v):
            raise ValueError("Zabbix: имя узла и метаданные — латиница, цифры, пробел, . _ -")
        return v

    @model_validator(mode="after")
    def _need_server(self):
        if self.enabled and not self.server and not self.server_active:
            raise ValueError("Zabbix: укажите адрес Zabbix server (или ServerActive)")
        return self


class MonitoringConfig(BaseModel):
    ping_targets: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"],
                                    description="Куда мерить задержку и потери (шлюз провайдера — всегда)")
    prometheus: PrometheusConfig = Field(default_factory=PrometheusConfig)
    snmp: SnmpConfig = Field(default_factory=SnmpConfig)
    zabbix: ZabbixConfig = Field(default_factory=ZabbixConfig)

    @field_validator("ping_targets")
    @classmethod
    def _targets(cls, v: list[str]) -> list[str]:
        out = []
        for x in v:
            x = (x or "").strip()
            if not x:
                continue
            try:
                ip = ipaddress.IPv4Address(x)
            except ValueError:
                raise ValueError(f"адрес для проверки связи '{x}': нужен IPv4-адрес") from None
            if str(ip) not in out:
                out.append(str(ip))
        if len(out) > 5:
            raise ValueError("адресов для проверки связи — не больше 5")
        return out

    def to_yaml(self) -> dict:
        return self.model_dump(exclude_none=True)


class ExporterState(BaseModel):
    enabled: bool = False
    installed: bool = True
    running: bool = False
    error: str | None = None
    flavor: str | None = None          # zabbix: agent2 / agentd


class MonitoringSettings(BaseModel):
    config: MonitoringConfig
    snmp: ExporterState
    zabbix: ExporterState
    lan_networks: list[str] = Field(default_factory=list)   # доступ из них открыт всегда
