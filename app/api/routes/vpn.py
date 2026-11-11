"""
Раздел VPN. Одновременно работает один туннель: включение одного выключает остальные.

  GET  /api/vpn                       какой туннель включён
  GET  /api/vpn/{wireguard|amneziawg}         состояние и настройки (без приватного ключа)
  PUT  /api/vpn/{wireguard|amneziawg}         сохранить и применить
  POST /api/vpn/{wireguard|amneziawg}/parse   разобрать .conf от сервера (для заполнения формы)
  POST /api/vpn/genkey                        сгенерировать пару ключей WireGuard/AmneziaWG
  GET  /api/vpn/l2tp,  PUT /api/vpn/l2tp       L2TP/IPsec (без PSK и пароля в ответе)
"""
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.models.l2tp import L2tpConfig, L2tpStatus
from app.models.wireguard import WgConfig, WgStatus, parse_wg_quick
from app.services import vpn as svc

router = APIRouter()
WgKind = Literal["wireguard", "amneziawg"]


class ConfText(BaseModel):
    text: str


class KeyPair(BaseModel):
    private_key: str
    public_key: str


class VpnSummary(BaseModel):
    enabled: str | None      # wireguard / amneziawg / l2tp / None


def _http(e: svc.VpnError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=e.message)


@router.get("", response_model=VpnSummary)
def summary():
    return VpnSummary(enabled=svc.enabled_kind())


@router.post("/genkey", response_model=KeyPair)
def generate_keys():
    try:
        private, public = svc.genkey()
    except svc.VpnError as e:
        raise _http(e)
    return KeyPair(private_key=private, public_key=public)


@router.get("/l2tp", response_model=L2tpStatus)
def get_l2tp():
    return svc.status("l2tp")


@router.put("/l2tp", response_model=L2tpStatus)
def set_l2tp(data: L2tpConfig):
    try:
        return svc.update("l2tp", data)
    except svc.VpnError as e:
        raise _http(e)


@router.get("/{kind}", response_model=WgStatus)
def get_wg(kind: WgKind):
    return svc.status(kind)


@router.put("/{kind}", response_model=WgStatus)
def set_wg(kind: WgKind, data: WgConfig):
    if kind == "wireguard" and data.obfuscation:
        raise HTTPException(422, "параметры обфускации есть только у AmneziaWG")
    try:
        return svc.update(kind, data)
    except svc.VpnError as e:
        raise _http(e)


@router.post("/{kind}/parse", response_model=WgConfig)
def parse_conf(kind: WgKind, body: ConfText):
    try:
        cfg = parse_wg_quick(body.text)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"не удалось разобрать конфиг: {e}")
    if kind == "wireguard" and cfg.obfuscation:
        raise HTTPException(422, "это конфиг AmneziaWG (есть Jc, S1, H1…) — импортируйте его во вкладке AmneziaWG")
    return cfg
