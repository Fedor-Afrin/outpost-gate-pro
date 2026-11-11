"""
Раздел WAN.

  GET  /api/wan         состояние WAN и текущие настройки
  PUT  /api/wan         сохранить настройки (dhcp / static / none) и применить
  POST /api/wan/renew   обновить аренду DHCP
"""
from fastapi import APIRouter, HTTPException

from app.models.wan import WanConfig, WanStatus
from app.services import wan as svc

router = APIRouter()


def _http(e: svc.WanError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=e.message)


@router.get("", response_model=WanStatus)
def get_wan():
    return svc.status()


@router.put("", response_model=WanStatus)
def set_wan(data: WanConfig):
    try:
        return svc.update(data)
    except svc.WanError as e:
        raise _http(e)


@router.post("/renew", response_model=WanStatus)
def renew_wan():
    try:
        svc.renew()
    except svc.WanError as e:
        raise _http(e)
    return svc.status()
