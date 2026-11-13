"""
Раздел WAN.

  GET  /api/wan         состояние WAN и текущие настройки
  PUT  /api/wan         сохранить настройки (dhcp / static / none) и применить
  POST /api/wan/renew   обновить аренду DHCP

  GET  /api/wan/wan2          второй провайдер: состояние и настройки
  PUT  /api/wan/wan2          включить / выключить / изменить второй WAN
  POST /api/wan/wan2/renew    обновить аренду DHCP второго WAN
  GET  /api/wan/multiwan      резерв или балансировка: настройки, состояние каналов, переключения
  PUT  /api/wan/multiwan      сохранить режим, веса и проверку связи
"""
from fastapi import APIRouter, HTTPException

from app.models.wan import MultiWanConfig, MultiWanStatus, Wan2Config, WanConfig, WanStatus
from app.services import multiwan
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


@router.get("/wan2", response_model=WanStatus)
def get_wan2():
    return svc.status("wan2")


@router.put("/wan2", response_model=WanStatus)
def set_wan2(data: Wan2Config):
    try:
        return svc.update_wan2(data)
    except svc.WanError as e:
        raise _http(e)


@router.post("/wan2/renew", response_model=WanStatus)
def renew_wan2():
    try:
        svc.renew("wan2")
    except svc.WanError as e:
        raise _http(e)
    return svc.status("wan2")


@router.get("/multiwan", response_model=MultiWanStatus)
def get_multiwan():
    return multiwan.status()


@router.put("/multiwan", response_model=MultiWanStatus)
def set_multiwan(data: MultiWanConfig):
    return multiwan.update(data)
