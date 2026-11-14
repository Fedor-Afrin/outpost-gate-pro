"""
VPN → GRE: туннели «роутер — роутер» поверх AmneziaWG / WireGuard / WAN.

  GET /api/gre    туннели, их состояние, интерфейсы для underlay
  PUT /api/gre    сохранить все туннели и применить (GRE, маршруты, OSPF, фаервол)
"""
from fastapi import APIRouter, HTTPException

from app.models.gre import GreConfig, GreStatus
from app.services import gre as svc

router = APIRouter()


@router.get("", response_model=GreStatus)
def get_gre():
    return svc.status()


@router.put("", response_model=GreStatus)
def set_gre(data: GreConfig):
    try:
        return svc.update(data)
    except svc.GreError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
