"""
Раздел Routing: динамическая маршрутизация (FRRouting).

  GET  /api/routing        настройки OSPF и BGP, соседи, маршруты от OSPF/BGP
  PUT  /api/routing        сохранить и применить (FRR перечитывает конфиг без перезапуска)
"""
from fastapi import APIRouter, HTTPException

from app.models.routing import RoutingConfig, RoutingStatus
from app.services import routing as svc

router = APIRouter()


@router.get("", response_model=RoutingStatus)
def get_routing():
    return svc.status()


@router.put("", response_model=RoutingStatus)
def set_routing(data: RoutingConfig):
    try:
        return svc.update(data)
    except svc.RoutingError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
