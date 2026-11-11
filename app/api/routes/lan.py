"""
Раздел LAN.

  GET    /api/lan                       состояние: мост, порты, DHCP-аренды, закреплённые адреса
  PUT    /api/lan                       сохранить настройки и применить (мост, dnsmasq, NAT, фаервол)
  POST   /api/lan/static-leases         закрепить адрес за MAC
  PUT    /api/lan/static-leases/{mac}   изменить
  DELETE /api/lan/static-leases/{mac}   открепить
Закреплённые адреса применяются без перезапуска LAN (dnsmasq перечитывает их по SIGHUP).
"""
from fastapi import APIRouter, HTTPException

from app.models.lan import LanConfig, LanStatus, StaticLease, StaticLeaseView
from app.services import lan as svc

router = APIRouter()


@router.get("", response_model=LanStatus)
def get_lan():
    return svc.status()


@router.put("", response_model=LanStatus)
def set_lan(data: LanConfig):
    try:
        return svc.update(data)
    except svc.LanError as e:
        raise HTTPException(status_code=e.status, detail=e.message)


def _http(e: svc.LanError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=e.message)


@router.post("/static-leases", response_model=list[StaticLeaseView], status_code=201)
def add_static(item: StaticLease):
    try:
        return svc.add_static(item)
    except svc.LanError as e:
        raise _http(e)


@router.put("/static-leases/{mac}", response_model=list[StaticLeaseView])
def update_static(mac: str, item: StaticLease):
    try:
        return svc.update_static(mac, item)
    except svc.LanError as e:
        raise _http(e)


@router.delete("/static-leases/{mac}", response_model=list[StaticLeaseView])
def delete_static(mac: str):
    try:
        return svc.delete_static(mac)
    except svc.LanError as e:
        raise _http(e)
