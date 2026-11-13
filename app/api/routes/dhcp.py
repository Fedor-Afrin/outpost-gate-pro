"""
Раздел DHCP (Kea): пулы, срок аренды, опции и закреплённые адреса по сегментам LAN.

  GET    /api/dhcp                                  сегменты, их настройки, все аренды
  PUT    /api/dhcp/{id}                             пул, срок, опции сегмента (Kea перечитывает без перезапуска)
  POST   /api/dhcp/{id}/static-leases               закрепить адрес за MAC
  PUT    /api/dhcp/{id}/static-leases/{mac}         изменить
  DELETE /api/dhcp/{id}/static-leases/{mac}         открепить
"""
from fastapi import APIRouter, HTTPException

from app.models.lan import DhcpSettings, DhcpStatus, StaticLease, StaticLeaseView
from app.services import lan as svc

router = APIRouter()


def _http(e: svc.LanError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=e.message)


@router.get("", response_model=DhcpStatus)
def get_dhcp():
    return svc.dhcp_status()


@router.put("/{seg_id}", response_model=DhcpStatus)
def set_dhcp(seg_id: str, data: DhcpSettings):
    try:
        return svc.update_dhcp(seg_id, data)
    except svc.LanError as e:
        raise _http(e)


@router.post("/{seg_id}/static-leases", response_model=list[StaticLeaseView], status_code=201)
def add_static(seg_id: str, item: StaticLease):
    try:
        return svc.add_static(item, seg_id)
    except svc.LanError as e:
        raise _http(e)


@router.put("/{seg_id}/static-leases/{mac}", response_model=list[StaticLeaseView])
def update_static(seg_id: str, mac: str, item: StaticLease):
    try:
        return svc.update_static(mac, item, seg_id)
    except svc.LanError as e:
        raise _http(e)


@router.delete("/{seg_id}/static-leases/{mac}", response_model=list[StaticLeaseView])
def delete_static(seg_id: str, mac: str):
    try:
        return svc.delete_static(mac, seg_id)
    except svc.LanError as e:
        raise _http(e)
