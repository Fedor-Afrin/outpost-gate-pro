"""
Раздел LAN: сегменты (мосты), их адреса, порты, DNS, домен, транзит между сегментами.

  GET    /api/lan                       основной сегмент (lan1): мост, порты, аренды, все сегменты
  PUT    /api/lan                       сохранить основной сегмент и применить
  GET    /api/lan/segments              все сегменты
  POST   /api/lan/segments              добавить сегмент (id выдаётся: lan2, lan3…)
  PUT    /api/lan/segments/{id}         изменить сегмент
  DELETE /api/lan/segments/{id}         удалить (кроме lan1)
  POST   /api/lan/static-leases         закрепить адрес за MAC (сегмент — по адресу)
  PUT    /api/lan/static-leases/{mac}   изменить
  DELETE /api/lan/static-leases/{mac}   открепить
Пулы, опции DHCP и закреплённые адреса по сегментам — /api/dhcp.
"""
from fastapi import APIRouter, HTTPException

from app.models.lan import LanConfig, LanStatus, SegmentStatus, StaticLease, StaticLeaseView
from app.services import lan as svc

router = APIRouter()


def _http(e: svc.LanError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=e.message)


@router.get("", response_model=LanStatus)
def get_lan():
    return svc.status()


@router.put("", response_model=LanStatus)
def set_lan(data: LanConfig):
    try:
        return svc.update(data)
    except svc.LanError as e:
        raise _http(e)


@router.get("/segments", response_model=list[SegmentStatus])
def list_segments():
    return svc.segments_status()


@router.post("/segments", response_model=list[SegmentStatus], status_code=201)
def add_segment(data: LanConfig):
    try:
        return svc.add_segment(data)
    except svc.LanError as e:
        raise _http(e)


@router.put("/segments/{seg_id}", response_model=list[SegmentStatus])
def update_segment(seg_id: str, data: LanConfig):
    try:
        return svc.update_segment(seg_id, data)
    except svc.LanError as e:
        raise _http(e)


@router.delete("/segments/{seg_id}", response_model=list[SegmentStatus])
def delete_segment(seg_id: str):
    try:
        return svc.delete_segment(seg_id)
    except svc.LanError as e:
        raise _http(e)


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
