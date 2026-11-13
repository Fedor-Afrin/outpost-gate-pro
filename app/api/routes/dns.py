"""
Раздел DNS (BIND 9): forwarders, кэш, кто может спрашивать, зоны и записи.

  GET  /api/dns     настройки, зоны, имена, которые роутер добавил сам (DHCP, PTR)
  PUT  /api/dns     сохранить всё целиком и применить (проверка named-checkconf / named-checkzone)
"""
from fastapi import APIRouter, HTTPException

from app.models.dns import DnsConfig, DnsStatus
from app.services import dns as svc

router = APIRouter()


@router.get("", response_model=DnsStatus)
def get_dns():
    return svc.status()


@router.put("", response_model=DnsStatus)
def set_dns(data: DnsConfig):
    try:
        return svc.update(data)
    except svc.DnsError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
