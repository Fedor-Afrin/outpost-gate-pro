"""Раздел Interfaces (аналог /interface print)."""
from fastapi import APIRouter, HTTPException

from app.models.interface import Interface
from app.services import interfaces as svc

router = APIRouter()


@router.get("", response_model=list[Interface])
def list_interfaces():
    return svc.list_interfaces()


@router.get("/{name}", response_model=Interface)
def get_interface(name: str):
    iface = svc.get_interface(name)
    if iface is None:
        raise HTTPException(status_code=404, detail=f"Интерфейс {name} не найден")
    return iface
