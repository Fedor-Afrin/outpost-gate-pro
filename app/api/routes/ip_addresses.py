"""
Раздел IP → Addresses (аналог /ip address в RouterOS).

  GET    /api/ip/addresses          /ip address print
  POST   /api/ip/addresses          /ip address add address=... interface=...
  PATCH  /api/ip/addresses/{id}     /ip address set / enable / disable
  DELETE /api/ip/addresses/{id}     /ip address remove
"""
from fastapi import APIRouter, HTTPException, Response, status

from app.models.address import Address, AddressCreate, AddressUpdate
from app.services import addresses as svc

router = APIRouter()


def _http(e: svc.AddressError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=e.message)


@router.get("", response_model=list[Address])
def print_addresses():
    return svc.list_addresses()


@router.post("", response_model=Address, status_code=status.HTTP_201_CREATED)
def add_address(data: AddressCreate):
    try:
        return svc.add_address(data)
    except svc.AddressError as e:
        raise _http(e)


@router.patch("/{addr_id}", response_model=Address)
def set_address(addr_id: int, data: AddressUpdate):
    try:
        return svc.update_address(addr_id, data)
    except svc.AddressError as e:
        raise _http(e)


@router.delete("/{addr_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_address(addr_id: int):
    try:
        svc.remove_address(addr_id)
    except svc.AddressError as e:
        raise _http(e)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
