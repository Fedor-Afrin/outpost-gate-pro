"""
Раздел IP → Routes (аналог /ip route в RouterOS).

  GET    /api/ip/routes          /ip route print
  POST   /api/ip/routes          /ip route add dst-address=... gateway=... distance=...
  PATCH  /api/ip/routes/{id}     /ip route set / enable / disable
  DELETE /api/ip/routes/{id}     /ip route remove
"""
from fastapi import APIRouter, HTTPException, Response, status

from app.models.route import Route, RouteCreate, RouteUpdate
from app.services import routes as svc

router = APIRouter()


def _http(e: svc.RouteError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=e.message)


@router.get("", response_model=list[Route])
def print_routes():
    return svc.list_routes()


@router.post("", response_model=Route, status_code=status.HTTP_201_CREATED)
def add_route(data: RouteCreate):
    try:
        return svc.add_route(data)
    except svc.RouteError as e:
        raise _http(e)


@router.patch("/{route_id}", response_model=Route)
def set_route(route_id: int, data: RouteUpdate):
    try:
        return svc.update_route(route_id, data)
    except svc.RouteError as e:
        raise _http(e)


@router.delete("/{route_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_route(route_id: int):
    try:
        svc.remove_route(route_id)
    except svc.RouteError as e:
        raise _http(e)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
