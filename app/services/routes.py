"""
Логика раздела IP → Routes.

В router.yaml (ключи как в RouterOS):
  ip:
    routes:
      - { id: 1, dst-address: 0.0.0.0/0, gateway: 192.168.1.1, distance: 1 }

distance в RouterOS = metric в Linux: чем меньше, тем приоритетнее.
Порядок изменения тот же, что у адресов: проверка -> ядро -> router.yaml.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from app.core.store import store
from app.models.route import Route, RouteCreate, RouteUpdate, gateway_is_ip
from app.services import netlink


class RouteError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --- конфиг -------------------------------------------------------------------
def _entries(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    ip = cfg.get("ip") or {}
    cfg["ip"] = ip
    entries = ip.get("routes") or []
    ip["routes"] = entries
    next_id = max((e.get("id", 0) for e in entries), default=0) + 1
    for e in entries:
        e.setdefault("distance", 1)
        if "id" not in e:
            e["id"] = next_id
            next_id += 1
    return entries


def _find(entries, route_id: int) -> dict[str, Any]:
    for e in entries:
        if e["id"] == route_id:
            return e
    raise RouteError(404, f"маршрут с id={route_id} не найден")


def _active(e) -> bool:
    return not e.get("disabled", False)


def _key(e) -> tuple[str, str, int]:
    return e["dst-address"], e["gateway"], int(e["distance"])


def _split(gateway: str) -> tuple[str | None, str | None]:
    """'192.168.1.1' -> (ip, None);  'eth1' -> (None, 'eth1')."""
    return (gateway, None) if gateway_is_ip(gateway) else (None, gateway)


def _kernel_add(e) -> None:
    gw, ifname = _split(e["gateway"])
    try:
        netlink.route_add(e["dst-address"], gw, ifname, int(e["distance"]))
    except netlink.NetlinkOpError as err:
        raise RouteError(400, str(err)) from err


def _kernel_del(e) -> None:
    gw, ifname = _split(e["gateway"])
    try:
        netlink.route_del(e["dst-address"], gw, ifname, int(e["distance"]))
    except netlink.NetlinkOpError as err:
        raise RouteError(500, str(err)) from err


def _check(entries, e, skip_id: int | None = None) -> None:
    _, ifname = _split(e["gateway"])
    if ifname and ifname not in netlink.link_names():
        raise RouteError(400, f"интерфейс '{ifname}' не существует")
    for other in entries:
        if other["id"] != skip_id and _key(other) == _key(e):
            raise RouteError(409, f"такой маршрут уже есть (id={other['id']})")


def _match(e, kernel: list[dict]) -> dict | None:
    """Найти маршрут конфига среди маршрутов ядра."""
    gw, ifname = _split(e["gateway"])
    for r in kernel:
        if r["dst"] != e["dst-address"] or r["metric"] != int(e["distance"]):
            continue
        if gw and r["gateway"] == gw:
            return r
        if ifname and not r["gateway"] and r["interface"] == ifname:
            return r
    return None


def _to_model(e, kroute: dict | None) -> Route:
    return Route(
        id=e["id"],
        dst_address=e["dst-address"],
        gateway=e["gateway"],
        distance=int(e["distance"]),
        interface=kroute["interface"] if kroute else None,
        comment=e.get("comment"),
        disabled=e.get("disabled", False),
        active=kroute is not None,
        static=True,
    )


def _sort_key(r: Route):
    net = ipaddress.ip_network(r.dst_address)
    return (int(net.network_address), net.prefixlen, r.distance)


# --- публичные операции ---------------------------------------------------------
def list_routes() -> list[Route]:
    entries = _entries(store.load())
    kernel = netlink.kernel_ipv4_routes()

    result: list[Route] = []
    used: list[dict] = []
    for e in entries:
        k = _match(e, kernel) if _active(e) else None
        if k:
            used.append(k)
        result.append(_to_model(e, k))

    # Динамические маршруты: connected (C) от адресов, маршрут Docker/DHCP и т.п. (D)
    for r in kernel:
        if r in used:
            continue
        result.append(Route(
            id=None,
            dst_address=r["dst"],
            gateway=r["gateway"] or r["interface"] or "",
            distance=r["metric"],
            interface=r["interface"],
            active=True,
            dynamic=True,
            connected=r["proto"] == netlink.RTPROT_KERNEL,
            ospf=r["proto"] == netlink.RTPROT_OSPF,
            bgp=r["proto"] == netlink.RTPROT_BGP,
        ))
    return sorted(result, key=_sort_key)


def add_route(data: RouteCreate) -> Route:
    with store.transaction() as cfg:
        entries = _entries(cfg)
        entry: dict[str, Any] = {
            "id": max((e["id"] for e in entries), default=0) + 1,
            "dst-address": data.dst_address,
            "gateway": data.gateway,
            "distance": data.distance,
        }
        if data.comment:
            entry["comment"] = data.comment
        if data.disabled:
            entry["disabled"] = True
        _check(entries, entry)
        if _active(entry):
            _kernel_add(entry)
        entries.append(entry)
    return _to_model(entry, None if data.disabled else {"interface": None})


def update_route(route_id: int, data: RouteUpdate) -> Route:
    with store.transaction() as cfg:
        entries = _entries(cfg)
        entry = _find(entries, route_id)
        old = dict(entry)

        changes = data.model_dump(exclude_unset=True)
        mapping = {"dst_address": "dst-address"}
        new = dict(entry)
        for k, v in changes.items():
            if v is None and k != "comment":
                continue
            new[mapping.get(k, k)] = v
        if not new.get("comment"):
            new.pop("comment", None)
        if not new.get("disabled"):
            new.pop("disabled", None)

        _check(entries, new, skip_id=route_id)

        if (_key(old), _active(old)) != (_key(new), _active(new)):
            if _active(old):
                _kernel_del(old)
            if _active(new):
                try:
                    _kernel_add(new)
                except RouteError:
                    if _active(old):  # вернуть как было
                        _kernel_add(old)
                    raise

        entry.clear()
        entry.update(new)
    return _to_model(entry, None if entry.get("disabled") else {"interface": None})


def remove_route(route_id: int) -> None:
    with store.transaction() as cfg:
        entries = _entries(cfg)
        entry = _find(entries, route_id)
        if _active(entry):
            _kernel_del(entry)
        entries.remove(entry)


def apply_all() -> None:
    """При старте: применить включённые маршруты (после адресов — иначе шлюз недоступен)."""
    with store.transaction() as cfg:
        entries = [e for e in _entries(cfg) if _active(e)]
    for e in entries:
        try:
            _kernel_add(e)
            print(f"[agent] route {e['dst-address']} via {e['gateway']} distance={e['distance']}")
        except RouteError as err:
            print(f"[agent] WARNING: route {e['dst-address']}: {err.message}")
