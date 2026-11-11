"""
Логика раздела IP → Addresses.

Порядок любого изменения:
  1. проверка (интерфейс есть, нет дубликата);
  2. применение к ядру через netlink;
  3. сохранение в router.yaml (со снимком предыдущей версии).
Если шаг 2 упал — конфиг не меняется, ошибка уходит клиенту.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Any

from app.core.store import store
from app.models.address import Address, AddressCreate, AddressUpdate
from app.services import netlink

HIDDEN_INTERFACES = {"lo"}  # loopback в /ip address не показываем, как RouterOS


class AddressError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# --- работа с секцией конфига ----------------------------------------------
def _entries(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    """cfg['ip']['addresses'] + выдача id записям, у которых его ещё нет."""
    ip = cfg.setdefault("ip", {}) or {}
    cfg["ip"] = ip
    entries = ip.get("addresses") or []
    ip["addresses"] = entries
    next_id = max((e.get("id", 0) for e in entries), default=0) + 1
    for e in entries:
        if "id" not in e:
            e["id"] = next_id
            next_id += 1
    return entries


def _find(entries: list[dict[str, Any]], addr_id: int) -> dict[str, Any]:
    for e in entries:
        if e["id"] == addr_id:
            return e
    raise AddressError(404, f"адрес с id={addr_id} не найден")


def _active(e: dict[str, Any]) -> bool:
    return not e.get("disabled", False)


def _check_interface(name: str) -> None:
    if name not in netlink.link_names():
        raise AddressError(400, f"интерфейс '{name}' не существует")


def _check_duplicate(entries, address: str, interface: str, skip_id: int | None = None) -> None:
    for e in entries:
        if e["id"] != skip_id and e["address"] == address and e["interface"] == interface:
            raise AddressError(409, f"{address} уже назначен на {interface} (id={e['id']})")


def _kernel(op, interface: str, address: str) -> None:
    try:
        op(interface, address)
    except netlink.NetlinkOpError as e:
        raise AddressError(500, str(e)) from e


def _to_model(e: dict[str, Any], invalid: bool) -> Address:
    return Address(
        id=e["id"],
        address=e["address"],
        network=str(ipaddress.ip_interface(e["address"]).network.network_address),
        interface=e["interface"],
        comment=e.get("comment"),
        disabled=e.get("disabled", False),
        invalid=invalid,
    )


# --- публичные операции -----------------------------------------------------
def list_addresses() -> list[Address]:
    entries = _entries(store.load())
    links = netlink.link_names()
    kernel = set(netlink.kernel_ipv4_addresses())

    result: list[Address] = []
    configured = set()
    for e in entries:
        key = (e["interface"], e["address"])
        configured.add(key)
        invalid = e["interface"] not in links or (_active(e) and key not in kernel)
        result.append(_to_model(e, invalid))

    # Динамические: есть в ядре, но не в конфиге (Docker, DHCP-клиент и т.п.) — флаг D
    for ifname, cidr in sorted(kernel - configured):
        if ifname in HIDDEN_INTERFACES:
            continue
        result.append(Address(
            id=None, address=cidr, interface=ifname, dynamic=True,
            network=str(ipaddress.ip_interface(cidr).network.network_address),
        ))
    return result


def add_address(data: AddressCreate) -> Address:
    _check_interface(data.interface)
    with store.transaction() as cfg:
        entries = _entries(cfg)
        _check_duplicate(entries, data.address, data.interface)
        entry: dict[str, Any] = {
            "id": max((e["id"] for e in entries), default=0) + 1,
            "address": data.address,
            "interface": data.interface,
        }
        if data.comment:
            entry["comment"] = data.comment
        if data.disabled:
            entry["disabled"] = True
        if _active(entry):
            _kernel(netlink.addr_add, data.interface, data.address)
        entries.append(entry)
    return _to_model(entry, invalid=False)


def update_address(addr_id: int, data: AddressUpdate) -> Address:
    with store.transaction() as cfg:
        entries = _entries(cfg)
        entry = _find(entries, addr_id)
        old = dict(entry)

        changes = data.model_dump(exclude_unset=True)
        new = {**entry, **{k: v for k, v in changes.items() if v is not None or k == "comment"}}
        if not new.get("comment"):
            new.pop("comment", None)
        if not new.get("disabled"):
            new.pop("disabled", None)

        if new["interface"] != old["interface"]:
            _check_interface(new["interface"])
        _check_duplicate(entries, new["address"], new["interface"], skip_id=addr_id)

        changed_kernel = (old["address"], old["interface"], _active(old)) != \
                         (new["address"], new["interface"], _active(new))
        if changed_kernel:
            if _active(old):
                _kernel(netlink.addr_del, old["interface"], old["address"])
            if _active(new):
                try:
                    _kernel(netlink.addr_add, new["interface"], new["address"])
                except AddressError:
                    if _active(old):  # вернуть как было
                        _kernel(netlink.addr_add, old["interface"], old["address"])
                    raise

        entry.clear()
        entry.update(new)
    return _to_model(entry, invalid=False)


def remove_address(addr_id: int) -> None:
    with store.transaction() as cfg:
        entries = _entries(cfg)
        entry = _find(entries, addr_id)
        if _active(entry):
            _kernel(netlink.addr_del, entry["interface"], entry["address"])
        entries.remove(entry)


def apply_all(wait_seconds: int = 10) -> None:
    """При старте: применить все включённые адреса из конфига.

    В GNS3 интерфейсы eth1..N могут появиться через мгновение после старта —
    ждём их до wait_seconds. Адреса, которых нет в конфиге, НЕ удаляем
    (адрес Docker/управления/DHCP — это «динамические» адреса).
    """
    with store.transaction() as cfg:   # заодно сохраняет id, если их не было
        entries = [e for e in _entries(cfg) if _active(e)]

    needed = {e["interface"] for e in entries}
    deadline = time.monotonic() + wait_seconds
    while needed - netlink.link_names() and time.monotonic() < deadline:
        time.sleep(0.5)

    links = netlink.link_names()
    for e in entries:
        if e["interface"] not in links:
            print(f"[agent] WARNING: {e['address']}: интерфейса {e['interface']} нет — пропущено")
            continue
        try:
            netlink.addr_add(e["interface"], e["address"])
            print(f"[agent] address {e['address']} -> {e['interface']}")
        except netlink.NetlinkOpError as err:
            print(f"[agent] ERROR: {err}")
