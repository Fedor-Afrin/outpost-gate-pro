"""
Раздел Firewall.

  GET    /api/firewall                       правила, пробросы, счётчики, системные правила
  GET    /api/firewall/ruleset               итоговый nftables (текстом)
  POST   /api/firewall/rules                 добавить правило
  PUT    /api/firewall/rules/{id}            изменить
  DELETE /api/firewall/rules/{id}            удалить
  POST   /api/firewall/rules/{id}/move       {"direction": "up" | "down"} — приоритет
  POST   /api/firewall/forwards              проброс порта WAN -> LAN
  PUT    /api/firewall/forwards/{id}
  DELETE /api/firewall/forwards/{id}
Любое изменение применяется сразу и атомарно; если nft отказал — всё возвращается как было.
"""
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.models.firewall import FirewallRule, FirewallStatus, PortForward
from app.services import firewall_rules as svc

router = APIRouter()


class Move(BaseModel):
    direction: Literal["up", "down"]


class Ruleset(BaseModel):
    text: str


def _do(fn, *args) -> FirewallStatus:
    try:
        fn(*args)
    except svc.RuleError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    return svc.status()


@router.get("", response_model=FirewallStatus)
def get_firewall():
    return svc.status()


@router.get("/ruleset", response_model=Ruleset)
def get_ruleset():
    return Ruleset(text=svc.preview())


@router.post("/rules", response_model=FirewallStatus, status_code=201)
def add_rule(rule: FirewallRule):
    return _do(svc.add_rule, rule)


@router.put("/rules/{rid}", response_model=FirewallStatus)
def update_rule(rid: int, rule: FirewallRule):
    return _do(svc.update_rule, rid, rule)


@router.delete("/rules/{rid}", response_model=FirewallStatus)
def delete_rule(rid: int):
    return _do(svc.delete_rule, rid)


@router.post("/rules/{rid}/move", response_model=FirewallStatus)
def move_rule(rid: int, body: Move):
    return _do(svc.move_rule, rid, body.direction)


@router.post("/forwards", response_model=FirewallStatus, status_code=201)
def add_forward(fwd: PortForward):
    return _do(svc.add_forward, fwd)


@router.put("/forwards/{fid}", response_model=FirewallStatus)
def update_forward(fid: int, fwd: PortForward):
    return _do(svc.update_forward, fid, fwd)


@router.delete("/forwards/{fid}", response_model=FirewallStatus)
def delete_forward(fid: int):
    return _do(svc.delete_forward, fid)
