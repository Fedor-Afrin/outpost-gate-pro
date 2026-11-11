"""
Правила пользователя и проброс портов: хранение в router.yaml и изменение.

  firewall:
    rules:     [{id, chain, action, in-zone, out-zone, src, dst, protocol, src-ports, dst-ports, ...}]
    forwards:  [{id, protocol, wan-port, to-ip, to-port, src, ...}]

Порядок rules = приоритет (сверху вниз, первое совпавшее решает).
Любое изменение: записать -> собрать ruleset -> nft -f. Если nft отказал — вернуть как было.
"""
from __future__ import annotations

import copy
import ipaddress
import threading

from app.core.store import store
from app.models.firewall import (FirewallRule, FirewallRuleView, FirewallStatus, PortForward,
                                 PortForwardView, ports_cover)
from app.services import firewall

_lock = threading.RLock()

# ключи YAML (как в RouterOS — через дефис) <-> поля моделей
_RULE_KEYS = {"in_zone": "in-zone", "out_zone": "out-zone", "src_ports": "src-ports", "dst_ports": "dst-ports"}
_FWD_KEYS = {"wan_port": "wan-port", "to_ip": "to-ip", "to_port": "to-port"}


class RuleError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _to_yaml(model, rid: int, keys: dict) -> dict:
    data = {"id": rid}
    for k, v in model.model_dump().items():
        if v is not None:
            data[keys.get(k, k)] = v
    return data


def _from_yaml(d: dict, keys: dict) -> dict:
    back = {v: k for k, v in keys.items()}
    return {back.get(k, k): v for k, v in d.items() if k != "id"}


def _section(data: dict, name: str) -> list[dict]:
    """Список внутри data['firewall'] — всегда один и тот же объект (пустой список не подменяется)."""
    if not isinstance(data.get("firewall"), dict):
        data["firewall"] = {}
    if not isinstance(data["firewall"].get(name), list):
        data["firewall"][name] = []
    return data["firewall"][name]


def rules() -> list[tuple[int, FirewallRule]]:
    items = (store.load().get("firewall") or {}).get("rules") or []
    return [(d["id"], FirewallRule(**_from_yaml(d, _RULE_KEYS))) for d in items]


def forwards() -> list[tuple[int, PortForward]]:
    items = (store.load().get("firewall") or {}).get("forwards") or []
    return [(d["id"], PortForward(**_from_yaml(d, _FWD_KEYS))) for d in items]


# --- проверки ------------------------------------------------------------------------------
def _check_rule(rule: FirewallRule) -> None:
    """Защита от самоблокировки: не дать закрыть себе доступ к роутеру из LAN."""
    api_port = max(firewall.management_ports())
    if (rule.chain == "input" and rule.enabled and rule.action != "accept"
            and rule.in_zone in ("lan", "any") and not rule.src
            and rule.protocol in ("all", "tcp") and ports_cover(rule.dst_ports, api_port)):
        raise RuleError(400, f"это правило закроет доступ к веб-интерфейсу (порт {api_port}) из LAN. "
                             f"Укажите источник или порты точнее")


def _port_range(ports: str) -> tuple[int, int]:
    nums = [int(x) for x in ports.split("-")]
    return nums[0], nums[-1]


def _check_forward(fwd: PortForward, others: list[tuple[int, PortForward]]) -> None:
    from app.services import lan
    cfg = lan.get_config()
    net = ipaddress.ip_interface(cfg.address).network
    if ipaddress.ip_address(fwd.to_ip) not in net:
        raise RuleError(400, f"{fwd.to_ip} не в сети LAN {net}")
    if ipaddress.ip_address(fwd.to_ip) == ipaddress.ip_interface(cfg.address).ip:
        raise RuleError(400, "это адрес самого роутера — для доступа к роутеру нужно правило «Входящие»")
    lo, hi = _port_range(fwd.wan_port)
    if fwd.protocol != "udp" and cfg.wan_management:
        for p in firewall.management_ports():
            if lo <= p <= hi:
                raise RuleError(409, f"порт {p} на WAN занят управлением роутером")
    protos = {"tcp", "udp"} if fwd.protocol == "tcp+udp" else {fwd.protocol}
    for fid, o in others:
        o_protos = {"tcp", "udp"} if o.protocol == "tcp+udp" else {o.protocol}
        o_lo, o_hi = _port_range(o.wan_port)
        if protos & o_protos and lo <= o_hi and o_lo <= hi:
            raise RuleError(409, f"порт {fwd.wan_port} уже пробрасывается (правило #{fid})")


# --- изменение с применением и откатом -----------------------------------------------------------
def _commit(mutate) -> None:
    """mutate(data) меняет router.yaml; затем — применить. nft отказал -> вернуть прежнее."""
    with _lock:
        before = copy.deepcopy(store.load().get("firewall") or {})
        with store.transaction() as data:
            mutate(data)
        try:
            firewall.refresh()
        except firewall.FirewallError as e:
            with store.transaction() as data:
                data["firewall"] = before
            try:
                firewall.refresh()
            except firewall.FirewallError:
                pass
            raise RuleError(400, str(e)) from e


def _next_id(items: list[dict]) -> int:
    return max((d["id"] for d in items), default=0) + 1


def _find(items: list[dict], rid: int, what: str) -> int:
    for i, d in enumerate(items):
        if d["id"] == rid:
            return i
    raise RuleError(404, f"{what} #{rid} не найдено")


def add_rule(rule: FirewallRule) -> None:
    _check_rule(rule)
    _commit(lambda data: _section(data, "rules").append(_to_yaml(rule, _next_id(_section(data, "rules")), _RULE_KEYS)))


def update_rule(rid: int, rule: FirewallRule) -> None:
    _check_rule(rule)
    def mutate(data):
        items = _section(data, "rules")
        items[_find(items, rid, "правило")] = _to_yaml(rule, rid, _RULE_KEYS)
    _commit(mutate)


def delete_rule(rid: int) -> None:
    def mutate(data):
        items = _section(data, "rules")
        items.pop(_find(items, rid, "правило"))
    _commit(mutate)


def move_rule(rid: int, direction: str) -> None:
    """Выше / ниже — в пределах своей цепочки (input или forward)."""
    def mutate(data):
        items = _section(data, "rules")
        i = _find(items, rid, "правило")
        chain = items[i]["chain"]
        same = [j for j, d in enumerate(items) if d["chain"] == chain]
        k = same.index(i) + (-1 if direction == "up" else 1)
        if 0 <= k < len(same):
            j = same[k]
            items[i], items[j] = items[j], items[i]
    _commit(mutate)


def add_forward(fwd: PortForward) -> None:
    _check_forward(fwd, forwards())
    _commit(lambda data: _section(data, "forwards").append(
        _to_yaml(fwd, _next_id(_section(data, "forwards")), _FWD_KEYS)))


def update_forward(fid: int, fwd: PortForward) -> None:
    _check_forward(fwd, [(i, f) for i, f in forwards() if i != fid])
    def mutate(data):
        items = _section(data, "forwards")
        items[_find(items, fid, "проброс")] = _to_yaml(fwd, fid, _FWD_KEYS)
    _commit(mutate)


def delete_forward(fid: int) -> None:
    def mutate(data):
        items = _section(data, "forwards")
        items.pop(_find(items, fid, "проброс"))
    _commit(mutate)


# --- статус ---------------------------------------------------------------------------------------
def status() -> FirewallStatus:
    from app.services import lan, vpn
    cfg = lan.get_config()
    wan_if = lan.wan_interface()
    vpn_rules = vpn.firewall_rules()
    c = firewall.counters()
    return FirewallStatus(
        active=firewall.is_active(),
        zones={"wan": wan_if, "lan": lan.BRIDGE if cfg.enabled else None,
               "vpn": vpn_rules.iface if vpn_rules else None},
        rules=[FirewallRuleView(id=rid, **r.model_dump(), packets=c.get(f"rule:{rid}", (0, 0))[0],
                                bytes=c.get(f"rule:{rid}", (0, 0))[1]) for rid, r in rules()],
        forwards=[PortForwardView(id=fid, **f.model_dump(), packets=c.get(f"fwd:{fid}", (0, 0))[0],
                                  bytes=c.get(f"fwd:{fid}", (0, 0))[1]) for fid, f in forwards()],
        system=firewall.system_rules(wan_if, cfg.wan_management, vpn_rules, firewall.routing_rules()),
        management_ports=firewall.management_ports(),
    )


def preview() -> str:
    """Итоговый ruleset, как он будет (или уже) применён."""
    ctx = firewall.context()
    if not ctx:
        return "# Фаервол работает вместе с LAN: включите LAN, чтобы правила применились.\n"
    return firewall.ruleset(*ctx)
