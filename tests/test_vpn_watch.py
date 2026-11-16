"""Сторож VPN (переподключение по handshake) и трафик самого роутера мимо туннеля."""
import time

import pytest

from app.models.l2tp import L2tpConfig
from app.models.wireguard import WgConfig
from app.services import firewall, vpn


@pytest.fixture
def w(monkeypatch):
    state = {"kind": "amneziawg", "iface": "awg0", "active": True, "mode": "full", "dns": ["1.1.1.1"],
             "since": time.time() - 1000}
    cfg = WgConfig(enabled=False, mode="full")
    hs = {"t": int(time.time()) - 30}
    calls = {"apply": 0, "ip": []}
    monkeypatch.setattr(vpn, "enabled_kind", lambda: "amneziawg")
    monkeypatch.setattr(vpn, "get_config", lambda kind: cfg)
    monkeypatch.setattr(vpn, "load_state", lambda: state)
    monkeypatch.setattr(vpn._awg, "running", lambda: True)
    monkeypatch.setattr(vpn, "_tool", lambda kind, *a, **k: f"priv\tpub\t1\t1\nPEER\tpsk\tep\tips\t{hs['t']}\t10\t20\t25")
    monkeypatch.setattr(vpn, "apply_current", lambda: calls.__setitem__("apply", calls["apply"] + 1))
    monkeypatch.setattr(vpn, "sync_bypass", lambda: None)
    monkeypatch.setattr(vpn, "_watch", {"bad_since": None, "last": 0.0, "backoff": 60, "count": 0, "at": None,
                                        "reason": None})
    return state, cfg, hs, calls


def test_watch_reconnects_on_stale_handshake(w, monkeypatch):
    state, cfg, hs, calls = w
    assert vpn.watch() is None and calls["apply"] == 0                    # handshake 30 с назад — жив
    hs["t"] = int(time.time()) - 400                                       # проснулись после сна
    assert "нет handshake с сервером" in vpn.watch() and calls["apply"] == 1
    assert vpn.watch() is None and calls["apply"] == 1                     # пауза между попытками
    vpn._watch["last"] -= 61
    assert vpn.watch() and calls["apply"] == 2 and vpn._watch["backoff"] == 120   # потом реже: 2, 4 … 10 мин
    hs["t"] = int(time.time()) - 5                                         # связь вернулась
    assert vpn.watch() is None and vpn._watch["backoff"] == 60 and vpn._watch["count"] == 2


def test_watch_other_failures(w, monkeypatch):
    state, cfg, hs, calls = w
    monkeypatch.setattr(vpn._awg, "running", lambda: False)
    assert "amneziawg-go" in vpn.watch()
    monkeypatch.setattr(vpn._awg, "running", lambda: True)
    vpn._watch["last"] = 0
    hs["t"] = 0
    state["since"] = time.time() - 10                                      # только подключились — ждём
    assert vpn.watch() is None
    state["since"] = time.time() - 300
    assert "сервер не ответил" in vpn.watch()
    vpn._watch["last"] = 0
    cfg.reconnect = False                                                  # сторож выключен
    assert vpn.watch() is None


def test_status_shows_reconnects(w, monkeypatch):
    monkeypatch.setattr(vpn.netlink, "link_names", lambda: ["awg0"])
    vpn._watch.update(count=3, at=1700000000.0, reason="нет handshake с сервером 400 с")
    st = vpn._status_wg("amneziawg")
    assert st.reconnects == 3 and st.reconnect_reason.startswith("нет handshake") and st.connected


def test_bypass_rules(monkeypatch):
    cmds = []
    rules = {"990": "", "991": ""}

    def fake_ip(*a, check=False):
        cmds.append(" ".join(a))
        if a[:3] == ("rule", "show", "pref"):
            return rules[a[3]]
        if a[:2] == ("rule", "add"):
            rules[a[3]] = " ".join(a)
        if a[:2] == ("route", "show"):
            return rules.get("tbl", "")
        if a[:2] == ("route", "replace"):
            rules["tbl"] = f"default via {a[4]} dev enp1s0"
        return ""
    monkeypatch.setattr(vpn, "_ip", fake_ip)
    want = {"gateway": "10.0.0.138", "dns": []}
    monkeypatch.setattr(vpn, "bypass_wanted", lambda: want)
    vpn.sync_bypass()
    assert "rule add pref 990 fwmark 0x200/0x200 lookup main suppress_prefixlength 1" in cmds
    assert "rule add pref 991 fwmark 0x200/0x200 lookup 120" in cmds
    assert "route replace default via 10.0.0.138 table 120" in cmds
    cmds.clear()
    vpn.sync_bypass()                                                     # всё на месте — ничего не трогаем
    assert not any(c.startswith(("rule add", "route replace")) for c in cmds)
    want["gateway"] = "10.0.0.1"                                          # шлюз WAN сменился
    vpn.sync_bypass()
    assert "route replace default via 10.0.0.1 table 120" in cmds
    monkeypatch.setattr(vpn, "bypass_wanted", lambda: None)               # туннель выключили / режим split
    cmds.clear()
    vpn.sync_bypass()
    assert "rule del pref 990" in cmds and "rule del pref 991" in cmds and "route flush table 120" in cmds


def test_firewall_router_direct():
    on = firewall.VpnRules(iface="awg0", nat=True, killswitch=True, inbound=False, router_direct=True,
                           tunnel_dns=("1.1.1.1", "1.0.0.1"))
    text = firewall.ruleset("enp1s0", "br-lan", False, on)
    ch = text[text.index("chain output_direct"):]
    assert "type route hook output priority mangle" in ch
    assert ch.index("ct direction reply return") < ch.index("meta mark set meta mark or 0x200")
    assert "meta l4proto { icmp, ipv6-icmp } return" in ch and "ip daddr { 1.1.1.1, 1.0.0.1 } return" in ch
    assert "10.0.0.0/8" in ch and "192.168.0.0/16" in ch
    assert "output_direct" not in firewall.ruleset("enp1s0", "br-lan", False,
                                                   firewall.VpnRules(iface="awg0", nat=True, killswitch=True,
                                                                     inbound=False))
    assert any("напрямую через WAN" in x for x in firewall.system_rules("enp1s0", False, on)["input"])


def test_models_roundtrip():
    c = WgConfig(reconnect=False, router_direct=False)
    back = WgConfig.from_yaml(c.to_yaml())
    assert back.reconnect is False and back.router_direct is False
    assert WgConfig.from_yaml({}).reconnect is True and WgConfig.from_yaml({}).router_direct is True
    l = L2tpConfig.from_yaml(L2tpConfig(reconnect=False, router_direct=False).to_yaml())
    assert l.reconnect is False and l.router_direct is False
