"""
Тесты Firewall: модели, генерация nft, защита от самоблокировки, проброс портов,
изменение с откатом, счётчики. nft подменяется (синтаксис проверяется отдельно, если nft есть).
"""
import json
import shutil
import subprocess

import pytest
import yaml

from app.core.store import ConfigStore
from app.models.firewall import FirewallRule, PortForward
from app.services import firewall, firewall_rules, lan, vpn, wan


@pytest.fixture
def env(tmp_path, monkeypatch):
    cfg = tmp_path / "router.yaml"
    cfg.write_text(yaml.safe_dump({"wan": {"interface": "eth1", "mode": "none"},
                                   "lan": {"enabled": True, "address": "192.168.88.1/24"}}))
    store = ConfigStore(str(cfg), str(tmp_path / "data"))
    (tmp_path / "data").mkdir()
    for mod in (firewall_rules, lan, vpn, wan):
        monkeypatch.setattr(mod, "store", store)
    monkeypatch.setattr(lan, "load_state", lambda: {"address": "192.168.88.1/24"})
    monkeypatch.setattr(lan, "wan_interface", lambda: "eth1")
    monkeypatch.setattr(vpn, "load_state", lambda: {})
    applied = []
    monkeypatch.setattr(firewall, "apply_text", lambda text: applied.append(text))
    monkeypatch.setattr(firewall, "counters", lambda: {"rule:1": (42, 4200), "fwd:1": (3, 180)})
    monkeypatch.setattr(firewall, "is_active", lambda: True)
    return store, applied


def test_models():
    r = FirewallRule(chain="input", src="203.0.113.7", protocol="tcp", dst_ports="22,443, 8000-8100")
    assert r.src == "203.0.113.7/32" and r.dst_ports == "22, 443, 8000-8100"
    assert FirewallRule(chain="input", src="0.0.0.0/0").src is None          # 0.0.0.0/0 = любой
    assert FirewallRule(chain="input", dst="10.0.0.0/8", out_zone="lan").dst is None   # input: назначение — роутер
    for bad in (dict(protocol="icmp", dst_ports="22"), dict(protocol="tcp", dst_ports="70000"),
                dict(protocol="tcp", dst_ports="2000-1000"), dict(src="300.1.1.1"), dict(description='a"b')):
        with pytest.raises(ValueError):
            FirewallRule(chain="forward", **bad)
    with pytest.raises(ValueError, match="диапазона"):
        PortForward(wan_port="5060-5070", to_ip="192.168.88.20", to_port=5060)


def test_render_rules():
    ifaces = {"wan": "eth1", "lan": "br-lan", "vpn": None}
    line = firewall.render_rule(FirewallRule(chain="forward", in_zone="lan", out_zone="wan", src="192.168.88.50",
                                             action="drop"), 3, ifaces)
    assert line.strip() == 'iifname "br-lan" oifname "eth1" ip saddr 192.168.88.50/32 counter drop comment "rule:3"'
    tcp = firewall.render_rule(FirewallRule(chain="input", in_zone="wan", protocol="tcp", dst_ports="80, 443"), 1, ifaces)
    assert "tcp dport { 80, 443 } counter accept" in tcp
    skipped = firewall.render_rule(FirewallRule(chain="input", in_zone="vpn"), 2, ifaces)
    assert skipped.strip().startswith("# rule:2 пропущено")
    pf = firewall.render_forward(PortForward(protocol="tcp+udp", wan_port="5060-5070", to_ip="192.168.88.21"), 1, "eth1")
    assert "meta l4proto { tcp, udp } th dport 5060-5070 counter dnat ip to 192.168.88.21" in pf


def test_user_rules_before_system(env):
    _, applied = env
    firewall_rules.add_rule(FirewallRule(chain="forward", in_zone="lan", src="192.168.88.50", action="drop"))
    text = applied[-1]
    assert text.index('comment "rule:1"') < text.index('iifname "br-lan" oifname "eth1" accept')


def test_lockout_protection(env):
    with pytest.raises(firewall_rules.RuleError, match="закроет доступ"):
        firewall_rules.add_rule(FirewallRule(chain="input", in_zone="lan", action="drop"))
    with pytest.raises(firewall_rules.RuleError):
        firewall_rules.add_rule(FirewallRule(chain="input", in_zone="any", protocol="tcp",
                                             dst_ports="8000-9000", action="reject"))
    # точечные запреты можно
    firewall_rules.add_rule(FirewallRule(chain="input", in_zone="lan", src="192.168.88.50", action="drop"))
    firewall_rules.add_rule(FirewallRule(chain="input", in_zone="lan", protocol="tcp", dst_ports="22", action="drop"))


def test_crud_move_and_rollback(env, monkeypatch):
    store, applied = env
    for d in ("a", "b", "c"):
        firewall_rules.add_rule(FirewallRule(chain="input", in_zone="wan", protocol="tcp",
                                             dst_ports="22", description=d))
    firewall_rules.add_rule(FirewallRule(chain="forward", description="f"))
    firewall_rules.move_rule(3, "up")
    assert [r.description for _, r in firewall_rules.rules()] == ["a", "c", "b", "f"]
    firewall_rules.move_rule(1, "up")                                  # первый — некуда
    assert [i for i, _ in firewall_rules.rules()] == [1, 3, 2, 4]
    firewall_rules.update_rule(2, FirewallRule(chain="input", description="b2", enabled=False))
    firewall_rules.delete_rule(1)
    assert [r.description for _, r in firewall_rules.rules()] == ["c", "b2", "f"]

    def broken(text):
        raise firewall.FirewallError("nft: Error: syntax error")
    monkeypatch.setattr(firewall, "apply_text", broken)
    with pytest.raises(firewall_rules.RuleError, match="syntax"):
        firewall_rules.add_rule(FirewallRule(chain="input", description="bad"))
    assert len(firewall_rules.rules()) == 3                          # откат конфига
    with pytest.raises(firewall_rules.RuleError):
        firewall_rules.delete_rule(99)


def test_port_forward_checks(env):
    _, applied = env
    firewall_rules.add_forward(PortForward(wan_port="8080", to_ip="192.168.88.20", to_port=80))
    assert 'dnat ip to 192.168.88.20:80 comment "fwd:1"' in applied[-1]
    assert "ct status dnat accept" in applied[-1]
    cases = [
        (PortForward(wan_port="8000", to_ip="192.168.88.20"), "управлением"),     # порт веб-интерфейса
        (PortForward(wan_port="8070-8090", to_ip="192.168.88.30"), "уже пробрасывается"),
        (PortForward(wan_port="9000", to_ip="10.0.0.5"), "не в сети LAN"),
        (PortForward(wan_port="9000", to_ip="192.168.88.1"), "самого роутера"),
    ]
    for fwd, msg in cases:
        with pytest.raises(firewall_rules.RuleError, match=msg):
            firewall_rules.add_forward(fwd)
    firewall_rules.add_forward(PortForward(protocol="udp", wan_port="8080", to_ip="192.168.88.20"))  # UDP — можно
    firewall_rules.update_forward(1, PortForward(wan_port="8081", to_ip="192.168.88.20"))
    firewall_rules.delete_forward(2)
    assert [f.wan_port for _, f in firewall_rules.forwards()] == ["8081"]


def test_status_and_preview(env):
    firewall_rules.add_rule(FirewallRule(chain="input", in_zone="wan", protocol="icmp", description="ping"))
    firewall_rules.add_forward(PortForward(wan_port="8080", to_ip="192.168.88.20"))
    st = firewall_rules.status()
    assert st.rules[0].packets == 42 and st.forwards[0].bytes == 180
    assert st.zones == {"wan": "eth1", "lan": "br-lan", "vpn": None}
    assert any("LAN → WAN — разрешено" in x for x in st.system["forward"])
    text = firewall_rules.preview()
    assert 'comment "rule:1"' in text and 'comment "fwd:1"' in text


def test_counters_parse(monkeypatch):
    sample = {"nftables": [{"metainfo": {}}, {"rule": {"comment": "rule:7", "expr": [
        {"match": {}}, {"counter": {"packets": 5, "bytes": 300}}, {"accept": None}]}},
        {"rule": {"expr": [{"counter": {"packets": 1, "bytes": 1}}]}}]}
    monkeypatch.setattr(firewall, "_nft", lambda args, stdin=None: subprocess.CompletedProcess(
        args, 0, stdout=json.dumps(sample), stderr=""))
    assert firewall.counters() == {"rule:7": (5, 300)}


@pytest.mark.skipif(not shutil.which("nft"), reason="нет nft")
def test_generated_ruleset_is_valid_nft(tmp_path):
    rules = [(1, FirewallRule(chain="input", in_zone="wan", src="203.0.113.0/24", protocol="tcp", dst_ports="22")),
             (2, FirewallRule(chain="forward", in_zone="vpn", out_zone="lan", dst="192.168.88.20",
                              protocol="tcp", dst_ports="80, 443, 5060-5070")),
             (3, FirewallRule(chain="forward", in_zone="lan", protocol="udp", src_ports="1024-65535",
                              dst_ports="53", action="reject"))]
    fwds = [(1, PortForward(wan_port="8080", to_ip="192.168.88.20", to_port=80)),
            (2, PortForward(protocol="tcp+udp", wan_port="5060-5070", to_ip="192.168.88.21", src="198.51.100.0/24"))]
    for vpn_rules in (None, firewall.VpnRules("wg0", False, True, True)):
        f = tmp_path / "rs.nft"
        f.write_text(firewall.ruleset("eth1", "br-lan", True, vpn_rules, rules, fwds))
        r = subprocess.run(["nft", "-c", "-f", str(f)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
