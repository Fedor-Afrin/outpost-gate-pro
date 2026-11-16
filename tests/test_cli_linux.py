"""CLI: синтаксис Linux (ip, nmcli …) и переключение синтаксиса."""
import pytest

from app.cli import commands as c
from app.cli import linux, shell
from tests.test_cli import FakeApi


@pytest.fixture
def lx(monkeypatch):
    api = FakeApi()
    api.data.update({
        "/api/ip/routes": [
            {"id": 1, "dst_address": "192.168.20.0/24", "gateway": "172.16.0.2", "distance": 1},
            {"id": None, "dst_address": "0.0.0.0/0", "gateway": "10.0.0.138", "distance": 1, "dynamic": True}],
        "/api/wan": {"config": {"interface": "enp1s0", "mode": "dhcp", "address": None, "gateway": None, "dns": []},
                     "interface": "enp1s0", "addresses": ["10.0.0.6/24"], "gateway": "10.0.0.138",
                     "dns": ["10.0.0.138"], "multi": False},
        "/api/lan/segments": [
            {"config": {"id": "lan1", "name": "LAN", "enabled": True, "address": "192.168.1.1/24", "dhcp_enabled": True,
                        "domain": "office.lan"}, "bridge": "br-lan", "active": True, "ports": ["enp7s0"]},
            {"config": {"id": "lan2", "name": "Guests", "enabled": True, "address": "192.168.2.1/24",
                        "dhcp_enabled": True}, "bridge": "br-lan2", "active": True, "ports": ["enp8s0"]}],
        "/api/vpn": {"enabled": "amneziawg"},
        "/api/vpn/amneziawg": {"config": {"enabled": True, "addresses": ["10.8.1.2/32"]}},
        "/api/gre": {"config": {"tunnels": [{"name": "gre1", "enabled": True, "remote": "10.8.1.3",
                                             "address": "172.16.0.1/30", "routes": []}]},
                     "tunnels": [{"name": "gre1", "exists": True}]},
        "/api/interfaces": [{"name": "enp1s0", "running": True}, {"name": "br-lan", "running": True},
                            {"name": "awg0", "running": True}, {"name": "gre1", "state": "up", "running": False},
                            {"name": "veth123", "running": True}, {"name": "lo", "running": True}],
    })
    out, runs = [], []
    monkeypatch.setattr(linux, "_run", lambda cmd: runs.append(cmd) or "OUT")
    monkeypatch.setattr(linux, "_run_live", lambda ctx, cmd: runs.append(cmd))
    return c.Ctx(api=api, out=out.append), out, runs


def puts(cx, method="PUT"):
    return [x for x in cx.api.calls if x[0] == method]


def test_ip_show_passthrough(lx):
    cx, out, runs = lx
    for line, cmd in (("ip a", ["ip", "address"]), ("ip -br a", ["ip", "-br", "address"]),
                      ("ip addr show dev br-lan", ["ip", "address", "show", "dev", "br-lan"]),
                      ("ip r", ["ip", "route"]), ("ip route get 8.8.8.8", ["ip", "route", "get", "8.8.8.8"]),
                      ("ip -s link", ["ip", "-s", "link"]), ("ip neigh", ["ip", "neigh"]),
                      ("bridge link", ["bridge", "link"]), ("ss -tlnp", ["ss", "-tlnp"])):
        linux.execute(cx, line)
        assert runs[-1] == cmd, line
    assert out[-1] == "OUT"
    for bad in ("ip -batch x", "ip -n other a", "ip netns exec x bash", "ip link set enp1s0 down",
                "ip neigh flush all", "bridge fdb add 00:11 dev x", "ip a; rm -rf /", "ss --kill", "rm -rf /"):
        with pytest.raises(c.CliError):
            linux.execute(cx, bad)


def test_ip_changes_go_to_config(lx):
    cx, out, runs = lx
    linux.execute(cx, "ip route add 192.168.30.0/24 via 172.16.0.2 metric 10")
    assert puts(cx, "POST")[-1] == ("POST", "/api/ip/routes", {"dst_address": "192.168.30.0/24",
                                    "gateway": "172.16.0.2", "comment": "ip route add", "distance": 10})
    linux.execute(cx, "ip route add default dev gre1")
    assert puts(cx, "POST")[-1][2]["dst_address"] == "0.0.0.0/0" and puts(cx, "POST")[-1][2]["gateway"] == "gre1"
    linux.execute(cx, "ip route del 192.168.20.0/24")
    assert puts(cx, "DELETE")[-1] == ("DELETE", "/api/ip/routes/1", None)
    with pytest.raises(c.CliError, match="dynamic"):
        linux.execute(cx, "ip route del default")
    linux.execute(cx, "ip addr add 10.10.0.1/24 dev br-lan")
    assert puts(cx, "POST")[-1][2] == {"address": "10.10.0.1/24", "interface": "br-lan", "comment": "ip addr add"}
    linux.execute(cx, "ip addr del 192.168.88.1/24 dev br-lan")
    assert puts(cx, "DELETE")[-1] == ("DELETE", "/api/ip/addresses/1", None)
    with pytest.raises(c.CliError, match="comes from a segment"):
        linux.execute(cx, "ip addr del 172.18.0.2/16 dev eth0")
    with pytest.raises(c.CliError, match="mask"):
        linux.execute(cx, "ip addr add 10.10.0.1 dev br-lan")
    assert not any(r[:3] == ["ip", "route", "add"] for r in runs)           # в ядро напрямую — никогда


def test_nmcli_show(lx):
    cx, out, _ = lx
    linux.execute(cx, "nmcli c")
    text = "\n".join(out)
    assert out[0].split() == ["NAME", "TYPE", "DEVICE", "STATE"]
    assert "wan" in text and "lan2" in text and "amneziawg" in text and "gre1" in text
    assert any(l.split()[:4] == ["amneziawg", "wireguard", "--", "activated"] for l in out)
    out.clear()
    linux.execute(cx, "nmcli d")
    devs = [l.split()[0] for l in out[1:]]
    assert devs == ["enp1s0", "br-lan", "awg0", "gre1"]                     # без veth и lo
    assert any(l.startswith("br-lan") and "lan1" in l for l in out)
    out.clear()
    linux.execute(cx, "nmcli c show wan")
    assert "ipv4.method:                  auto" in out and "IP4.GATEWAY:                  10.0.0.138" in out
    out.clear()
    linux.execute(cx, "nmcli c show Guests")
    assert "ipv4.addresses:               192.168.2.1/24" in out
    out.clear()
    linux.execute(cx, "nmcli")
    assert out[1].split()[:2] == ["connected", "full"]
    with pytest.raises(c.CliError, match="unknown connection"):
        linux.execute(cx, "nmcli c show nothing")


def test_nmcli_modify_and_updown(lx):
    cx, out, _ = lx
    linux.execute(cx, 'nmcli c mod wan ipv4.method manual ipv4.addresses 203.0.113.10/24 '
                      'ipv4.gateway 203.0.113.1 ipv4.dns "1.1.1.1 8.8.8.8"')
    p = puts(cx)[-1]
    assert p[1] == "/api/wan" and p[2]["mode"] == "static" and p[2]["address"] == "203.0.113.10/24"
    assert p[2]["gateway"] == "203.0.113.1" and p[2]["dns"] == ["1.1.1.1", "8.8.8.8"]
    assert out[-1] == "Connection 'wan' successfully updated."
    linux.execute(cx, "nmcli c mod lan1 ipv4.addresses 192.168.5.1/24")
    assert puts(cx)[-1][1] == "/api/lan" and puts(cx)[-1][2]["address"] == "192.168.5.1/24"
    linux.execute(cx, "nmcli c mod lan2 ipv4.method manual")
    assert puts(cx)[-1][1] == "/api/lan/segments/lan2" and puts(cx)[-1][2]["dhcp_enabled"] is False
    linux.execute(cx, "nmcli c down lan2")
    assert puts(cx)[-1][2]["enabled"] is False
    linux.execute(cx, "nmcli c up amneziawg")
    assert puts(cx)[-1] == ("PUT", "/api/vpn/amneziawg", {"enabled": True, "addresses": ["10.8.1.2/32"]})
    linux.execute(cx, "nmcli c mod gre1 ipv4.routes 192.168.20.0/24,192.168.21.0/24")
    assert puts(cx)[-1][2]["tunnels"][0]["routes"] == ["192.168.20.0/24", "192.168.21.0/24"]
    with pytest.raises(c.CliError, match="main WAN"):
        linux.execute(cx, "nmcli c down wan")
    with pytest.raises(c.CliError, match="ipv4.method"):
        linux.execute(cx, "nmcli c mod wan ipv4.method shared")


def test_ping_names_and_flags(lx, monkeypatch):
    from app.services import tools
    cx, out, runs = lx
    monkeypatch.setattr(tools, "resolve_sync", lambda h, f=None: ("192.168.1.1", "DNS роутера: samba.office.lan"))
    linux.execute(cx, "ping samba")
    assert runs[-1] == ["ping", "-c", "4", "192.168.1.1"] and out[-1].startswith("samba -> 192.168.1.1")
    linux.execute(cx, "ping -c 2 -I br-lan samba")
    assert runs[-1] == ["ping", "-c", "2", "-I", "br-lan", "192.168.1.1"]
    for bad in ("ping -f samba", "ping -i 0.01 samba", "ping", "traceroute -z x"):
        with pytest.raises(c.CliError):
            linux.execute(cx, bad)


def test_syntax_switch_and_one_shot(lx, monkeypatch):
    cx, out, runs = lx
    cx.api.data["/api/auth/cli"] = {"syntax": "linux"}
    assert shell.get_syntax(cx.api) == "linux"
    shell.run_line(cx, "ip -br a", [], "linux")
    assert runs[-1] == ["ip", "-br", "address"]
    assert shell.run_line(cx, "/ip address", [], "linux") == ["ip", "address"]   # «/…» — RouterOS и здесь
    assert shell.run_line(cx, "/ip address", [], "routeros") == ["ip", "address"]
    monkeypatch.setenv("OG_SYNTAX", "routeros")                                 # Ansible: admin+cet1024w
    assert shell.get_syntax(cx.api) == "routeros"
    shell.save_syntax(cx.api, "linux")
    assert not puts(cx)                                                         # выбор пользователя не трогаем
    monkeypatch.delenv("OG_SYNTAX")
    shell.save_syntax(cx.api, "linux")
    assert puts(cx)[-1] == ("PUT", "/api/auth/cli", {"syntax": "linux"})
    with pytest.raises(c.Quit):
        linux.execute(cx, "exit")


def test_without_paging_ignored(lx):
    cx, out, _ = lx
    c.execute(cx, "/ip address print without-paging", [])
    assert any("192.168.88.1/24" in l for l in out)


def test_cli_prefs(tmp_path, monkeypatch):
    from app.services import cli_prefs
    monkeypatch.setattr(cli_prefs, "_path", lambda: tmp_path / "cli-prefs.json")
    assert cli_prefs.get("admin") == {"syntax": None, "lang": "en"}
    assert cli_prefs.set_syntax("admin", "linux") == {"syntax": "linux", "lang": "en"}
    assert cli_prefs.update("admin", lang="he") == {"syntax": "linux", "lang": "he"}
    assert cli_prefs.get("ivan") == {"syntax": None, "lang": "en"}
    with pytest.raises(ValueError):
        cli_prefs.set_syntax("admin", "cisco")
    with pytest.raises(ValueError):
        cli_prefs.update("admin", lang="de")


def test_translation_and_language_switch(lx):
    from app.cli import term
    cx, out, _ = lx
    with pytest.raises(c.CliError) as e:
        linux.execute(cx, "ip route del 10.99.0.0/16")
    en = str(e.value)
    assert en == "route 10.99.0.0/16 is not in the configuration"
    assert term.tr("ru", en) == "маршрута 10.99.0.0/16 нет в конфигурации"
    assert term.tr("he", en) == "הנתיב 10.99.0.0/16 לא בתצורה"
    assert term.tr("ru", "что-то неизвестное") == "что-то неизвестное"          # нет шаблона — как есть
    assert linux.switch_language(cx, "sl2", None) == "ru" and cx.lang == "ru"
    assert out[-1].startswith("Язык: Русский")
    linux.execute(cx, "nmcli c down lan2")
    assert out[-1] == "Соединение 'lan2' выключено."
    assert linux.switch_language(cx, "sl", "he") == "he" and linux.switch_language(cx, "sl.en", None) == "en"
    assert linux.switch_language(cx, "sl", None) is None and out[-1].startswith("Language: English")
    with pytest.raises(c.CliError):
        linux.switch_language(cx, "sl", "de")
    for lang in ("en", "ru", "he"):                                        # help на трёх языках, первая строка — язык
        cx.lang = lang
        out.clear()
        linux.execute(cx, "help")
        assert "sl1 English" in out[0] and len(out) > 15
    # каждый шаблон каталога переводится и не теряет подстановок
    for en_tpl, (ru, he) in term.CATALOG.items():
        names = sorted(__import__("re").findall(r"\{(\w+)\}", en_tpl))
        assert sorted(__import__("re").findall(r"\{(\w+)\}", ru)) == names, en_tpl
        assert sorted(__import__("re").findall(r"\{(\w+)\}", he)) == names, en_tpl


def test_shell_sl_regex():
    for line, ok in (("sl1", True), ("sl3", True), ("sl ru", True), ("SL2", True), ("sl.he", True),
                     ("switch-language en", True), ("sl", True), ("slx", False), ("ss -tlnp", False)):
        assert bool(shell.SL_RE.match(line)) is ok, line


def test_colors(lx):
    from app.cli import term
    cx, out, runs = lx
    cx.color = True
    linux.execute(cx, "ip -br a")
    assert runs[-1] == ["ip", "-color=always", "-br", "address"]
    linux.execute(cx, "ip -j a")
    assert runs[-1] == ["ip", "-j", "address"]                           # JSON — без цветов
    out.clear()
    linux.execute(cx, "nmcli c")
    assert out[0].startswith("\x1b[1m") and any("\x1b[32mamneziawg" in l for l in out)    # активное — зелёным
    out.clear()
    linux.execute(cx, "nmcli d")
    assert any("\x1b[32mconnected" in l for l in out)
    assert term.prompt(True, "admin", "office") == "\x1b[01;32madmin@office\x1b[00m:\x1b[01;34m~\x1b[00m$ "
    assert term.prompt(False, "admin", "office") == "admin@office:~$ "
    cx.color = False
    out.clear()
    linux.execute(cx, "nmcli c")
    assert not any("\x1b" in l for l in out)                           # Ansible / скрипты — чистый текст
    assert "\x1b" not in term.banner(False, "ru") and "OutpostGate" in term.banner(True, "he")
