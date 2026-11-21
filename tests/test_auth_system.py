"""
Тесты System: пароли и сессии, права доступа, пользователи, защита от подбора,
резервные копии и снимки, проверка конфигурации, Safe Mode, журнал, ресурсы.
"""
import time

import pytest
import yaml

from app.core import auth
from app.core.config import settings
from app.core.store import ConfigStore
from app.services import system


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "_users_file", lambda: tmp_path / "users.json")
    monkeypatch.setattr(auth, "_secret_file", lambda: tmp_path / "secret.key")
    monkeypatch.setattr(system, "_data", lambda name: tmp_path / name)
    auth._fails.clear()
    return tmp_path


# --- auth -------------------------------------------------------------------------------------------
def test_password_hashing():
    h = auth.hash_password("correct horse")
    assert h.startswith("scrypt$") and "correct" not in h
    assert auth.verify_password("correct horse", h)
    assert not auth.verify_password("wrong", h)
    assert auth.hash_password("correct horse") != h          # соль разная


def test_first_run_admin_without_password(data, monkeypatch):
    monkeypatch.delenv("ROUTER_ADMIN_PASSWORD", raising=False)
    auth.ensure_admin()
    assert auth.list_users() == [{"name": "admin", "role": "full", "must_change": False, "has_password": False}]
    user, token = auth.login("admin", "", "192.168.1.20")            # из LAN — пустой пароль
    assert not user.has_password and not user.must_change
    assert auth.user_from_token(token).name == "admin"
    with pytest.raises(auth.AuthError, match="локальной сети"):
        auth.login("admin", "", "8.8.4.4")                            # из интернета — нельзя
    with pytest.raises(auth.AuthError):
        auth.login("admin", "anything", "192.168.1.20")              # непустой пароль не подходит
    auth.ensure_admin()                                               # второй раз ничего не делает
    assert len(auth.list_users()) == 1


def test_set_first_password(data, monkeypatch):
    monkeypatch.delenv("ROUTER_ADMIN_PASSWORD", raising=False)
    auth.ensure_admin()
    _, old_token = auth.login("admin", "", "127.0.0.1")
    new_token = auth.change_own_password("admin", "", "MyPassword1")
    assert auth.user_from_token(old_token) is None                    # сессия без пароля закрыта
    assert auth.user_from_token(new_token).has_password
    with pytest.raises(auth.AuthError):
        auth.login("admin", "", "127.0.0.1")                          # пустой больше не подходит
    assert auth.login("admin", "MyPassword1", "203.0.113.5")[0].name == "admin"   # с паролем — откуда угодно
    assert oct((data / "users.json").stat().st_mode)[-3:] == "600"


def test_preset_admin_password(data, monkeypatch):
    monkeypatch.setenv("ROUTER_ADMIN_PASSWORD", "MySecret123")
    auth.ensure_admin()
    user, _ = auth.login("admin", "MySecret123", "ip")
    assert not user.must_change


def test_tokens(data):
    auth.add_user("ivan", "password1", "read")
    token = auth.make_token("ivan")
    assert auth.user_from_token(token).role == "read"
    assert auth.user_from_token(token[:-2] + "xx") is None                # подпись испорчена
    assert auth.user_from_token(auth.make_token("ivan", ttl=-1)) is None  # истёк
    assert auth.token_from({}, {"authorization": f"Bearer {token}"}) == token
    auth.update_user("ivan", password="password2")                        # смена пароля
    assert auth.user_from_token(token) is None                            # старые сессии не действуют


def test_change_own_password(data):
    auth.add_user("admin", "password1", "full", must_change=True)
    with pytest.raises(auth.AuthError, match="текущий"):
        auth.change_own_password("admin", "wrong", "password2")
    with pytest.raises(auth.AuthError, match="короче"):
        auth.change_own_password("admin", "password1", "short")
    token = auth.change_own_password("admin", "password1", "password2")
    assert not auth.user_from_token(token).must_change


def test_bruteforce_throttle(data):
    auth.add_user("admin", "password1", "full")
    for _ in range(auth.FAIL_LIMIT):
        with pytest.raises(auth.AuthError):
            auth.login("admin", "bad", "6.6.6.6")
    with pytest.raises(auth.AuthError) as e:
        auth.login("admin", "password1", "6.6.6.6")          # даже верный пароль — пауза
    assert e.value.status == 429
    assert auth.login("admin", "password1", "7.7.7.7")[0].name == "admin"   # другой IP — можно


def test_check_access():
    full, read = auth.User("a", "full"), auth.User("r", "read")
    must = auth.User("n", "full", must_change=True)
    assert auth.check_access("/index.html", "GET", None) is None
    assert auth.check_access("/api/system/health", "GET", None) is None
    assert auth.check_access("/api/wan", "GET", None)[0] == 401
    assert auth.check_access("/api/wan", "PUT", full) is None
    assert auth.check_access("/api/wan", "GET", read) is None
    assert auth.check_access("/api/wan", "PUT", read)[0] == 403
    assert auth.check_access("/api/wan", "GET", must)[0] == 403
    assert auth.check_access("/api/auth/password", "POST", must) is None


def test_user_management(data):
    auth.add_user("admin", "password1", "full")
    auth.add_user("viewer", "password1", "read")
    with pytest.raises(auth.AuthError, match="уже есть"):
        auth.add_user("viewer", "password1", "read")
    with pytest.raises(auth.AuthError, match="имя"):
        auth.add_user("Bad Name", "password1", "read")
    with pytest.raises(auth.AuthError, match="без администратора"):
        auth.update_user("admin", role="read")
    with pytest.raises(auth.AuthError, match="самого себя"):
        auth.delete_user("admin", "admin")
    with pytest.raises(auth.AuthError, match="последнего"):
        auth.delete_user("admin", "viewer")
    auth.delete_user("viewer", "admin")
    assert [u["name"] for u in auth.list_users()] == ["admin"]


# --- конфигурация, бэкапы, снимки -----------------------------------------------------------------------
@pytest.fixture
def cfg(tmp_path, monkeypatch, data):
    path = tmp_path / "router.yaml"
    path.write_text(yaml.safe_dump({"system": {"identity": "home"}, "wan": {"interface": "eth1", "mode": "dhcp"}}))
    st = ConfigStore(str(path), str(tmp_path))
    monkeypatch.setattr(system, "store", st)
    applied = []
    monkeypatch.setattr(system, "reapply", lambda: applied.append(st.load()))
    return st, applied


def test_identity(cfg):
    st, _ = cfg
    assert system.identity() == "home"
    system.set_identity("Офис Ивана")
    assert st.load()["system"]["identity"] == "Офис Ивана"
    with pytest.raises(system.SysError):
        system.set_identity("<script>")


def test_validate_config():
    system.validate_config({"wan": {"mode": "static", "address": "10.0.0.2/24", "gateway": "10.0.0.1"}})
    bad = [
        "строка вместо словаря",
        {"wan": {"mode": "static", "address": "10.0.0.2/24"}},                         # нет шлюза
        {"lan": {"address": "300.1.1.1/24"}},
        {"vpn": {"wireguard": {"peer": {"endpoint": "no-port"}}}},
        {"firewall": {"rules": [{"id": 1, "chain": "input", "protocol": "icmp", "dst-ports": "22"}]}},
        {"lan": {"dhcp-server": {"static-leases": [{"mac": "zz", "ip": "1.2.3.4"}]}}},
    ]
    for d in bad:
        with pytest.raises(system.SysError):
            system.validate_config(d)


def test_restore_and_snapshots(cfg):
    st, applied = cfg
    new = yaml.safe_dump({"system": {"identity": "restored"}, "wan": {"interface": "eth0", "mode": "none"}})
    system.restore_text(new, "test")
    assert st.load()["system"]["identity"] == "restored" and len(applied) == 1
    snaps = system.snapshots()
    assert len(snaps) == 1                                                  # прежняя версия сохранена
    system.restore_snapshot(snaps[0]["name"])
    assert st.load()["system"]["identity"] == "home"
    with pytest.raises(system.SysError):
        system.restore_text("wan: {mode: static}", "bad")                   # проверка не пройдена
    with pytest.raises(system.SysError):
        system.restore_text("::: not yaml :::\n  - [", "broken")
    with pytest.raises(system.SysError):
        system.snapshot_path("../router.yaml")
    assert st.load()["system"]["identity"] == "home"                        # плохие файлы ничего не испортили


# --- Safe Mode ----------------------------------------------------------------------------------------------
def test_safe_mode_commit(cfg):
    st, applied = cfg
    sm = system.SafeMode()
    sm.start(15, "admin")
    with pytest.raises(system.SysError):
        sm.start(15, "other")                                               # уже включён
    st.save({**st.load(), "system": {"identity": "changed"}})
    sm.commit()
    assert not sm.active and st.load()["system"]["identity"] == "changed" and not applied


def test_safe_mode_rollback_on_lost_connection(cfg, monkeypatch):
    st, applied = cfg
    sm = system.SafeMode()
    sm.start(15, "admin")
    st.save({**st.load(), "system": {"identity": "risky change"}})
    sm.deadline = time.time() - 1                                           # «связь пропала»
    for _ in range(30):
        if not sm.active:
            break
        time.sleep(0.1)
    assert not sm.active and sm.last_event["type"] == "rollback"
    assert st.load()["system"]["identity"] == "home" and len(applied) == 1
    assert not sm.file().exists()
    assert any(e["method"] == "ROLLBACK" for e in system.audit_log())


def test_safe_mode_heartbeat_and_restart_recovery(cfg):
    st, _ = cfg
    sm = system.SafeMode()
    sm.start(15, "admin")
    sm.deadline = time.time() + 1
    sm.status(heartbeat=True)
    assert sm.deadline > time.time() + 10                                   # веб на связи — срок продлён
    sm.active = False                                                       # «роутер упал» посреди Safe Mode
    st.save({**st.load(), "system": {"identity": "half-done"}})
    sm2 = system.SafeMode()
    sm2.recover_on_startup()
    assert st.load()["system"]["identity"] == "home" and sm2.last_event["type"] == "rollback"
    with pytest.raises(system.SysError):
        sm2.start(5, "admin")                                               # меньше 15 с нельзя


# --- журнал и ресурсы ---------------------------------------------------------------------------------------------
def test_audit(data):
    system.audit("admin", "PUT", "/api/wan", 200, "10.0.0.5")
    system.audit("admin", "DELETE", "/api/firewall/rules/3", 404, "10.0.0.5")
    log = system.audit_log()
    assert [x["method"] for x in log] == ["DELETE", "PUT"]                  # новые сверху
    assert log[0]["status"] == 404


def test_resource_parsers():
    mem = system.parse_meminfo("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 250 kB\n")
    assert mem == {"total": 1024000, "used": 768000, "percent": 75.0}
    system._cpu_last = None
    assert system.cpu_percent("cpu  100 0 100 800 0 0 0 0 0 0\n") is None    # первый замер
    assert system.cpu_percent("cpu  200 0 200 1000 0 0 0 0 0 0\n") == 50.0
