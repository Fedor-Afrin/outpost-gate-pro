"""
Вход в веб-интерфейс и API: пользователи, пароли, сессии, роли.

  * пароли — scrypt (стандартная библиотека), в router.yaml их НЕТ: пользователи лежат
    отдельно в data/users.json, поэтому восстановление бэкапа не заблокирует вход;
  * сессия — подписанный HMAC токен в cookie (HttpOnly, SameSite=Strict) или в заголовке
    Authorization: Bearer (для CLI и скриптов). Смена пароля сразу обнуляет старые сессии;
  * первый запуск, как в MikroTik: admin БЕЗ пароля (поле пароля пустое), пока пароль
    не задан — в веб-интерфейсе висит напоминание. Вход без пароля — только из локальной
    сети (10/8, 172.16/12, 192.168/16, localhost). Или задайте ROUTER_ADMIN_PASSWORD;
  * роли: full — всё, read — только просмотр;
  * защита от подбора: 5 неудачных входов с одного IP за 5 минут -> пауза.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings

COOKIE = "og_session"
SESSION_TTL = 12 * 3600
MIN_PASSWORD = 8
NAME_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,31}$")
ROLES = ("full", "read")
FAIL_LIMIT, FAIL_WINDOW = 5, 300

_lock = threading.RLock()
_fails: dict[str, list[float]] = {}


class AuthError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class User:
    name: str
    role: str
    must_change: bool = False
    has_password: bool = True


# --- хранение ------------------------------------------------------------------------------
def _users_file() -> Path:
    return Path(settings.data_dir) / "users.json"


def _secret_file() -> Path:
    return Path(settings.data_dir) / "secret.key"


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp.")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _load() -> list[dict]:
    try:
        return json.loads(_users_file().read_text()).get("users", [])
    except (OSError, ValueError):
        return []


def _save(users: list[dict]) -> None:
    _write_private(_users_file(), json.dumps({"users": users}, indent=2))


def _secret() -> bytes:
    with _lock:
        try:
            return bytes.fromhex(_secret_file().read_text().strip())
        except (OSError, ValueError):
            key = secrets.token_bytes(32)
            _write_private(_secret_file(), key.hex())
            return key


# --- пароли ----------------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if stored == "":                      # пароль не задан: подходит только пустой
        return password == ""
    try:
        _, n, r, p, salt, dk = stored.split("$")
        test = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(dk) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(test.hex(), dk)


def check_password_policy(password: str) -> None:
    if len(password or "") < MIN_PASSWORD:
        raise AuthError(422, f"пароль — не короче {MIN_PASSWORD} символов")


# --- токены сессии --------------------------------------------------------------------------------
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(name: str, ttl: int = SESSION_TTL) -> str:
    u = next((u for u in _load() if u["name"] == name), None)
    if not u:
        raise AuthError(404, "нет такого пользователя")
    payload = _b64(json.dumps({"u": name, "e": int(time.time()) + ttl, "v": u["hash"][-12:]}).encode())
    sig = _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def user_from_token(token: str | None) -> User | None:
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    good = _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, good):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        return None
    if data.get("e", 0) < time.time():
        return None
    u = next((u for u in _load() if u["name"] == data.get("u")), None)
    if not u or u["hash"][-12:] != data.get("v"):       # пароль сменили — старые сессии не действуют
        return None
    return _user(u)


def _user(u: dict) -> User:
    return User(u["name"], u["role"], u.get("must_change", False), bool(u["hash"]))


def is_local(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


def token_from(cookies: dict, headers: dict) -> str | None:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return cookies.get(COOKIE)


# --- вход ------------------------------------------------------------------------------------------
def _throttled(ip: str) -> bool:
    now = time.time()
    _fails[ip] = [t for t in _fails.get(ip, []) if now - t < FAIL_WINDOW]
    return len(_fails[ip]) >= FAIL_LIMIT


def login(name: str, password: str, ip: str) -> tuple[User, str]:
    with _lock:
        if _throttled(ip):
            raise AuthError(429, "слишком много неудачных попыток — подождите 5 минут")
        u = next((u for u in _load() if u["name"] == (name or "").strip().lower()), None)
        if not u or not verify_password(password or "", u["hash"]):
            _fails.setdefault(ip, []).append(time.time())
            raise AuthError(401, "неверное имя или пароль")
        if not u["hash"] and not is_local(ip):
            raise AuthError(403, "пароль не задан: вход без пароля разрешён только из локальной сети")
        _fails.pop(ip, None)
        return _user(u), make_token(u["name"])


def passwordless(name: str) -> bool:
    """Пользователь есть и пароль у него не задан (первый вход admin, как в MikroTik)."""
    u = next((u for u in _load() if u["name"] == (name or "").strip().lower()), None)
    return bool(u) and not u["hash"]


def get_user(name: str) -> User | None:
    u = next((u for u in _load() if u["name"] == name), None)
    return _user(u) if u else None


def check_access(path: str, method: str, user: User | None) -> tuple[int, str] | None:
    """Решение для одного запроса к /api: None — пропустить, иначе (код, причина)."""
    public = ("/api/auth/login", "/api/auth/logout", "/api/auth/me", "/api/system/health")
    if not path.startswith("/api") or path in public:
        return None
    if not user:
        return 401, "нужен вход"
    if path.startswith("/api/auth/"):
        return None
    if user.must_change:
        return 403, "сначала смените пароль"
    if method not in ("GET", "HEAD") and user.role != "full":
        return 403, "у роли «только просмотр» нет прав на изменения"
    return None


# --- пользователи -------------------------------------------------------------------------------------
def list_users() -> list[dict]:
    return [{"name": u["name"], "role": u["role"], "must_change": u.get("must_change", False),
             "has_password": bool(u["hash"])} for u in _load()]


def add_user(name: str, password: str, role: str, must_change: bool = False) -> None:
    name = (name or "").strip().lower()
    if not NAME_RE.match(name):
        raise AuthError(422, "имя: латиница, цифры, . _ -, от 2 до 32 символов, с буквы")
    if role not in ROLES:
        raise AuthError(422, "роль: full или read")
    check_password_policy(password)
    with _lock:
        users = _load()
        if any(u["name"] == name for u in users):
            raise AuthError(409, f"пользователь {name} уже есть")
        users.append({"name": name, "hash": hash_password(password), "role": role, "must_change": must_change})
        _save(users)


def update_user(name: str, password: str | None = None, role: str | None = None,
                must_change: bool | None = None) -> None:
    with _lock:
        users = _load()
        u = next((u for u in users if u["name"] == name), None)
        if not u:
            raise AuthError(404, f"нет пользователя {name}")
        if role is not None:
            if role not in ROLES:
                raise AuthError(422, "роль: full или read")
            if role != "full" and u["role"] == "full" and sum(x["role"] == "full" for x in users) == 1:
                raise AuthError(409, "нельзя оставить роутер без администратора с полными правами")
            u["role"] = role
        if password is not None:
            check_password_policy(password)
            u["hash"] = hash_password(password)
        if must_change is not None:
            u["must_change"] = must_change
        _save(users)


def change_own_password(name: str, old: str, new: str) -> str:
    u = next((u for u in _load() if u["name"] == name), None)
    if not u or not verify_password(old or "", u["hash"]):
        raise AuthError(403, "текущий пароль неверен")
    if old == new:
        raise AuthError(422, "новый пароль совпадает со старым")
    update_user(name, password=new, must_change=False)
    return make_token(name)           # старые сессии больше не действуют, выдаём новую


def delete_user(name: str, current: str) -> None:
    if name == current:
        raise AuthError(409, "нельзя удалить самого себя")
    with _lock:
        users = _load()
        u = next((u for u in users if u["name"] == name), None)
        if not u:
            raise AuthError(404, f"нет пользователя {name}")
        if u["role"] == "full" and sum(x["role"] == "full" for x in users) == 1:
            raise AuthError(409, "нельзя удалить последнего администратора")
        _save([x for x in users if x["name"] != name])


def ensure_admin() -> None:
    """Первый запуск: создать admin — без пароля (как MikroTik) или с ROUTER_ADMIN_PASSWORD."""
    if _load():
        return
    preset = os.getenv("ROUTER_ADMIN_PASSWORD")
    if preset and len(preset) >= MIN_PASSWORD:
        add_user("admin", preset, "full")
        print("[auth] создан пользователь admin с паролем из ROUTER_ADMIN_PASSWORD")
        return
    _save([{"name": "admin", "hash": "", "role": "full", "must_change": False}])
    print("[auth] первый запуск: пользователь admin БЕЗ пароля (вход только из локальной сети).")
    print("[auth] Задайте пароль: веб-интерфейс -> плашка «Пароль не задан» или System -> Пользователи.")
