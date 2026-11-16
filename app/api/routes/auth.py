"""
Вход в веб-интерфейс.

  POST /api/auth/login      {"name", "password"} -> cookie сессии (+ token для CLI/скриптов)
  POST /api/auth/logout     выйти
  GET  /api/auth/me         кто вошёл (или logged_in: false)
  POST /api/auth/password   {"old", "new"} — сменить свой пароль
"""
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from app.core import auth
from app.services import system

router = APIRouter()


class LoginBody(BaseModel):
    name: str
    password: str


class PasswordBody(BaseModel):
    old: str
    new: str


def _set_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(auth.COOKIE, token, max_age=auth.SESSION_TTL, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https", path="/")


def _ip(request: Request) -> str:
    return request.client.host if request.client else "-"


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response):
    try:
        user, token = auth.login(body.name, body.password, _ip(request))
    except auth.AuthError as e:
        system.audit(body.name or "-", "LOGIN", "неудачный вход", e.status, _ip(request))
        raise HTTPException(e.status, e.message)
    system.audit(user.name, "LOGIN", "вход", 200, _ip(request))
    _set_cookie(response, request, token)
    return {"name": user.name, "role": user.role, "must_change": user.must_change,
            "has_password": user.has_password, "token": token}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(auth.COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(request: Request):
    user = auth.user_from_token(auth.token_from(request.cookies, request.headers))
    if not user:
        return {"logged_in": False}
    return {"logged_in": True, "name": user.name, "role": user.role, "must_change": user.must_change,
            "has_password": user.has_password, "identity": system.identity()}


class CliPrefsBody(BaseModel):
    syntax: str | None = None
    lang: str | None = None


@router.get("/cli")
def get_cli_prefs(request: Request):
    """Синтаксис CLI пользователя: routeros | linux | null (ещё не выбирал — CLI спросит при входе)."""
    from app.services import cli_prefs
    user = auth.user_from_token(auth.token_from(request.cookies, request.headers))
    if not user:
        raise HTTPException(401, "нужен вход")
    return cli_prefs.get(user.name)


@router.put("/cli")
def set_cli_prefs(body: CliPrefsBody, request: Request):
    from app.services import cli_prefs
    user = auth.user_from_token(auth.token_from(request.cookies, request.headers))
    if not user:
        raise HTTPException(401, "нужен вход")
    try:
        return cli_prefs.update(user.name, syntax=body.syntax, lang=body.lang)
    except ValueError as e:
        raise HTTPException(422, str(e))


@router.post("/password")
def change_password(body: PasswordBody, request: Request, response: Response):
    user = auth.user_from_token(auth.token_from(request.cookies, request.headers))
    if not user:
        raise HTTPException(401, "нужен вход")
    try:
        token = auth.change_own_password(user.name, body.old, body.new)
    except auth.AuthError as e:
        raise HTTPException(e.status, e.message)
    _set_cookie(response, request, token)
    return {"ok": True, "token": token}
