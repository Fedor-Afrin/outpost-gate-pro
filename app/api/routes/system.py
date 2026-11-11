"""
Раздел System.

  GET  /api/system/health                 жив ли API (без входа)
  GET  /api/system/resource               CPU, память, диск, uptime, температура, модель
  PUT  /api/system/identity               {"identity"} — имя роутера
  GET  /api/system/users                  пользователи
  POST /api/system/users                  {"name", "password", "role"}
  PUT  /api/system/users/{name}           {"password"?, "role"?}
  DELETE /api/system/users/{name}
  GET  /api/system/backup                 скачать router.yaml
  POST /api/system/restore                {"text": "<yaml>"} — восстановить (с проверкой)
  GET  /api/system/snapshots              автоматические снимки перед каждым изменением
  GET  /api/system/snapshots/{name}       скачать снимок
  POST /api/system/snapshots/{name}/restore
  GET  /api/system/safe-mode              состояние (и «я на связи» для открытого веба)
  POST /api/system/safe-mode              {"timeout"} — включить
  POST /api/system/safe-mode/commit | /rollback
  GET  /api/system/audit?limit=           журнал действий
  POST /api/system/restart                перезапустить сервис роутера
"""
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from app.core import auth
from app.services import system as svc

router = APIRouter()


class IdentityBody(BaseModel):
    identity: str


class NewUser(BaseModel):
    name: str
    password: str
    role: Literal["full", "read"] = "full"


class UserUpdate(BaseModel):
    password: str | None = None
    role: Literal["full", "read"] | None = None


class RestoreBody(BaseModel):
    text: str
    filename: str | None = None


class SafeModeStart(BaseModel):
    timeout: int = 60


def _sys(fn, *args):
    try:
        return fn(*args)
    except svc.SysError as e:
        raise HTTPException(e.status, e.message)


def _auth(fn, *args, **kw):
    try:
        return fn(*args, **kw)
    except auth.AuthError as e:
        raise HTTPException(e.status, e.message)


def _me(request: Request) -> str:
    return getattr(request.state, "user", "-")


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/resource")
def resource():
    return svc.resource()


@router.put("/identity")
def set_identity(body: IdentityBody):
    return {"identity": _sys(svc.set_identity, body.identity)}


@router.get("/users")
def users():
    return auth.list_users()


@router.post("/users", status_code=201)
def add_user(body: NewUser):
    _auth(auth.add_user, body.name, body.password, body.role, must_change=True)
    return auth.list_users()


@router.put("/users/{name}")
def update_user(name: str, body: UserUpdate):
    # пароль, заданный администратором, пользователь меняет при первом входе
    _auth(auth.update_user, name, password=body.password, role=body.role,
          must_change=True if body.password else None)
    return auth.list_users()


@router.delete("/users/{name}")
def delete_user(name: str, request: Request):
    _auth(auth.delete_user, name, _me(request))
    return auth.list_users()


@router.get("/backup")
def backup():
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    return PlainTextResponse(svc.backup_text(), media_type="application/x-yaml", headers={
        "Content-Disposition": f'attachment; filename="{svc.identity()}-{stamp}.yaml"'})


@router.post("/restore")
def restore(body: RestoreBody):
    _sys(svc.restore_text, body.text, f"файл {body.filename or 'из веба'}")
    return {"ok": True}


@router.get("/snapshots")
def snapshots():
    return svc.snapshots()


@router.get("/snapshots/{name}")
def get_snapshot(name: str):
    return FileResponse(_sys(svc.snapshot_path, name), media_type="application/x-yaml", filename=name)


@router.post("/snapshots/{name}/restore")
def restore_snapshot(name: str):
    _sys(svc.restore_snapshot, name)
    return {"ok": True}


@router.get("/safe-mode")
def safe_mode_status():
    return svc.safe_mode.status(heartbeat=True)


@router.post("/safe-mode")
def safe_mode_start(body: SafeModeStart, request: Request):
    return _sys(svc.safe_mode.start, body.timeout, _me(request))


@router.post("/safe-mode/commit")
def safe_mode_commit():
    return _sys(svc.safe_mode.commit)


@router.post("/safe-mode/rollback")
def safe_mode_rollback():
    return _sys(svc.safe_mode.rollback)


@router.get("/audit")
def audit(limit: int = 200):
    return svc.audit_log(min(max(limit, 1), 2000))


@router.post("/restart")
def restart():
    svc.restart_service()
    return {"ok": True, "message": "сервис перезапускается — страница обновится через несколько секунд"}
