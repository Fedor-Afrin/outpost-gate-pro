"""
Раздел Files: файловый сервер Samba.

  GET    /api/files                         настройки, папки, пользователи, тома, диски, подключения
  PUT    /api/files                         сохранить настройки целиком (сервер, папки, пользователи, группы)
  POST   /api/files/users                   создать пользователя с паролем
  PUT    /api/files/users/{name}/password   сменить пароль
  POST   /api/files/disks/mount             подключить раздел (только режим host)
  DELETE /api/files/disks/{name}            отключить диск
  POST   /api/files/disks/format            стереть и создать ext4 (подтверждение — имя устройства)
"""
from fastapi import APIRouter, HTTPException

from app.models.files import FilesConfig, FilesStatus, FormatRequest, MountRequest, PasswordSet, UserCreate
from app.services import files as svc

router = APIRouter()


def _call(fn, *args):
    try:
        return fn(*args)
    except svc.FilesError as e:
        raise HTTPException(status_code=e.status, detail=e.message)


@router.get("", response_model=FilesStatus)
def get_files():
    return svc.status()


@router.put("", response_model=FilesStatus)
def set_files(data: FilesConfig):
    return _call(svc.update, data)


@router.post("/users", response_model=FilesStatus, status_code=201)
def add_user(data: UserCreate):
    return _call(svc.add_user, data)


@router.put("/users/{name}/password", response_model=FilesStatus)
def set_password(name: str, data: PasswordSet):
    return _call(svc.change_password, name, data.password)


@router.post("/disks/mount", response_model=FilesStatus)
def mount(data: MountRequest):
    return _call(svc.mount, data)


@router.delete("/disks/{name}", response_model=FilesStatus)
def unmount(name: str):
    return _call(svc.unmount, name)


@router.post("/disks/format", response_model=FilesStatus)
def format_device(data: FormatRequest):
    return _call(svc.format_device, data)
