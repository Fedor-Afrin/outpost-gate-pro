"""Схемы файлового сервера Samba (секция files: в router.yaml).

Пароли пользователей в router.yaml не хранятся: Samba держит их хэши в своей базе
(data/samba/private/passdb.tdb). В конфиге — только имена, группы и права.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator, model_validator

NAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
SHARE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.$-]{0,79}$")
FOLDER_RE = re.compile(r"^[^/\\\x00][^\\\x00]{0,250}$")
VOLUME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
NETBIOS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,14}$")
RESERVED_SHARES = {"global", "homes", "printers", "print$", "ipc$"}
RESERVED_USERS = {"root", "nobody", "daemon", "bin", "sys", "frr", "bind", "kea", "og-files", "admin-smb"}
FIRST_UID = 20000            # служебные Unix-учётки Samba — отдельный диапазон, не пересекаются с системой


def _check_name(v: str, what: str) -> str:
    v = v.strip().lower()
    if not NAME_RE.match(v):
        raise ValueError(f"{what} '{v}': латиница в нижнем регистре, цифры, _ . -, до 32 символов, с буквы")
    if v in RESERVED_USERS:
        raise ValueError(f"{what} '{v}': имя занято системой")
    return v


def _access_list(v: list[str]) -> list[str]:
    """Пользователи и группы (@группа)."""
    out = []
    for x in v:
        x = x.strip()
        if not x:
            continue
        name = _check_name(x[1:] if x.startswith("@") else x, "доступ")
        item = ("@" if x.startswith("@") else "") + name
        if item not in out:
            out.append(item)
    return out


class FileUser(BaseModel):
    name: str = Field(examples=["anna"])
    full_name: str | None = Field(None, max_length=80)
    enabled: bool = True
    groups: list[str] = Field(default_factory=list)
    uid: int | None = Field(None, description="Назначается роутером, не меняется")

    _n = field_validator("name")(classmethod(lambda cls, v: _check_name(v, "пользователь")))

    @field_validator("groups")
    @classmethod
    def _groups(cls, v: list[str]) -> list[str]:
        out = []
        for g in v:
            g = _check_name(g.lstrip("@"), "группа")
            if g not in out:
                out.append(g)
        return out

    @field_validator("full_name")
    @classmethod
    def _full(cls, v: str | None) -> str | None:
        if v and any(c in v for c in ":\n\"\\"):
            raise ValueError("ФИО: без двоеточий и кавычек")
        return v or None


class FileGroup(BaseModel):
    name: str = Field(examples=["accounting"])
    description: str | None = Field(None, max_length=80)
    gid: int | None = None

    _n = field_validator("name")(classmethod(lambda cls, v: _check_name(v, "группа")))


class Share(BaseModel):
    name: str = Field(examples=["Documents"])
    volume: str = Field("data", description="Где лежит: data (встроенное хранилище) или имя подключённого диска")
    folder: str = Field(examples=["documents"], description="Папка внутри тома")
    comment: str | None = Field(None, max_length=120)
    enabled: bool = True
    browseable: bool = Field(True, description="Видна в сетевом окружении")
    read_users: list[str] = Field(default_factory=list, description="Только чтение: user или @group")
    write_users: list[str] = Field(default_factory=list, description="Чтение и запись: user или @group")
    guest: str = Field("none", description="none | read | write — доступ без пароля")
    recycle: bool = Field(True, description="Корзина: удалённое попадает в .recycle/<пользователь>")
    macos: bool = Field(False, description="Совместимость с macOS (Finder, Time Machine)")
    hide_dot_files: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not SHARE_RE.match(v) or v.lower() in RESERVED_SHARES:
            raise ValueError(f"имя папки '{v}': латиница, цифры, пробел, _ . - $, до 80 символов")
        return v

    @field_validator("folder")
    @classmethod
    def _folder(cls, v: str) -> str:
        v = v.strip().strip("/")
        if not v or not FOLDER_RE.match(v) or any(p in ("..", ".") for p in v.split("/")):
            raise ValueError(f"путь '{v}': папка внутри тома, без .. и обратных слэшей")
        return v

    @field_validator("volume")
    @classmethod
    def _volume(cls, v: str) -> str:
        if not VOLUME_RE.match(v):
            raise ValueError(f"том '{v}': data или имя диска")
        return v

    @field_validator("comment")
    @classmethod
    def _comment(cls, v: str | None) -> str | None:
        if v and any(c in v for c in "\n\\"):
            raise ValueError("описание: одной строкой")
        return v or None

    _r = field_validator("read_users", "write_users")(classmethod(lambda cls, v: _access_list(v)))

    @field_validator("guest")
    @classmethod
    def _guest(cls, v: str) -> str:
        if v not in ("none", "read", "write"):
            raise ValueError("гостевой доступ: none, read или write")
        return v

    @model_validator(mode="after")
    def _who(self):
        if self.guest == "none" and not (self.read_users or self.write_users):
            raise ValueError(f"папка {self.name}: укажите, кому доступно, или разрешите гостей")
        return self


class DiskMount(BaseModel):
    """Подключённый диск (раздел): монтируется по UUID в /mnt/disks/<name>."""
    name: str = Field(examples=["archive"], description="Имя тома — так он виден при выборе папки")
    uuid: str
    fstype: str | None = None
    automount: bool = True
    read_only: bool = False

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip().lower()
        if not VOLUME_RE.match(v) or v == "data":
            raise ValueError(f"имя диска '{v}': латиница, цифры, _ -, до 32 символов (не data)")
        return v

    @field_validator("uuid")
    @classmethod
    def _uuid(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9-]{4,64}", v):
            raise ValueError("неверный UUID раздела")
        return v


class FilesConfig(BaseModel):
    enabled: bool = False
    workgroup: str = Field("WORKGROUP", description="Рабочая группа Windows")
    netbios_name: str | None = Field(None, description="Имя сервера в сети; пусто — имя роутера")
    server_string: str = Field("OutpostGate Pro", max_length=80)
    segments: list[str] = Field(default_factory=list, description="На каких сегментах LAN работает; пусто — на всех")
    min_protocol: str = Field("SMB2_10", description="SMB2_10 | SMB3")
    netbios: bool = Field(False, description="Старый NetBIOS (nmbd): нужен для очень старых Windows и сканеров")
    users: list[FileUser] = Field(default_factory=list)
    groups: list[FileGroup] = Field(default_factory=list)
    shares: list[Share] = Field(default_factory=list)
    disks: list[DiskMount] = Field(default_factory=list)

    @field_validator("workgroup")
    @classmethod
    def _wg(cls, v: str) -> str:
        v = v.strip().upper()
        if not NETBIOS_RE.match(v):
            raise ValueError("рабочая группа: латиница, цифры, дефис, до 15 символов")
        return v

    @field_validator("netbios_name")
    @classmethod
    def _nb(cls, v: str | None) -> str | None:
        if not v:
            return None
        v = v.strip().upper()
        if not NETBIOS_RE.match(v):
            raise ValueError("имя сервера: латиница, цифры, дефис, до 15 символов")
        return v

    @field_validator("server_string")
    @classmethod
    def _ss(cls, v: str) -> str:
        if any(c in v for c in "\n\\%"):
            raise ValueError("описание сервера: одной строкой, без % и \\")
        return v.strip() or "OutpostGate Pro"

    @field_validator("min_protocol")
    @classmethod
    def _proto(cls, v: str) -> str:
        if v not in ("SMB2_10", "SMB3"):
            raise ValueError("минимальный протокол: SMB2_10 или SMB3")
        return v

    @model_validator(mode="after")
    def _consistency(self):
        def dup(items, what):
            names = [i.lower() if isinstance(i, str) else i for i in items]
            if len(names) != len(set(names)):
                raise ValueError(f"{what} указан дважды")
        dup([u.name for u in self.users], "пользователь")
        dup([g.name for g in self.groups], "группа")
        dup([s.name for s in self.shares], "общая папка")
        dup([d.name for d in self.disks], "диск")
        dup([d.uuid for d in self.disks], "раздел (UUID)")
        users, groups = {u.name for u in self.users}, {g.name for g in self.groups}
        clash = users & groups
        if clash:
            raise ValueError(f"имя {sorted(clash)[0]} занято и пользователем, и группой")
        for u in self.users:
            for g in u.groups:
                if g not in groups:
                    raise ValueError(f"{u.name}: нет группы {g}")
        volumes = {"data"} | {d.name for d in self.disks}
        for s in self.shares:
            if s.volume not in volumes:
                raise ValueError(f"папка {s.name}: нет тома {s.volume}")
            for who in s.read_users + s.write_users:
                if who.startswith("@") and who[1:] not in groups:
                    raise ValueError(f"папка {s.name}: нет группы {who[1:]}")
                if not who.startswith("@") and who not in users:
                    raise ValueError(f"папка {s.name}: нет пользователя {who}")
        return self

    def to_yaml(self) -> dict:
        return self.model_dump(exclude_none=True)


# --- запросы ---------------------------------------------------------------------------------
class PasswordSet(BaseModel):
    password: str = Field(min_length=6, max_length=127)


class UserCreate(FileUser):
    password: str = Field(min_length=6, max_length=127)


class FormatRequest(BaseModel):
    device: str = Field(examples=["/dev/sdb"])
    label: str = Field("data", pattern=r"^[A-Za-z0-9_-]{1,16}$")
    confirm: str = Field(description="Повторите имя устройства — защита от ошибки")


class MountRequest(BaseModel):
    uuid: str
    name: str
    automount: bool = True
    read_only: bool = False


# --- состояние -----------------------------------------------------------------------------
class BlockDevice(BaseModel):
    name: str                       # sdb1
    path: str                       # /dev/sdb1
    type: str                       # disk | part
    size: int = 0
    fstype: str | None = None
    label: str | None = None
    uuid: str | None = None
    model: str | None = None
    transport: str | None = None    # usb | sata | nvme
    removable: bool = False
    parent: str | None = None
    system: bool = False            # на нём сам сервер — трогать нельзя
    mounted_as: str | None = None   # имя тома, если подключён роутером
    used: int | None = None
    free: int | None = None


class Volume(BaseModel):
    name: str
    path: str
    mounted: bool = True
    size: int | None = None
    free: int | None = None


class Session(BaseModel):
    user: str
    machine: str
    protocol: str | None = None
    share: str | None = None
    since: str | None = None
    open_files: int = 0


class FilesStatus(BaseModel):
    config: FilesConfig
    installed: bool = True
    running: bool = False
    error: str | None = None
    netbios_name: str = ""
    listen: list[str] = []          # адреса, на которых отвечает
    disks_allowed: bool = False     # управление дисками (только режим host)
    volumes: list[Volume] = []
    devices: list[BlockDevice] = []
    sessions: list[Session] = []
    segments: list[dict] = []
    users_without_password: list[str] = []
