"""Samba: настройки, smb.conf, учётки, диски (без самой Samba и без реальных дисков)."""
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.store import ConfigStore
from app.models.files import FilesConfig, FormatRequest, MountRequest, UserCreate
from app.services import files


def cfg(**kw):
    base = {"enabled": True,
            "users": [{"name": "anna", "groups": ["acc"]}, {"name": "boris"}],
            "groups": [{"name": "acc"}],
            "shares": [{"name": "Documents", "folder": "docs", "read_users": ["boris"], "write_users": ["@acc"]},
                       {"name": "Public", "folder": "pub", "guest": "write", "recycle": False}]}
    base.update(kw)
    return FilesConfig.model_validate(base)


def test_model_validation():
    c = cfg()
    assert c.workgroup == "WORKGROUP" and c.shares[0].write_users == ["@acc"]
    bad = [
        {"users": [{"name": "Anna Bad"}]},
        {"users": [{"name": "root"}]},
        {"users": [{"name": "anna", "groups": ["nogroup"]}]},
        {"shares": [{"name": "X", "folder": "../etc", "guest": "read"}]},
        {"shares": [{"name": "homes", "folder": "h", "guest": "read"}]},
        {"shares": [{"name": "X", "folder": "x"}]},                                  # никому не доступна
        {"shares": [{"name": "X", "folder": "x", "write_users": ["ghost"]}]},
        {"shares": [{"name": "X", "folder": "x", "volume": "usb", "guest": "read"}]},  # нет такого тома
        {"users": [{"name": "acc"}], "groups": [{"name": "acc"}]},
        {"workgroup": "TOO-LONG-WORKGROUP"},
        {"min_protocol": "NT1"},
    ]
    for b in bad:
        with pytest.raises(ValidationError):
            cfg(**b)


def test_assign_ids_stable():
    c = files.assign_ids(cfg())
    assert [u.uid for u in c.users] == [20000, 20001] and c.groups[0].gid == 20002
    c.users.append(c.users[0].model_copy(update={"name": "vera", "uid": None}))
    c2 = files.assign_ids(c)
    assert [u.uid for u in c2.users] == [20000, 20001, 20003]


def test_smb_conf(tmp_path):
    c = cfg(shares=[
        {"name": "Documents", "folder": "docs", "read_users": ["boris"], "write_users": ["@acc"], "comment": "Общие"},
        {"name": "Public", "folder": "pub", "guest": "write", "recycle": False},
        {"name": "Mac Backup", "folder": "tm", "write_users": ["anna"], "macos": True, "browseable": False},
        {"name": "Old", "folder": "old", "guest": "read", "enabled": False}])
    t = files.smb_conf(c, ["br-lan", "br-lan2"], "OFFICE", tmp_path)
    assert "netbios name = OFFICE" in t and "interfaces = lo br-lan br-lan2" in t
    assert "bind interfaces only = yes" in t and "map to guest = Bad User" in t
    assert f"passdb backend = tdbsam:{tmp_path}/private/passdb.tdb" in t
    assert "disable netbios = yes" in t and "smb ports = 445" in t
    docs = t[t.index("[Documents]"):t.index("[Public]")]
    assert "valid users = boris @acc" in docs and "read only = yes" in docs and "write list = @acc" in docs
    assert "read list = boris" in docs and "comment = Общие" in docs and "vfs objects = recycle" in docs
    assert "recycle:repository = .recycle/%U" in docs and "force user = og-files" in docs
    pub = t[t.index("[Public]"):t.index("[Mac Backup]")]
    assert "guest ok = yes" in pub and "read only = no" in pub and "valid users" not in pub and "recycle" not in pub
    mac = t[t.index("[Mac Backup]"):]
    assert "vfs objects = catia fruit streams_xattr recycle" in mac and "browseable = no" in mac
    assert "fruit:metadata = stream" in t and "[Old]" not in t
    t2 = files.smb_conf(cfg(netbios=True, shares=[{"name": "D", "folder": "d", "write_users": ["anna"]}]), ["br-lan"], "X", tmp_path)
    assert "disable netbios = no" in t2 and "smb ports" not in t2 and "map to guest = Never" in t2


LSBLK = {"blockdevices": [
    {"name": "sda", "path": "/dev/sda", "size": 256000000000, "type": "disk", "model": "Samsung SSD", "tran": "sata",
     "rm": False, "maj:min": "8:0", "children": [
         {"name": "sda1", "path": "/dev/sda1", "size": 512000000, "type": "part", "fstype": "vfat", "maj:min": "8:1"},
         {"name": "sda2", "path": "/dev/sda2", "size": 255000000000, "type": "part", "fstype": "ext4",
          "uuid": "root-uuid", "maj:min": "8:2"}]},
    {"name": "sdb", "path": "/dev/sdb", "size": 2000000000000, "type": "disk", "model": "WD Elements", "tran": "usb",
     "rm": True, "maj:min": "8:16", "children": [
         {"name": "sdb1", "path": "/dev/sdb1", "size": 2000000000000, "type": "part", "fstype": "ntfs",
          "label": "Archive", "uuid": "ABCD-1234", "maj:min": "8:17"}]},
    {"name": "loop0", "path": "/dev/loop0", "type": "loop", "maj:min": "7:0"},
]}
MOUNTINFO = """\
1000 900 0:50 / / rw,relatime - overlay overlay rw
1010 1000 8:2 /var/lib/docker/containers/x/hosts /etc/hosts rw - ext4 /dev/sda2 rw
1011 1000 0:60 / /proc rw - proc proc rw
"""


def test_parse_devices_marks_system_disk():
    used = files._mounted_majmin(MOUNTINFO)
    assert used == {"8:2"}
    devs = {d.name: d for d in files.parse_devices(LSBLK, used, {"ABCD-1234": "archive"})}
    assert set(devs) == {"sda", "sda1", "sda2", "sdb", "sdb1"}               # loop пропущен
    assert devs["sda"].system and devs["sda1"].system and devs["sda2"].system  # весь диск сервера
    assert not devs["sdb"].system and devs["sdb1"].fstype == "ntfs" and devs["sdb1"].parent == "sdb"
    assert devs["sdb1"].mounted_as == "archive" and devs["sdb"].transport == "usb" and devs["sdb"].removable


def test_mount_options(monkeypatch):
    monkeypatch.setattr(files, "_exists_user", lambda n: None)
    assert files.mount_options("ntfs", False) == ("ntfs3", "rw,noatime,uid=19999,gid=19999,umask=002")
    assert files.mount_options("ext4", True) == ("ext4", "ro,noatime")


def test_parse_sessions():
    data = {"sessions": {"3": {"username": "anna", "remote_machine": "192.168.1.20", "session_dialect": "SMB3_11",
                               "server_id": {"pid": "77"}}},
            "tcons": {"1": {"service": "Documents", "session_id": "3", "connected_at": "2026-11-13T10:00:00"}},
            "open_files": {"/x": {"opens": {"a": {"server_id": {"pid": "77"}}, "b": {"server_id": {"pid": "77"}}}}}}
    s = files.parse_sessions(data)[0]
    assert (s.user, s.machine, s.protocol, s.share, s.open_files) == ("anna", "192.168.1.20", "SMB3_11", "Documents", 2)
    assert files.parse_sessions({}) == []


@pytest.fixture
def env(tmp_path, monkeypatch):
    store = ConfigStore(tmp_path / "router.yaml", tmp_path / "snap")
    monkeypatch.setattr(files, "store", store)
    calls = {"apply": [], "passwords": []}
    monkeypatch.setattr(files, "apply", lambda c=None: calls["apply"].append(c or files.get_config()))
    monkeypatch.setattr(files, "set_password", lambda n, p: calls["passwords"].append((n, p)))
    monkeypatch.setattr(files, "status", lambda: files.get_config())
    return store, calls


def test_update_keeps_ids_and_rolls_back(env, monkeypatch):
    store, calls = env
    files.update(cfg())
    first = files.get_config()
    assert [u.uid for u in first.users] == [20000, 20001]
    edited = cfg(users=[{"name": "boris"}, {"name": "anna", "groups": ["acc"]}])   # без uid, другой порядок
    files.update(edited)
    assert {u.name: u.uid for u in files.get_config().users} == {"anna": 20000, "boris": 20001}

    def boom(c=None):
        raise files.FilesError(400, "testparm")
    monkeypatch.setattr(files, "apply", boom)
    with pytest.raises(files.FilesError):
        files.update(cfg(workgroup="OTHER"))
    assert files.get_config().workgroup == "WORKGROUP"                       # откат


def test_add_user_sets_password(env):
    store, calls = env
    files.update(cfg())
    files.add_user(UserCreate(name="vera", password="secret123", groups=["acc"]))
    c = files.get_config()
    assert any(u.name == "vera" and u.uid == 20003 for u in c.users)
    assert calls["passwords"] == [("vera", "secret123")]
    with pytest.raises(files.FilesError):
        files.add_user(UserCreate(name="vera", password="secret123"))
    with pytest.raises(files.FilesError):
        files.change_password("ghost", "secret123")


def test_disks_only_in_host_mode_and_guarded(env, monkeypatch):
    store, calls = env
    files.update(cfg())
    monkeypatch.setenv("ROUTER_DISKS", "0")
    with pytest.raises(files.FilesError) as e:
        files.mount(MountRequest(uuid="ABCD-1234", name="archive"))
    assert e.value.status == 403
    monkeypatch.setenv("ROUTER_DISKS", "1")
    devs = files.parse_devices(LSBLK, {"8:2"}, {})
    monkeypatch.setattr(files, "devices", lambda: devs)
    monkeypatch.setattr(files, "sync_accounts", lambda c: None)
    mounted = []
    monkeypatch.setattr(files, "_mount", lambda d, fs: mounted.append((d.name, fs)))
    with pytest.raises(files.FilesError, match="сам сервер"):
        files.mount(MountRequest(uuid="root-uuid", name="sys"))
    files.mount(MountRequest(uuid="ABCD-1234", name="Archive"))
    assert mounted == [("archive", "ntfs")] and files.get_config().disks[0].name == "archive"
    with pytest.raises(files.FilesError, match="уже подключён"):
        files.mount(MountRequest(uuid="ABCD-1234", name="other"))
    # папка на диске — отключить нельзя
    c = files.get_config()
    c.shares.append(c.shares[0].model_copy(update={"name": "Arch", "volume": "archive", "folder": "a"}))
    files.update(c)
    with pytest.raises(files.FilesError, match="используют папки"):
        files.unmount("archive")
    # список дисков через PUT не меняется
    c = files.get_config()
    c.disks = []
    files.update(c)
    assert files.get_config().disks[0].name == "archive"
    # форматирование: подтверждение и системный диск
    with pytest.raises(files.FilesError, match="подтверждение"):
        files.format_device(FormatRequest(device="/dev/sdb", confirm="/dev/sdc"))
    with pytest.raises(files.FilesError, match="сам сервер"):
        files.format_device(FormatRequest(device="/dev/sda", confirm="/dev/sda"))
