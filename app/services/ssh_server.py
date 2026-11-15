"""
SSH-доступ к командной строке роутера (asyncssh).

  ssh admin@<роутер>            (dev: ssh -p 2222 admin@localhost)
  -> сразу оболочка в стиле MikroTik, не bash. Bash — командой /system shell.

  * пользователи и пароли — те же, что у веб-интерфейса; admin без пароля
    пускается без вопросов только из локальной сети (как веб);
  * для каждого входа запускается `python -m app.cli` на отдельном псевдотерминале (PTY):
    у оболочки и у bash внутри неё нормальный терминал — Tab, Ctrl-C, размеры окна;
  * без терминала (ssh admin@router "/ip route print") — выполняется одна команда;
  * ключ сервера создаётся при первом запуске и хранится в data/ssh_host_ed25519_key.
"""
from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import pty
import struct
import sys
import termios
from pathlib import Path

from app.core import auth
from app.core.config import settings

APP_HOME = Path(__file__).resolve().parents[2]


def _host_key(asyncssh):
    path = Path(settings.data_dir) / "ssh_host_ed25519_key"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(path))
        os.chmod(path, 0o600)
        print(f"[ssh] создан ключ сервера {path}")
    return asyncssh.read_private_key(str(path))


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    with contextlib.suppress(OSError):
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows or 24, cols or 80, 0, 0))


async def start():
    """Запустить SSH-сервер в текущем цикле событий. Возвращает объект сервера или None."""
    try:
        import asyncssh
    except ImportError:
        print("[ssh] нет asyncssh — CLI по SSH недоступен (пересоберите образ)")
        return None

    from app.services import system

    class Server(asyncssh.SSHServer):
        def connection_made(self, conn):
            self.conn = conn
            peer = conn.get_extra_info("peername")
            self.ip = peer[0] if peer else "-"
            self.opts = ""

        def _grant(self, user: auth.User, token: str | None = None) -> None:
            self.conn.set_extra_info(og_user=user.name, og_role=user.role,
                                     og_token=token or auth.make_token(user.name), og_opts=self.opts)
            system.audit(user.name, "SSH", "вход по SSH", 200, self.ip)

        def begin_auth(self, username):
            # RouterOS: «admin+cet1024w» — имя и параметры терминала (без цветов, ширина). Так входит Ansible
            # (community.routeros): берём имя, а сессию ведём в синтаксисе RouterOS без вопросов
            username, _, self.opts = username.partition("+")
            if auth.passwordless(username) and auth.is_local(self.ip):
                self._grant(auth.get_user(username.lower()))
                return False                       # без пароля: сразу внутрь, как MikroTik
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            username = username.partition("+")[0]
            try:
                user, token = auth.login(username, password, self.ip)
            except auth.AuthError:
                system.audit(username or "-", "SSH", "неудачный вход по SSH", 401, self.ip)
                return False
            if user.must_change:
                return False                       # временный пароль сначала меняется в веб-интерфейсе
            self._grant(user, token)
            return True

    async def handle(process):
        conn = process.get_extra_info("connection")
        env = {**os.environ, "OG_TOKEN": conn.get_extra_info("og_token"), "OG_USER": conn.get_extra_info("og_user"),
               "OG_ROLE": conn.get_extra_info("og_role"), "HOME": "/root",
               **({"OG_SYNTAX": "routeros"} if conn.get_extra_info("og_opts") else {}),
               "TERM": process.get_terminal_type() or "xterm-256color"}
        cmd = [sys.executable, "-m", "app.cli"] + (["-c", process.command] if process.command else [])

        if not process.get_terminal_type():        # без терминала: одна команда
            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=APP_HOME, env=env, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await proc.communicate()
            process.stdout.write(out)
            process.exit(proc.returncode or 0)
            return

        master, slave = pty.openpty()
        cols, rows, *_ = process.get_terminal_size()
        _set_winsize(master, rows, cols)
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=APP_HOME, env=env, stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True)     # своя сессия; PTY делает управляющим сама оболочка
        os.close(slave)

        loop = asyncio.get_running_loop()
        closed = asyncio.Event()

        def from_pty():
            try:
                data = os.read(master, 65536)
            except OSError:
                data = b""
            if not data:
                loop.remove_reader(master)
                closed.set()
                return
            process.stdout.write(data)

        async def to_pty():
            while not closed.is_set():
                try:
                    data = await process.stdin.read(4096)
                except asyncssh.TerminalSizeChanged as e:
                    _set_winsize(master, e.height, e.width)
                    continue
                except asyncssh.BreakReceived:
                    data = b"\x03"
                if not data:
                    break
                os.write(master, data)

        loop.add_reader(master, from_pty)
        writer = asyncio.create_task(to_pty())
        code = await proc.wait()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(closed.wait(), 2)
        writer.cancel()
        with contextlib.suppress(Exception):
            loop.remove_reader(master)
        os.close(master)
        process.exit(code or 0)

    port = int(os.getenv("CLI_SSH_PORT", "22"))
    try:
        server = await asyncssh.create_server(
            Server, "", port, server_host_keys=[_host_key(asyncssh)], process_factory=handle,
            encoding=None,          # байты как есть — их обрабатывает PTY
            line_editor=False)      # редактирование строки делает сама оболочка (prompt_toolkit)
    except OSError as e:
        print(f"[ssh] не удалось открыть порт {port}: {e} — CLI по SSH недоступен")
        return None
    print(f"[ssh] CLI по SSH на порту {port}")
    return server
