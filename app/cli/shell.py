"""
Интерактивная оболочка: приглашение [admin@имя] /ip address>, Tab, история, Ctrl-C.

Запуск:
  * по SSH — автоматически (app/services/ssh_server.py), сразу после входа;
  * в консоли контейнера — команда `outpost` (в GNS3: Auxiliary console -> outpost);
  * одна команда без интерактива: outpost -c "/ip address print"  или  ssh admin@router "/ip route print".
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

from app.cli import commands
from app.cli.api import Api, ApiError

BANNER = """
  OutpostGate Pro — VPN-шлюз удалённого сотрудника
  Команды как в MikroTik RouterOS:  /ip address print · /ip route print · /ping 8.8.8.8
  ? — помощь · Tab — подсказки · сокращения: /ip addr pr · /system shell — bash · quit — выход
"""


def run_bash() -> None:
    """/system shell: настоящий bash; exit или Ctrl-D — назад в оболочку роутера."""
    print("Командная строка Linux. Назад в OutpostGate Pro: exit или Ctrl-D\n")
    env = {**os.environ, "PS1": r"[shell@outpost-gate-pro \W]# "}
    shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
    subprocess.call([shell, "--norc"] if shell.endswith("bash") else [shell], env=env)
    print("\nНазад в OutpostGate Pro.")


def _whoami(api: Api) -> tuple[str, str, str]:
    me = api.get("/api/auth/me")
    if not me.get("logged_in"):
        raise ApiError("нет входа: токен не принят")
    return me["name"], me["role"], me.get("identity") or "outpost-gate-pro"


def run_one(ctx: commands.Ctx, line: str) -> int:
    try:
        commands.execute(ctx, line, [])
        return 0
    except commands.Quit:
        return 0
    except commands.CliError as e:
        print(str(e), file=sys.stderr)
        return 1


def interactive(ctx: commands.Ctx, identity: str) -> None:
    cwd: list[str] = []
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import Completer, Completion
        from prompt_toolkit.history import InMemoryHistory

        class RouterCompleter(Completer):
            def get_completions(self, document, complete_event):
                text = document.text_before_cursor
                last = text.split(" ")[-1]
                for word in commands.complete(text, cwd, ctx):
                    yield Completion(word, start_position=-len(last))

        session = PromptSession(history=InMemoryHistory(), completer=RouterCompleter(), complete_while_typing=False)
        read = lambda p: session.prompt(p)
    except ImportError:                                   # без prompt_toolkit — простой ввод
        read = input

    print(BANNER)
    while True:
        prompt = f"[{ctx.user}@{identity}] {commands.path_str(cwd)}> " if cwd else f"[{ctx.user}@{identity}] > "
        try:
            line = read(prompt)
        except KeyboardInterrupt:          # Ctrl-C — очистить строку
            continue
        except EOFError:                   # Ctrl-D — выход
            print("quit")
            return
        try:
            cwd = commands.execute(ctx, line, cwd)
        except commands.Quit:
            return
        except commands.CliError as e:
            print(e)
        except KeyboardInterrupt:
            print()
        if "identity set" in line and "name=" in line:     # обновить приглашение
            try:
                identity = _whoami(ctx.api)[2]
            except ApiError:
                pass


def _take_terminal() -> None:
    """Запуск по SSH: процесс в новой сессии — делаем PTY управляющим терминалом (Ctrl-C, bash)."""
    try:
        import fcntl
        import termios
        if os.isatty(0):
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    except OSError:
        pass                                   # уже есть управляющий терминал (запуск из консоли)


def main() -> None:
    _take_terminal()
    parser = argparse.ArgumentParser(prog="outpost", description="CLI OutpostGate Pro в стиле MikroTik")
    parser.add_argument("-c", "--command", help="выполнить одну команду и выйти")
    args = parser.parse_args()

    api = Api()
    try:
        user, role, identity = _whoami(api)
    except ApiError as e:
        sys.exit(f"OutpostGate Pro: {e}")
    ctx = commands.Ctx(api=api, user=user, role=os.getenv("OG_ROLE") or role, shell=run_bash)
    if args.command:
        sys.exit(run_one(ctx, args.command))
    interactive(ctx, identity)
