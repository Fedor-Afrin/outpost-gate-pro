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

from app.cli import commands, linux
from app.cli.api import Api, ApiError

BANNER = """
  OutpostGate Pro — VPN-шлюз удалённого сотрудника
  Команды как в MikroTik RouterOS:  /ip address print · /ip route print · /ping 8.8.8.8
  ? — помощь · Tab — подсказки · сокращения: /ip addr pr · /system shell — bash · quit — выход
  linux — перейти на синтаксис Linux (ip a, nmcli)
"""
BANNER_LINUX = """
  OutpostGate Pro — VPN-шлюз удалённого сотрудника
  Синтаксис Linux:  ip a · ip r · nmcli c · ss -tlnp · ping -c 3 samba
  help — список · /… — команда RouterOS · routeros — синтаксис MikroTik · exit — выход
"""
SYNTAX_QUESTION = """
  Синтаксис командной строки / CLI syntax:
    1) MikroTik RouterOS   /ip address print · /ip route add …
    2) Linux               ip a · ip route add … · nmcli c
  Выбор запомнится; переключить потом: linux / routeros.
"""
SWITCH_LINUX = ("linux", ":linux", "/linux")
SWITCH_ROUTEROS = ("routeros", "mikrotik", "ros", ":routeros", "/routeros")
LINUX_WORDS = ["ip", "nmcli", "bridge", "ss", "ping", "traceroute", "hostname", "help", "routeros", "exit", "clear"]


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


def get_syntax(api: Api) -> str | None:
    """Синтаксис: OG_SYNTAX (Ansible, логин admin+cet1024w — всегда RouterOS) или выбор пользователя."""
    forced = os.getenv("OG_SYNTAX")
    if forced in ("routeros", "linux"):
        return forced
    try:
        return api.get("/api/auth/cli").get("syntax")
    except ApiError:
        return None


def save_syntax(api: Api, syntax: str) -> None:
    if os.getenv("OG_SYNTAX"):
        return                                    # Ansible и т. п.: выбор пользователя не трогаем
    try:
        api.put("/api/auth/cli", {"syntax": syntax})
    except ApiError:
        pass


def ask_syntax(timeout: float = 20.0) -> tuple[str, bool]:
    """Первый вход: спросить синтаксис. -> (синтаксис, ответил ли человек).
    Нет ответа за timeout (скрипт, Ansible) — RouterOS: дальше пойдёт обычное приглашение."""
    import select
    print(SYNTAX_QUESTION)
    print("  Выбор [1]: ", end="", flush=True)
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
    except (OSError, ValueError):
        ready = []
    if not ready:
        print("1")
        return "routeros", False
    answer = sys.stdin.readline().strip().lower()
    return ("linux" if answer in ("2", "linux", "l") else "routeros"), True


def run_line(ctx: commands.Ctx, line: str, cwd: list[str], syntax: str) -> list[str]:
    """Одна строка в текущем синтаксисе; «/…» — всегда RouterOS."""
    if syntax == "linux" and not line.strip().startswith("/"):
        linux.execute(ctx, line)
        return cwd
    return commands.execute(ctx, line, cwd)


def run_one(ctx: commands.Ctx, line: str) -> int:
    try:
        run_line(ctx, line, [], get_syntax(ctx.api) or "routeros")
        return 0
    except commands.Quit:
        return 0
    except commands.CliError as e:
        print(str(e), file=sys.stderr)
        return 1


def interactive(ctx: commands.Ctx, identity: str) -> None:
    cwd: list[str] = []
    syntax = get_syntax(ctx.api)
    if syntax is None:
        syntax, answered = ask_syntax()
        save_syntax(ctx.api, syntax)
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import Completer, Completion
        from prompt_toolkit.history import InMemoryHistory

        class RouterCompleter(Completer):
            def get_completions(self, document, complete_event):
                text = document.text_before_cursor
                last = text.split(" ")[-1]
                if syntax == "linux" and not text.lstrip().startswith("/"):
                    if " " not in text.strip():
                        for word in LINUX_WORDS:
                            if word.startswith(last):
                                yield Completion(word, start_position=-len(last))
                    return
                for word in commands.complete(text, cwd, ctx):
                    yield Completion(word, start_position=-len(last))

        session = PromptSession(history=InMemoryHistory(), completer=RouterCompleter(), complete_while_typing=False)
        read = lambda p: session.prompt(p)
    except ImportError:                                   # без prompt_toolkit — простой ввод
        read = input

    print(BANNER_LINUX if syntax == "linux" else BANNER)
    while True:
        if syntax == "linux":
            prompt = f"{ctx.user}@{identity}:~$ "
        else:
            prompt = f"[{ctx.user}@{identity}] {commands.path_str(cwd)}> " if cwd else f"[{ctx.user}@{identity}] > "
        try:
            line = read(prompt)
        except KeyboardInterrupt:          # Ctrl-C — очистить строку
            continue
        except EOFError:                   # Ctrl-D — выход
            print("quit")
            return
        word = line.strip().lower()
        if word in SWITCH_LINUX + SWITCH_ROUTEROS:
            syntax = "linux" if word in SWITCH_LINUX else "routeros"
            cwd = []
            save_syntax(ctx.api, syntax)
            print(BANNER_LINUX if syntax == "linux" else BANNER)
            continue
        try:
            cwd = run_line(ctx, line, cwd, syntax)
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
