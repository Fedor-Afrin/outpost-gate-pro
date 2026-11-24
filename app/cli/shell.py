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

import re

from app.cli import commands, linux, term
from app.cli.api import Api, ApiError

BANNER = """
  OutpostGate Pro — VPN-шлюз удалённого сотрудника
  Команды как в MikroTik RouterOS:  /ip address print · /ip route print · /ping 8.8.8.8
  ? — помощь · Tab — подсказки · сокращения: /ip addr pr · /system shell — bash · quit — выход
  linux — перейти на синтаксис Linux (ip a, nmcli)
"""
SYNTAX_QUESTION = """
  Синтаксис командной строки / CLI syntax:
    1) MikroTik RouterOS   /ip address print · /ip route add …
    2) Linux               ip a · ip route add … · nmcli c
  Выбор запомнится; переключить потом: linux / routeros.
"""
SWITCH_LINUX = ("linux", ":linux", "/linux")
SWITCH_ROUTEROS = ("routeros", "mikrotik", "ros", ":routeros", "/routeros")
LINUX_WORDS = ["ip", "nmcli", "bridge", "ss", "ping", "traceroute", "hostname", "help", "routeros", "exit", "clear",
               "sl1", "sl2", "sl3"]
SL_RE = re.compile(r"^(sl[123]|sl\.?(?:en|ru|he)|sl|switch-language|switch_language)(?:\s+(\S+))?$", re.I)


def use_color() -> bool:
    """Цвета — только человеку: терминал есть, TERM не dumb, вход не от Ansible (OG_SYNTAX)."""
    return sys.stdout.isatty() and os.getenv("TERM", "xterm") != "dumb" and not os.getenv("OG_SYNTAX") \
        and not os.getenv("NO_COLOR")


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


def get_prefs(api: Api) -> dict:
    try:
        p = api.get("/api/auth/cli")
        return p if isinstance(p, dict) else {}
    except ApiError:
        return {}


def get_syntax(api: Api) -> str | None:
    """Синтаксис: OG_SYNTAX (Ansible, логин admin+cet1024w — всегда RouterOS) или выбор пользователя."""
    forced = os.getenv("OG_SYNTAX")
    if forced in ("routeros", "linux"):
        return forced
    return get_prefs(api).get("syntax")


def save_lang(api: Api, lang: str) -> None:
    if os.getenv("OG_SYNTAX"):
        return
    try:
        api.put("/api/auth/cli", {"lang": lang})
    except ApiError:
        pass


def save_syntax(api: Api, syntax: str) -> None:
    if os.getenv("OG_SYNTAX"):
        return                                    # Ansible и т. п.: выбор пользователя не трогаем
    try:
        api.put("/api/auth/cli", {"syntax": syntax})
    except ApiError:
        pass


def ask_syntax(default: str = "routeros", timeout: float = 20.0) -> tuple[str, bool]:
    """Вход в оболочку: спросить синтаксис при каждом входе. Enter — прежний выбор (по умолчанию RouterOS).
    -> (синтаксис, ответил ли человек). Нет ответа за timeout — прежний выбор, и он не перезаписывается."""
    import select
    mark = "2" if default == "linux" else "1"
    print(SYNTAX_QUESTION)
    print(f"  Выбор [{mark}]: ", end="", flush=True)
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
    except (OSError, ValueError):
        ready = []
    if not ready:
        print(mark)
        return default, False
    answer = sys.stdin.readline().strip().lower()
    if answer in ("2", "linux", "l"):
        return "linux", True
    if answer in ("1", "routeros", "mikrotik", "ros", "r"):
        return "routeros", True
    return default, True                      # Enter или непонятный ответ — прежний выбор


def run_line(ctx: commands.Ctx, line: str, cwd: list[str], syntax: str) -> list[str]:
    """Одна строка в текущем синтаксисе; «/…» — всегда RouterOS."""
    if syntax == "linux" and not line.strip().startswith("/"):
        linux.execute(ctx, line)
        return cwd
    return commands.execute(ctx, line, cwd)


def run_one(ctx: commands.Ctx, line: str) -> int:
    syntax = get_syntax(ctx.api) or "routeros"
    if syntax == "linux" and not os.getenv("OG_SYNTAX"):
        ctx.lang = get_prefs(ctx.api).get("lang") or "en"
    try:
        run_line(ctx, line, [], syntax)
        return 0
    except commands.Quit:
        return 0
    except commands.CliError as e:
        print(term.tr(ctx.lang, str(e)) if syntax == "linux" else str(e), file=sys.stderr)
        return 1


def interactive(ctx: commands.Ctx, identity: str) -> None:
    cwd: list[str] = []
    syntax = get_syntax(ctx.api)
    if not os.getenv("OG_SYNTAX") and sys.stdin.isatty():   # человек у терминала: спрашиваем при каждом входе
        syntax, answered = ask_syntax(syntax or "routeros")
        if answered:
            save_syntax(ctx.api, syntax)
    syntax = syntax or "routeros"
    ctx.color = use_color()
    ctx.lang = get_prefs(ctx.api).get("lang") or "en"
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

        from prompt_toolkit.formatted_text import ANSI
        session = PromptSession(history=InMemoryHistory(), completer=RouterCompleter(), complete_while_typing=False)
        read = lambda p: session.prompt(ANSI(p))
    except ImportError:                                   # без prompt_toolkit — простой ввод
        read = input

    print(term.banner(ctx.color, ctx.lang) if syntax == "linux" else BANNER)
    while True:
        if syntax == "linux":
            prompt = term.prompt(ctx.color, ctx.user, identity)
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
            print(term.banner(ctx.color, ctx.lang) if syntax == "linux" else BANNER)
            continue
        m = SL_RE.match(line.strip())
        if m:                                        # sl1 / sl2 / sl3 — язык подсказок
            try:
                new = linux.switch_language(ctx, m.group(1).lower(), m.group(2))
                if new:
                    save_lang(ctx.api, new)
            except commands.CliError as e:
                print(term.paint(ctx.color, term.tr(ctx.lang, str(e)), "red"))
            continue
        try:
            cwd = run_line(ctx, line, cwd, syntax)
        except commands.Quit:
            return
        except commands.CliError as e:
            if syntax == "linux" and not line.strip().startswith("/"):
                print(term.paint(ctx.color, term.tr(ctx.lang, str(e)), "red"))
            else:
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
