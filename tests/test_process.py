"""ManagedProcess: демон, который при выходе шлёт SIGTERM своей группе, не должен задевать роутер."""
import os
import signal
import sys
import time

from app.core.process import ManagedProcess

# Так ведёт себя smbd/nmbd с --no-process-group: на SIGTERM он гасит всю свою группу процессов.
KILL_GROUP = (
    "import os, signal, time\n"
    "signal.signal(signal.SIGTERM, lambda *a: (signal.signal(signal.SIGTERM, signal.SIG_IGN), os.killpg(0, signal.SIGTERM), os._exit(0)))\n"
    "time.sleep(30)\n"
)


def test_new_session_isolates_group_kill():
    got = []
    old = signal.signal(signal.SIGTERM, lambda *a: got.append(1))
    try:
        p = ManagedProcess("fake-smbd")
        p.start([sys.executable, "-c", KILL_GROUP], new_session=True)
        time.sleep(0.5)
        assert os.getpgid(p._proc.pid) != os.getpgrp()
        p.stop()
        time.sleep(0.2)
        assert got == []           # роутер SIGTERM не получил
        assert not p.running()
    finally:
        signal.signal(signal.SIGTERM, old)


def test_files_starts_samba_in_own_session():
    from app.services import files
    src = open(files.__file__, encoding="utf-8").read()
    assert src.count("conf], new_session=True)") == 2   # smbd и nmbd
