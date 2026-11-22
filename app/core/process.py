"""Долгоживущие фоновые процессы (amneziawg-go, charon, xl2tpd, kea-dhcp4, named), которыми управляет роутер."""
from __future__ import annotations

import subprocess
import threading


class ManagedProcess:
    def __init__(self, name: str):
        self.name = name
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(self, cmd: list[str], env: dict | None = None, new_session: bool = False) -> None:
        """new_session=True — запустить в отдельной сессии и группе процессов.
        Нужно для демонов, которые при остановке рассылают SIGTERM всей своей группе
        (smbd/nmbd с --no-process-group): иначе сигнал получает и сам роутер (PID 1)."""
        with self._lock:
            if self.running():
                return
            self._proc = subprocess.Popen(cmd, env=env, start_new_session=new_session)   # вывод — в docker logs
            print(f"[proc] {self.name} запущен (pid {self._proc.pid})")

    def signal(self, sig: int) -> bool:
        """Послать сигнал (SIGHUP — перечитать конфигурацию). False — процесс не запущен."""
        with self._lock:
            if not self.running():
                return False
            self._proc.send_signal(sig)
            return True

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            if self.running():
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait()
                print(f"[proc] {self.name} остановлен")
            self._proc = None
