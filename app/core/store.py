"""
Хранилище конфигурации: router.yaml — единый источник правды.

- чтение/запись YAML под блокировкой (API-запросы идут параллельно);
- атомарная запись: временный файл + rename, файл никогда не бывает «наполовину записан»;
- снимок (snapshot) перед каждым изменением — основа для бэкапов и Safe Mode.
"""
from __future__ import annotations

import copy
import os
import shutil
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from app.core.config import settings

MAX_SNAPSHOTS = 50


class ConfigStore:
    def __init__(self, config_file: str, data_dir: str):
        self.path = Path(config_file)
        self.snapshots_dir = Path(data_dir) / "snapshots"
        self._lock = threading.RLock()

    # --- чтение -------------------------------------------------------------
    def load(self) -> dict[str, Any]:
        with self._lock:
            if not self.path.exists():
                return {}
            with self.path.open(encoding="utf-8") as f:
                return yaml.safe_load(f) or {}

    # --- запись -------------------------------------------------------------
    def save(self, data: dict[str, Any]) -> None:
        with self._lock:
            self._snapshot()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".router.", suffix=".yaml")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
                os.replace(tmp, self.path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise

    def _snapshot(self) -> None:
        if not self.path.exists():
            return
        try:
            self.snapshots_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            shutil.copy2(self.path, self.snapshots_dir / f"router-{stamp}.yaml")
            old = sorted(self.snapshots_dir.glob("router-*.yaml"))[:-MAX_SNAPSHOTS]
            for p in old:
                p.unlink(missing_ok=True)
        except OSError as e:  # снимок не должен ломать основную операцию
            print(f"[store] WARNING: snapshot failed: {e}")

    # --- транзакция ---------------------------------------------------------
    def transaction(self):
        """with store.transaction() as cfg: ...изменить cfg...  -> сохранится при выходе."""
        return _Transaction(self)


class _Transaction:
    def __init__(self, store: ConfigStore):
        self.store = store

    def __enter__(self) -> dict[str, Any]:
        self.store._lock.acquire()
        self.original = self.store.load()
        self.data = copy.deepcopy(self.original)
        return self.data

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None and self.data != self.original:
                self.store.save(self.data)
        finally:
            self.store._lock.release()
        return False


store = ConfigStore(settings.config_file, settings.data_dir)
