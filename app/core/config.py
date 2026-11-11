"""Настройки приложения из переменных окружения."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    version: str = "0.2.0"
    # host   — управляет сетью сервера (network_mode: host)
    # gns3   — изолированный контейнер внутри GNS3
    # dev    — разработка на рабочем ПК (свой namespace, хост не трогается)
    mode: str = os.getenv("ROUTER_MODE", "dev")
    config_file: str = os.getenv("ROUTER_CONFIG", "/etc/outpost-gate-pro/router.yaml")
    data_dir: str = os.getenv("ROUTER_DATA", "/var/lib/outpost-gate-pro")
    log_level: str = os.getenv("LOG_LEVEL", "info")


settings = Settings()
