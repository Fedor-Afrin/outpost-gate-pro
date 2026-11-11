"""Pydantic-схемы для интерфейсов."""
from pydantic import BaseModel


class Interface(BaseModel):
    index: int
    name: str
    mac: str | None = None
    mtu: int | None = None
    state: str            # up / down / unknown
    running: bool         # есть ли линк (флаг R в RouterOS)
    addresses: list[str] = []
    rx_bytes: int = 0
    tx_bytes: int = 0
