"""Чтение/запись sysctl текущего network namespace."""
from pathlib import Path

IP_FORWARD = Path("/proc/sys/net/ipv4/ip_forward")


def get_ip_forward() -> bool:
    try:
        return IP_FORWARD.read_text().strip() == "1"
    except OSError:
        return False


def set_ip_forward(enabled: bool) -> bool:
    try:
        IP_FORWARD.write_text("1" if enabled else "0")
        return True
    except OSError:
        return False
