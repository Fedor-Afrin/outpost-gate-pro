"""Обработчик событий pppd для L2TP (вызывается из ppp-up.sh / ppp-down.sh)."""
import os
import sys

from app.services import vpn

if __name__ == "__main__":
    try:
        vpn.ppp_event(sys.argv[1] if len(sys.argv) > 1 else "", os.environ)
    except Exception as e:  # ошибка хука не должна ронять pppd
        print(f"[vpn] ERROR ppp-hook: {e}", file=sys.stderr)
