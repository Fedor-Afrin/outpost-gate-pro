#!/bin/sh
# Скрипт событий busybox udhcpc: deconfig / bound / renew / leasefail / nak.
# udhcpc передаёт данные аренды в переменных окружения (ip, subnet, router, dns, lease).
# Вся логика — в Python: app/services/wan_hook.py
cd "${ROUTER_HOME:-/opt/outpost-gate-pro}" || exit 1
exec python3 -m app.services.wan_hook "$1"
