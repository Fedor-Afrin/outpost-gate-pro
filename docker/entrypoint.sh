#!/bin/sh
set -e
echo "[entrypoint] OutpostGate Pro, mode=${ROUTER_MODE}"

# Устройства для VPN: /dev/net/tun (AmneziaWG) и /dev/ppp (L2TP).
# Docker разрешает tun по умолчанию; ppp — через device_cgroup_rules в compose.
mkdir -p /dev/net
[ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200 2>/dev/null || echo "[entrypoint] нет /dev/net/tun — AmneziaWG не заработает"
[ -e /dev/ppp ]     || mknod /dev/ppp c 108 0 2>/dev/null     || echo "[entrypoint] нет /dev/ppp — L2TP не заработает"

# Pro начинался как копия OutpostGate Lite: перенести её настройки, если они есть
# (один раз; свои настройки не перезаписываются)
migrate() {   # $1 — старая папка, $2 — новая
    if [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ] && [ ! -e "$2/.migrated" ] \
       && { [ ! -e "$2/router.yaml" ] && [ ! -e "$2/users.json" ]; }; then
        mkdir -p "$2" && cp -a "$1/." "$2/" && touch "$2/.migrated"
        echo "[entrypoint] настройки перенесены: $1 -> $2"
    fi
}
migrate /etc/outpost-gate-lite /etc/outpost-gate-pro
migrate /var/lib/outpost-gate-lite /var/lib/outpost-gate-pro

# Конфиг по умолчанию — только если своего ещё нет
mkdir -p /etc/outpost-gate-pro /var/lib/outpost-gate-pro
[ -e /etc/outpost-gate-pro/router.yaml ] || cp /usr/share/outpost-gate-pro/router.yaml.default /etc/outpost-gate-pro/router.yaml

# Агент применения конфига запускается внутри API (lifespan в app/main.py):
# DHCP-клиентом, dnsmasq и VPN-процессами владеет долгоживущий процесс.
exec uvicorn app.main:app --loop asyncio --host "${API_HOST}" --port "${API_PORT}" --log-level "${LOG_LEVEL:-info}"
