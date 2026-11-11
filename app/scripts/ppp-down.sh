#!/bin/sh
# pppd вызывает этот скрипт, когда L2TP-туннель упал.
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
cd /opt/outpost-gate-pro || exit 1
exec python3 -m app.services.vpn_hook down
