#!/bin/sh
# pppd вызывает этот скрипт, когда L2TP-туннель поднялся (IFNAME, IPLOCAL, IPREMOTE, DNS1, DNS2).
# pppd очищает окружение, поэтому пути — полные.
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
cd /opt/outpost-gate-pro || exit 1
exec python3 -m app.services.vpn_hook up
