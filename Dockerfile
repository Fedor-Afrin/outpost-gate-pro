# Один образ для всех режимов: dev / gns3 / host.
# Режим определяется НЕ здесь, а способом запуска (compose / GNS3).

# --- AmneziaWG: userspace-реализация (модуль ядра не нужен) ---------------------
FROM golang:1-bookworm AS awg-go
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go /src \
    && cd /src && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/amneziawg-go .

# --- AmneziaWG: утилита awg (собирается на той же базе, что и итоговый образ) ---
FROM python:3.12-slim AS awg-tools
RUN apt-get update && apt-get install -y --no-install-recommends build-essential git ca-certificates \
    && git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools /src \
    && make -C /src/src \
    && mkdir -p /out \
    && (cp /src/src/awg /out/awg 2>/dev/null || cp /src/src/wg /out/awg)

# --- итоговый образ -------------------------------------------------------------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 nftables iputils-ping traceroute tcpdump procps busybox \
        ieee-data wireguard-tools \
        kea-dhcp4-server bind9 bind9-utils bind9-dnsutils \
        strongswan-charon strongswan-swanctl xl2tpd ppp \
        frr frr-pythontools \
        samba samba-common-bin samba-vfs-modules fdisk e2fsprogs exfatprogs \
        snmpd chrony conntrack tzdata \
    && rm -rf /var/lib/apt/lists/*

# Zabbix agent: agent 2, если есть в репозитории дистрибутива, иначе классический zabbix_agentd
RUN apt-get update \
    && (apt-get install -y --no-install-recommends zabbix-agent2 \
        || apt-get install -y --no-install-recommends zabbix-agent) \
    && rm -rf /var/lib/apt/lists/*

COPY --from=awg-go /out/amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=awg-tools /out/awg /usr/local/bin/awg

WORKDIR /opt/outpost-gate-pro

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY web/ web/
COPY docker/router.yaml.default /usr/share/outpost-gate-pro/router.yaml.default
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/outpost /usr/local/bin/outpost
RUN chmod +x /entrypoint.sh /usr/local/bin/outpost app/scripts/*.sh \
    && mkdir -p /etc/outpost-gate-pro /var/lib/outpost-gate-pro /var/log/frr \
    && chown frr:frr /var/log/frr

ENV ROUTER_MODE=dev \
    CLI_SSH_PORT=22 \
    PYTHONUNBUFFERED=1 \
    API_HOST=0.0.0.0 \
    API_PORT=8000

EXPOSE 8000 22 161/udp 10050
ENTRYPOINT ["/entrypoint.sh"]
