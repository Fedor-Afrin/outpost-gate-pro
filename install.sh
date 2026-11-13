#!/usr/bin/env bash
# =============================================================================
#  install.sh — установка OutpostGate Pro на виртуальную машину или сервер (режим host)
#
#    sudo ./install.sh                 установка: мастер спросит порты WAN / WAN2 / LAN и пароль
#    sudo ./install.sh --update        пересобрать и перезапустить (после update_pro_*.sh)
#    sudo ./install.sh --status        состояние
#    sudo ./install.sh --uninstall     удалить (настройки и данные остаются)
#    sudo ./install.sh --uninstall --purge   удалить вместе с настройками и данными
#    ./install.sh --help               все параметры (установка без вопросов — для Ansible и т. п.)
#
#  Что делает установка:
#    1. ставит Docker (официальный репозиторий) и запрещает ему трогать фаервол (daemon.json:
#       iptables=false) — иначе Docker закрывает транзит (FORWARD DROP);
#    2. убирает выбранные порты из-под netplan/systemd-networkd и NetworkManager —
#       ими управляет роутер (порт SSH, через который вы подключены, не трогается без вашего согласия);
#    3. включает маршрутизацию (ip_forward), модули ядра (WireGuard, L2TP, QoS);
#       снимает FORWARD DROP, оставшийся от Docker, и даёт серверу свои DNS (порт WAN забирает роутер,
#       и DNS провайдера системе больше не приходят — без этого не соберётся образ при обновлении);
#    4. собирает образ, пишет первый /etc/outpost-gate-pro/router.yaml и запускает контейнер.
#  Дальше все настройки — в веб-интерфейсе: http://<адрес LAN>:8000
# =============================================================================
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPLOY="$ROOT/deploy/host"
COMPOSE=(docker compose -f "$DEPLOY/docker-compose.yml" --env-file "$DEPLOY/.env")
P="${OG_PREFIX:-}"              # корень для тестов установщика (обычно пусто)
SYS_NET="${OG_SYS_NET:-/sys/class/net}"
CONF_DIR=$P/etc/outpost-gate-pro
DATA_DIR=$P/var/lib/outpost-gate-pro
STATE="$CONF_DIR/install.state"
IMAGE=outpost-gate-pro:latest
CONTAINER=outpost-gate-pro
NETWORKD_FILE=$P/etc/systemd/network/05-outpost-gate-unmanaged.network
NM_FILE=$P/etc/NetworkManager/conf.d/99-outpost-gate.conf
SYSCTL_FILE=$P/etc/sysctl.d/99-outpost-gate.conf
MODULES_FILE=$P/etc/modules-load.d/outpost-gate.conf
DAEMON_JSON=$P/etc/docker/daemon.json
RESOLVED_FILE=$P/etc/systemd/resolved.conf.d/outpost-gate.conf
MODULES=(wireguard ppp_generic l2tp_ppp pppox sch_htb sch_fq_codel sch_ingress cls_u32 act_police nf_conntrack 8021q)

# --- вывод --------------------------------------------------------------------------------------
if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'; else B= G= Y= R= C= N=; fi
say()  { echo "${C}>>>${N} $*"; }
ok()   { echo "${G}  ✓${N} $*"; }
warn() { echo "${Y}  !${N} $*"; }
die()  { echo "${R}ОШИБКА:${N} $*" >&2; exit 1; }
hr()   { echo "${C}--------------------------------------------------------------------------${N}"; }

# --- параметры ----------------------------------------------------------------------------------
ACTION=install; YES=0; PURGE=0
WAN=""; WAN_MODE=""; WAN_ADDR=""; WAN_GW=""; WAN_DNS=""
WAN2=""; WAN2_MODE=""; WAN2_ADDR=""; WAN2_GW=""; WAN2_DNS=""; MULTIWAN_MODE=""
LAN=""; LAN_ADDR=""; WAN_MGMT=""; PASSWORD=""; PASSWORD_SET=0
API_PORT=""; CLI_PORT=""; IDENTITY=""; KEEP_CONFIG=""; HOST_DNS=""

usage() {
    sed -n '3,9p' "$0" | sed 's/^#  \{0,1\}//'
    cat <<'EOF'

Установка без вопросов (всё, что не задано, — по умолчанию):
  -y, --yes                 не спрашивать; значения по умолчанию
  --wan IF                  порт провайдера (по умолчанию — порт маршрута по умолчанию)
  --wan-mode MODE           none — адрес задаёт система (netplan), dhcp, static
  --wan-address A/M --wan-gateway GW --wan-dns D1,D2     для static
  --wan2 IF [--wan2-mode dhcp|static --wan2-address .. --wan2-gateway ..]   второй провайдер
  --multiwan failover|balance
  --lan IF1,IF2             порты LAN («-» — без LAN); по умолчанию — все остальные, кроме порта SSH
  --lan-address A/M         адрес роутера в LAN (192.168.88.1/24)
  --wan-management yes|no   веб и SSH роутера с WAN (по умолчанию yes, если вы подключены через WAN)
  --password PASS           пароль admin при первом запуске (иначе admin без пароля, вход только из LAN)
  --api-port N  --cli-port N   порты веба (8000) и CLI по SSH (2222)
  --identity NAME           имя роутера
  --keep-config | --new-config   что делать с существующим router.yaml
  --host-dns "D1 D2"        DNS для самого сервера, когда порт WAN у роутера (по умолчанию 1.1.1.1 8.8.8.8)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --update) ACTION=update ;;
        --status) ACTION=status ;;
        --uninstall) ACTION=uninstall ;;
        --purge) PURGE=1 ;;
        -y|--yes) YES=1 ;;
        --wan) WAN="$2"; shift ;;
        --wan-mode) WAN_MODE="$2"; shift ;;
        --wan-address) WAN_ADDR="$2"; shift ;;
        --wan-gateway) WAN_GW="$2"; shift ;;
        --wan-dns) WAN_DNS="$2"; shift ;;
        --wan2) WAN2="$2"; shift ;;
        --wan2-mode) WAN2_MODE="$2"; shift ;;
        --wan2-address) WAN2_ADDR="$2"; shift ;;
        --wan2-gateway) WAN2_GW="$2"; shift ;;
        --wan2-dns) WAN2_DNS="$2"; shift ;;
        --multiwan) MULTIWAN_MODE="$2"; shift ;;
        --lan) LAN="$2"; shift ;;
        --lan-address) LAN_ADDR="$2"; shift ;;
        --wan-management) WAN_MGMT="$2"; shift ;;
        --password) PASSWORD="$2"; PASSWORD_SET=1; shift ;;
        --api-port) API_PORT="$2"; shift ;;
        --cli-port) CLI_PORT="$2"; shift ;;
        --identity) IDENTITY="$2"; shift ;;
        --host-dns) HOST_DNS="${2//,/ }"; shift ;;
        --keep-config) KEEP_CONFIG=yes ;;
        --new-config) KEEP_CONFIG=no ;;
        -h|--help) usage; exit 0 ;;
        *) die "неизвестный параметр $1 (см. --help)" ;;
    esac
    shift
done

# --- вопросы -------------------------------------------------------------------------------------
ask() {   # ask "Вопрос" "по умолчанию" -> REPLY
    local q="$1" def="${2:-}"
    if [[ $YES -eq 1 ]]; then REPLY="$def"; return; fi
    if [[ -n "$def" ]]; then read -rp "  $q [${def}]: " REPLY; else read -rp "  $q: " REPLY; fi
    REPLY="${REPLY:-$def}"
}

yesno() {   # yesno "Вопрос" y|n
    local def="$2" hint
    [[ "$def" == y ]] && hint="Д/н" || hint="д/Н"
    if [[ $YES -eq 1 ]]; then [[ "$def" == y ]]; return; fi
    read -rp "  $1 [$hint]: " REPLY
    REPLY="${REPLY:-$def}"
    [[ "${REPLY,,}" =~ ^(y|yes|д|да)$ ]]
}

in_list() { local x="$1" item; shift; for item in "$@"; do [[ "$item" == "$x" ]] && return 0; done; return 1; }

# --- проверки -----------------------------------------------------------------------------------
preflight() {
    [[ $EUID -eq 0 || -n "$P" ]] || die "запустите через sudo: sudo $0"
    [[ -f "$DEPLOY/docker-compose.yml" && -f "$ROOT/Dockerfile" ]] || die "запускайте из папки проекта OutpostGate Pro"
    [[ -e /.dockerenv && -z "$P" ]] && die "это контейнер — установка нужна на виртуальной машине или сервере"
    command -v systemctl >/dev/null || die "нужен systemd"
    command -v python3 >/dev/null || { say "Ставлю python3"; apt-get update -qq && apt-get install -y -qq python3 >/dev/null; }
    # shellcheck disable=SC1091
    . "$P/etc/os-release"
    OS_ID="$ID"; OS_CODENAME="${VERSION_CODENAME:-}"
    case "$OS_ID" in
        ubuntu|debian) ok "система: $PRETTY_NAME" ;;
        *) warn "система $PRETTY_NAME не проверялась (рассчитано на Ubuntu 22.04/24.04 и Debian 12/13)"
           yesno "Продолжить?" n || exit 1 ;;
    esac
}

# --- интерфейсы ----------------------------------------------------------------------------------
list_ifaces() {
    local n
    for p in "$SYS_NET"/*; do
        n=${p##*/}
        case "$n" in lo|docker*|veth*|br-*|virbr*|wg*|awg*|tun*|tap*|l2tp*|ppp*|vnet*|dummy*|ifb*|*.*) continue ;; esac
        [[ -e "$p/device" || "$n" == en* || "$n" == eth* || "$n" == usb* ]] || continue
        echo "$n"
    done
}

ssh_ifaces() {   # интерфейсы, через которые сейчас идут SSH-сессии к серверу
    local addrs a
    addrs=$(ss -Htn state established 2>/dev/null | awk '{print $3}' | grep -E ":(${HOST_SSH_PORT:-22})$" \
        | sed -e 's/:[0-9]*$//' -e 's/^\[::ffff://' -e 's/^\[//' -e 's/\]$//' | sort -u || true)
    [[ -n "${SSH_CONNECTION:-}" ]] && addrs+=$'\n'"$(echo "$SSH_CONNECTION" | awk '{print $3}')"
    for a in $addrs; do
        ip -4 -o addr show 2>/dev/null | awk -v ip="$a" '{split($4,x,"/"); if (x[1]==ip) print $2}'
    done | sort -u
}

default_iface() { ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}'; }
iface_ipv4() { ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4}' | paste -sd, -; }
host_ssh_port() { sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' || true; }

show_ifaces() {
    local i=0 flags n
    printf "  ${B}%-3s %-14s %-7s %-18s %-20s %s${N}\n" "#" "Порт" "Линк" "MAC" "IPv4" ""
    for n in "${IFACES[@]}"; do
        i=$((i + 1)); flags=""
        in_list "$n" "${SSH_IFS[@]}" && flags+="${Y}← вы подключены по SSH${N} "
        [[ "$n" == "$DEF_IF" ]] && flags+="(маршрут по умолчанию)"
        printf "  %-3s %-14s %-7s %-18s %-20s %s\n" "$i" "$n" "$(cat "$SYS_NET/$n/operstate" 2>/dev/null)" \
            "$(cat "$SYS_NET/$n/address" 2>/dev/null)" "$(iface_ipv4 "$n")" "$flags"
    done
}

pick_iface() {   # pick_iface "вопрос" "по умолчанию" -> IFACE ("" — нет)
    ask "$1" "$2"
    local v="$REPLY"
    [[ "$v" == "-" || -z "$v" ]] && { IFACE=""; return; }
    [[ "$v" =~ ^[0-9]+$ && $v -ge 1 && $v -le ${#IFACES[@]} ]] && v="${IFACES[$((v - 1))]}"
    in_list "$v" "${IFACES[@]}" || die "нет порта $v"
    IFACE="$v"
}

check_cidr() { python3 -c "import ipaddress,sys; ipaddress.ip_interface(sys.argv[1])" "$1" 2>/dev/null; }

# --- мастер --------------------------------------------------------------------------------------
wizard() {
    mapfile -t IFACES < <(list_ifaces)
    [[ ${#IFACES[@]} -ge 1 ]] || die "не найдено ни одного сетевого порта"
    HOST_SSH_PORT=$(host_ssh_port); HOST_SSH_PORT=${HOST_SSH_PORT:-22}
    mapfile -t SSH_IFS < <(ssh_ifaces)
    DEF_IF=$(default_iface)
    hr; say "Сетевые порты сервера"; show_ifaces; hr
    [[ ${#IFACES[@]} -lt 2 ]] && warn "один порт: роутер будет без LAN — для проверки добавьте ВМ второй сетевой адаптер"

    ask "Имя роутера" "${IDENTITY:-$(hostname -s)}"; IDENTITY="$REPLY"

    # WAN
    if [[ -z "$WAN" ]]; then pick_iface "Порт WAN (провайдер; номер или имя)" "${DEF_IF:-${IFACES[0]}}"; WAN="$IFACE"; fi
    in_list "$WAN" "${IFACES[@]}" || die "нет порта $WAN"
    local wan_ssh=0; in_list "$WAN" "${SSH_IFS[@]}" && wan_ssh=1
    if [[ -z "$WAN_MODE" ]]; then
        echo "  Как настраивать адрес WAN:"
        echo "    none   — оставить системе (netplan/DHCP сервера): безопасно, если вы подключены через этот порт"
        echo "    dhcp   — роутер сам получает адрес (DHCP-клиент роутера)"
        echo "    static — вручную"
        local def=dhcp
        [[ $wan_ssh -eq 1 || -n "$(iface_ipv4 "$WAN")" ]] && def=none
        ask "Режим WAN" "$def"; WAN_MODE="$REPLY"
    fi
    [[ "$WAN_MODE" =~ ^(none|dhcp|static)$ ]] || die "режим WAN: none, dhcp или static"
    if [[ "$WAN_MODE" == static ]]; then
        [[ -n "$WAN_ADDR" ]] || { ask "IP-адрес WAN с маской" "$(iface_ipv4 "$WAN" | cut -d, -f1)"; WAN_ADDR="$REPLY"; }
        [[ -n "$WAN_GW" ]] || { ask "Шлюз провайдера" "$(ip -4 route show default dev "$WAN" 2>/dev/null | awk '{print $3; exit}')"; WAN_GW="$REPLY"; }
        [[ -n "$WAN_DNS" ]] || { ask "DNS (через запятую)" "1.1.1.1,8.8.8.8"; WAN_DNS="$REPLY"; }
    fi
    if [[ $wan_ssh -eq 1 && "$WAN_MODE" != none ]]; then
        warn "вы подключены через $WAN: при смене режима адрес может поменяться и SSH отвалится"
        yesno "Всё равно отдать адрес $WAN роутеру?" n || WAN_MODE=none
    fi

    # WAN2
    local rest=() n
    for n in "${IFACES[@]}"; do [[ "$n" != "$WAN" ]] && rest+=("$n"); done
    if [[ -z "$WAN2" && $YES -eq 0 && ${#rest[@]} -ge 2 ]]; then
        ask "Второй провайдер WAN2 (порт; Enter — нет)" ""
        WAN2="$REPLY"
        [[ "$WAN2" =~ ^[0-9]+$ ]] && WAN2="${IFACES[$((WAN2 - 1))]:-}"
    fi
    if [[ -n "$WAN2" ]]; then
        in_list "$WAN2" "${rest[@]}" || die "WAN2: нет свободного порта $WAN2"
        [[ -n "$WAN2_MODE" ]] || { ask "Режим WAN2 (dhcp / static)" dhcp; WAN2_MODE="$REPLY"; }
        [[ "$WAN2_MODE" =~ ^(dhcp|static)$ ]] || die "режим WAN2: dhcp или static"
        if [[ "$WAN2_MODE" == static ]]; then
            [[ -n "$WAN2_ADDR" ]] || { ask "IP-адрес WAN2 с маской" ""; WAN2_ADDR="$REPLY"; }
            [[ -n "$WAN2_GW" ]] || { ask "Шлюз WAN2" ""; WAN2_GW="$REPLY"; }
        fi
        [[ -n "$MULTIWAN_MODE" ]] || { ask "Два провайдера: failover (резерв) или balance (балансировка)" failover; MULTIWAN_MODE="$REPLY"; }
        [[ "$MULTIWAN_MODE" =~ ^(failover|balance)$ ]] || die "режим: failover или balance"
        local r2=(); for n in "${rest[@]}"; do [[ "$n" != "$WAN2" ]] && r2+=("$n"); done; rest=("${r2[@]}")
    fi

    # LAN
    if [[ -z "$LAN" ]]; then
        local def=() n
        for n in "${rest[@]}"; do in_list "$n" "${SSH_IFS[@]}" || def+=("$n"); done
        local d; d=$(IFS=,; echo "${def[*]}"); [[ -z "$d" ]] && d="-"
        ask "Порты LAN (через запятую; «-» — без LAN)" "$d"; LAN="$REPLY"
    fi
    LAN_PORTS=()
    if [[ "$LAN" != "-" && -n "$LAN" ]]; then
        IFS=, read -ra parts <<<"$LAN"
        for n in "${parts[@]}"; do
            n=$(echo "$n" | xargs)
            [[ "$n" =~ ^[0-9]+$ ]] && n="${IFACES[$((n - 1))]:-}"
            in_list "$n" "${rest[@]}" || die "LAN: порт $n занят WAN или не существует"
            LAN_PORTS+=("$n")
        done
    fi
    for n in "${LAN_PORTS[@]}"; do
        if in_list "$n" "${SSH_IFS[@]}"; then
            warn "вы подключены через $n: в LAN-мосте он потеряет свой адрес, SSH отвалится"
            warn "дальше заходить надо будет из LAN: http://<адрес LAN>:8000"
            yesno "Всё равно отдать $n в LAN?" n || die "уберите $n из LAN и запустите снова"
        fi
    done
    [[ -n "$LAN_ADDR" ]] || { ask "Адрес роутера в LAN" "192.168.88.1/24"; LAN_ADDR="$REPLY"; }
    check_cidr "$LAN_ADDR" || die "адрес LAN: например 192.168.88.1/24"

    # управление с WAN
    if [[ -z "$WAN_MGMT" ]]; then
        local def=n; in_list "$WAN" "${SSH_IFS[@]}" && def=y
        [[ -n "$WAN2" ]] && in_list "$WAN2" "${SSH_IFS[@]}" && def=y
        echo "  Управление с WAN: веб (порт ${API_PORT:-8000}), CLI (SSH ${CLI_PORT:-2222}) и SSH сервера ($HOST_SSH_PORT)"
        echo "  будут доступны со стороны провайдера. Для ВМ в домашней сети это обычно нужно."
        if yesno "Открыть управление с WAN?" "$def"; then WAN_MGMT=yes; else WAN_MGMT=no; fi
    fi
    if [[ "$WAN_MGMT" == no ]] && in_list "$WAN" "${SSH_IFS[@]}"; then
        warn "вы подключены через WAN ($WAN), а управление с WAN закрыто: SSH к серверу отвалится после запуска"
        yesno "Оставить закрытым?" n || WAN_MGMT=yes
    fi

    API_PORT=${API_PORT:-8000}; CLI_PORT=${CLI_PORT:-2222}
    if [[ $YES -eq 0 && $PASSWORD_SET -eq 0 && ! -s "$CONF_DIR/users.json" ]]; then
        echo "  Пароль admin (не короче 8 символов). Enter — без пароля: тогда войти можно только из LAN."
        local p2
        while true; do
            read -rsp "  Пароль: " PASSWORD; echo
            [[ -z "$PASSWORD" ]] && break
            [[ ${#PASSWORD} -ge 8 ]] || { warn "не короче 8 символов"; continue; }
            read -rsp "  Ещё раз: " p2; echo
            [[ "$PASSWORD" == "$p2" ]] && break
            warn "пароли не совпали"
        done
    fi
    [[ -n "$PASSWORD" && ${#PASSWORD} -lt 8 ]] && die "пароль — не короче 8 символов"
    [[ "$PASSWORD" == *"'"* || "$PASSWORD" == *'$'* ]] && die "в пароле нельзя использовать ' и \$ (задайте такой пароль потом в вебе)"
    if [[ -z "$PASSWORD" && "$WAN_MGMT" == yes && ! -s "$CONF_DIR/users.json" ]]; then
        warn "admin без пароля входит только из LAN — через WAN войти не получится, пока не зададите пароль"
    fi

    hr; say "Итог"
    echo "  Имя:            $IDENTITY"
    echo "  WAN:            $WAN ($WAN_MODE${WAN_ADDR:+, $WAN_ADDR via $WAN_GW})"
    [[ -n "$WAN2" ]] && echo "  WAN2:           $WAN2 ($WAN2_MODE${WAN2_ADDR:+, $WAN2_ADDR via $WAN2_GW}), режим $MULTIWAN_MODE"
    echo "  LAN:            ${LAN_PORTS[*]:-нет} — роутер $LAN_ADDR, DHCP и DNS для LAN"
    echo "  Управление:     с WAN — $WAN_MGMT; веб :$API_PORT, CLI ssh -p $CLI_PORT admin@…"
    echo "  Пароль admin:   $([[ -n "$PASSWORD" ]] && echo задан || echo 'нет (вход из LAN)')"
    hr
    yesno "Устанавливаем?" y || exit 0
}

# --- Docker --------------------------------------------------------------------------------------
install_docker() {
    if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
        ok "Docker $(docker --version | awk '{print $3}' | tr -d ,) и compose уже есть"
    else
        say "Ставлю Docker (официальный репозиторий)"
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg >/dev/null
        install -m 0755 -d /etc/apt/keyrings
        if curl -fsSL "https://download.docker.com/linux/$OS_ID/gpg" -o /etc/apt/keyrings/docker.asc; then
            chmod a+r /etc/apt/keyrings/docker.asc
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$OS_ID $OS_CODENAME stable" \
                > /etc/apt/sources.list.d/docker.list
            apt-get update -qq
            apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null \
                || { warn "репозиторий Docker не сработал — ставлю из репозитория дистрибутива"; rm -f /etc/apt/sources.list.d/docker.list
                     apt-get update -qq; apt-get install -y -qq docker.io docker-compose-v2 >/dev/null 2>&1 \
                         || apt-get install -y -qq docker.io docker-compose >/dev/null 2>&1 || true; }
        else
            warn "нет доступа к download.docker.com — ставлю из репозитория дистрибутива"
            apt-get update -qq
            apt-get install -y -qq docker.io docker-compose-v2 >/dev/null 2>&1 \
                || apt-get install -y -qq docker.io docker-compose >/dev/null 2>&1 || true
        fi
        docker compose version >/dev/null 2>&1 || die "не удалось поставить docker compose"
        ok "Docker установлен"
    fi
    systemctl enable --now docker >/dev/null 2>&1 || true
}

configure_docker() {
    # Docker не должен трогать фаервол: его FORWARD DROP закрывает транзит роутера
    mkdir -p "$(dirname "$DAEMON_JSON")" "$CONF_DIR"
    local changed
    changed=$(python3 - "$DAEMON_JSON" "$CONF_DIR/daemon.json.orig" <<'EOF'
import json, os, shutil, sys
path, orig = sys.argv[1], sys.argv[2]
cur = {}
if os.path.exists(path):
    try:
        cur = json.load(open(path))
    except ValueError:
        sys.exit("daemon.json испорчен — исправьте вручную")
    if not os.path.exists(orig):
        shutil.copy2(path, orig)
elif not os.path.exists(orig):
    open(orig, "w").write("")            # пустой: файла не было
new = {**cur, "iptables": False, "ip6tables": False}
if new != cur:
    json.dump(new, open(path, "w"), indent=2)
    print("yes")
EOF
)
    if [[ "$changed" == yes ]]; then
        local others
        others=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -vx "$CONTAINER" || true)
        if [[ -n "$others" ]]; then
            warn "на сервере работают другие контейнеры: $(echo $others)"
            warn "без iptables у Docker их проброшенные порты и выход в интернет через NAT Docker перестанут работать"
            yesno "Продолжить?" y || die "отменено"
        fi
        systemctl restart docker
        ok "Docker больше не трогает фаервол (daemon.json: iptables=false)"
    else
        ok "Docker уже настроен (iptables=false)"
    fi
    docker_forward_open
}

docker_forward_open() {
    # Docker с iptables=false новых правил не ставит, но уже поставленные живут до перезагрузки:
    # политика FORWARD DROP режет транзит LAN -> WAN (роутер сам пингует, клиенты — нет)
    local t
    for t in iptables ip6tables; do
        command -v "$t" >/dev/null 2>&1 || continue
        if "$t" -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP'; then
            "$t" -P FORWARD ACCEPT && ok "$t: снята политика FORWARD DROP, оставшаяся от Docker"
        fi
    done
}

host_dns() {
    # порт WAN у роутера: DNS провайдера системе (systemd-resolved) могут больше не приходить —
    # тогда сервер не находит registry-1.docker.io и образ не собирается. Свои DNS — всегда, это безопасно:
    # resolved спрашивает и их, и DNS порта, если они есть
    [[ -n "$WAN" ]] || { rm -f "$RESOLVED_FILE"; return 0; }
    systemctl is-active -q systemd-resolved || return 0
    local dns=${HOST_DNS:-"1.1.1.1 8.8.8.8"}
    mkdir -p "$(dirname "$RESOLVED_FILE")"
    local new
    new=$(printf '%s\n' "# OutpostGate Pro: DNS самого сервера — порт WAN у роутера (удаляется install.sh --uninstall)" \
        "[Resolve]" "DNS=$dns" "FallbackDNS=9.9.9.9")
    if [[ "$(cat "$RESOLVED_FILE" 2>/dev/null)" != "$new" ]]; then
        echo "$new" > "$RESOLVED_FILE"
        systemctl restart systemd-resolved || true
    fi
    ok "DNS сервера: $dns"
}

# --- сеть сервера --------------------------------------------------------------------------------
host_network() {
    say "Сеть сервера"
    mkdir -p "$(dirname "$MODULES_FILE")" "$(dirname "$SYSCTL_FILE")"
    : > "$MODULES_FILE"
    local m
    for m in "${MODULES[@]}"; do
        modprobe "$m" 2>/dev/null && echo "$m" >> "$MODULES_FILE" || true
    done
    ok "модули ядра: $(paste -sd' ' "$MODULES_FILE")"

    cat > "$SYSCTL_FILE" <<'EOF'
# OutpostGate Pro: маршрутизатор
net.ipv4.ip_forward = 1
# два провайдера: ответы могут приходить не тем каналом, которым ушёл запрос
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
    if [[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
        # мосты LAN не должны прогонять кадры через iptables/nftables (иначе фаервол режет трафик внутри LAN)
        printf '%s\n' "net.bridge.bridge-nf-call-iptables = 0" "net.bridge.bridge-nf-call-ip6tables = 0" \
            "net.bridge.bridge-nf-call-arptables = 0" >> "$SYSCTL_FILE"
    fi
    sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
    ok "ip_forward=1, rp_filter=2"

    # порты, которыми управляет роутер, — не трогает ни netplan/networkd, ни NetworkManager
    MANAGED=("${LAN_PORTS[@]}")
    [[ "$WAN_MODE" != none ]] && MANAGED+=("$WAN")
    [[ -n "$WAN2" ]] && MANAGED+=("$WAN2")
    if [[ ${#MANAGED[@]} -gt 0 ]]; then
        if systemctl is-active -q systemd-networkd; then
            mkdir -p "$(dirname "$NETWORKD_FILE")"
            cat > "$NETWORKD_FILE" <<EOF
# OutpostGate Pro: этими портами управляет роутер (удаляется install.sh --uninstall)
[Match]
Name=${MANAGED[*]}

[Link]
Unmanaged=yes
EOF
            networkctl reload >/dev/null 2>&1 || systemctl restart systemd-networkd
            ok "systemd-networkd (netplan) больше не управляет: ${MANAGED[*]}"
        fi
        if systemctl is-active -q NetworkManager; then
            mkdir -p "$(dirname "$NM_FILE")"
            { echo "# OutpostGate Pro: этими портами управляет роутер"; echo "[keyfile]"
              echo "unmanaged-devices=$(printf 'interface-name:%s;' "${MANAGED[@]}")"; } > "$NM_FILE"
            nmcli general reload >/dev/null 2>&1 || systemctl reload NetworkManager || true
            ok "NetworkManager больше не управляет: ${MANAGED[*]}"
        fi
        for m in "${MANAGED[@]}"; do
            in_list "$m" "${SSH_IFS[@]}" && continue          # свой SSH не рвём — адрес уберёт роутер
            ip -4 addr flush dev "$m" 2>/dev/null || true      # адреса, оставшиеся от DHCP системы
            ip link set "$m" up 2>/dev/null || true
        done
    fi
    host_dns
}

# --- конфигурация --------------------------------------------------------------------------------
write_env() {
    local tz
    tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC)
    umask 077
    cat > "$DEPLOY/.env" <<EOF
# OutpostGate Pro: параметры запуска (пишет install.sh)
API_PORT=$API_PORT
CLI_SSH_PORT=$CLI_PORT
HOST_SSH_PORT=$HOST_SSH_PORT
TZ=$tz
EOF
    if [[ -n "$PASSWORD" && ! -s "$CONF_DIR/users.json" ]]; then
        printf "ROUTER_ADMIN_PASSWORD='%s'\n" "$PASSWORD" >> "$DEPLOY/.env"
    fi
    umask 022
    TZ_HOST="$tz"
}

build_image() {
    say "Собираю образ (первый раз — несколько минут)"
    "${COMPOSE[@]}" build
    ok "образ $IMAGE готов"
}

write_config() {
    mkdir -p "$CONF_DIR" "$DATA_DIR"
    if [[ -s "$CONF_DIR/router.yaml" ]]; then
        if [[ -z "$KEEP_CONFIG" ]]; then
            warn "уже есть $CONF_DIR/router.yaml"
            if yesno "Оставить его (иначе — новый из ответов мастера, старый уйдёт в копию)?" y; then KEEP_CONFIG=yes; else KEEP_CONFIG=no; fi
        fi
        if [[ "$KEEP_CONFIG" == yes ]]; then ok "router.yaml оставлен как есть"; return; fi
        cp -a "$CONF_DIR/router.yaml" "$CONF_DIR/router.yaml.before-install-$(date +%Y%m%d-%H%M%S)"
    fi
    local json
    json=$(IDENTITY="$IDENTITY" TZ_HOST="$TZ_HOST" WAN="$WAN" WAN_MODE="$WAN_MODE" WAN_ADDR="$WAN_ADDR" WAN_GW="$WAN_GW" \
        WAN_DNS="$WAN_DNS" WAN2="$WAN2" WAN2_MODE="$WAN2_MODE" WAN2_ADDR="$WAN2_ADDR" WAN2_GW="$WAN2_GW" \
        WAN2_DNS="$WAN2_DNS" MULTIWAN_MODE="$MULTIWAN_MODE" LAN_PORTS="${LAN_PORTS[*]}" LAN_ADDR="$LAN_ADDR" \
        WAN_MGMT="$WAN_MGMT" python3 - <<'EOF'
import json, os
e = os.environ
lst = lambda s: [x.strip() for x in (s or "").replace(";", ",").split(",") if x.strip()]
wan = {"interface": e["WAN"], "mode": e["WAN_MODE"], "dns": lst(e.get("WAN_DNS"))}
if e["WAN_MODE"] == "static":
    wan.update(address=e["WAN_ADDR"], gateway=e["WAN_GW"])
wan2 = None
if e.get("WAN2"):
    wan2 = {"interface": e["WAN2"], "mode": e["WAN2_MODE"], "dns": lst(e.get("WAN2_DNS"))}
    if e["WAN2_MODE"] == "static":
        wan2.update(address=e["WAN2_ADDR"], gateway=e["WAN2_GW"])
print(json.dumps({"identity": e["IDENTITY"], "timezone": e.get("TZ_HOST") or None, "wan": wan, "wan2": wan2,
                  "multiwan_mode": e.get("MULTIWAN_MODE") or "failover",
                  "lan": {"address": e["LAN_ADDR"], "ports": e["LAN_PORTS"].split(),
                          "wan_management": e["WAN_MGMT"] == "yes"}}))
EOF
)
    local tmp="$CONF_DIR/.router.yaml.new"
    if ! docker run --rm --network none --entrypoint python3 "$IMAGE" -m app.scripts.initconfig "$json" > "$tmp"; then
        rm -f "$tmp"; die "не удалось собрать router.yaml (см. сообщение выше)"
    fi
    mv "$tmp" "$CONF_DIR/router.yaml"
    ok "записан $CONF_DIR/router.yaml"
}

save_state() {
    cat > "$STATE" <<EOF
# что поставил install.sh — для --update и --uninstall
INSTALLED=$(date -Iseconds)
ROOT=$ROOT
WAN=$WAN
WAN2=$WAN2
LAN_PORTS="${LAN_PORTS[*]}"
LAN_ADDR=$LAN_ADDR
API_PORT=$API_PORT
CLI_PORT=$CLI_PORT
WAN_MGMT=$WAN_MGMT
WAN_MODE=$WAN_MODE
HOST_DNS="$HOST_DNS"
EOF
}

# --- запуск --------------------------------------------------------------------------------------
wait_healthy() {
    local port="$1" i
    for i in $(seq 1 90); do
        if python3 -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:$port/api/system/health', timeout=2)" 2>/dev/null; then
            return 0
        fi
        sleep 2
    done
    return 1
}

start() {
    say "Запускаю"
    if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
        docker rm -f "$CONTAINER" >/dev/null      # старый контейнер (в т.ч. от ручного запуска)
    fi
    "${COMPOSE[@]}" up -d --force-recreate
    if wait_healthy "$API_PORT"; then
        ok "роутер запущен"
    else
        docker logs --tail 40 "$CONTAINER" 2>&1 | sed 's/^/    /'
        die "роутер не ответил за 3 минуты — см. журнал выше и: docker logs $CONTAINER"
    fi
    sed -i '/^ROUTER_ADMIN_PASSWORD=/d' "$DEPLOY/.env"        # пароль нужен только для первого запуска
}

summary() {
    local lan_ip=${LAN_ADDR%/*} wan_ip
    wan_ip=$(iface_ipv4 "$WAN" | cut -d, -f1); wan_ip=${wan_ip%/*}
    hr
    echo "${G}${B}OutpostGate Pro установлен.${N}"
    [[ ${#LAN_PORTS[@]} -gt 0 ]] && echo "  Веб из LAN:   http://$lan_ip:$API_PORT"
    [[ "$WAN_MGMT" == yes && -n "$wan_ip" ]] && echo "  Веб с WAN:    http://$wan_ip:$API_PORT"
    echo "  CLI:          ssh -p $CLI_PORT admin@${lan_ip}"
    echo "  Журнал:       docker logs -f $CONTAINER"
    echo "  Обновление:   скрипт update_pro_*.sh в $ROOT, затем  sudo ./install.sh --update"
    echo "  Удаление:     sudo ./install.sh --uninstall   (настройки остаются в $CONF_DIR и $DATA_DIR)"
    if [[ -z "$PASSWORD" && $HAD_USERS -eq 0 ]]; then
        echo "  ${Y}Задайте пароль admin:${N} веб → плашка «Пароль не задан» (вход без пароля — только из LAN)"
    fi
    hr
}

# --- действия ------------------------------------------------------------------------------------
do_install() {
    preflight
    hr; echo "${B}OutpostGate Pro — установка на сервер${N}"; hr
    install_docker
    HAD_USERS=0; [[ -s "$CONF_DIR/users.json" ]] && HAD_USERS=1
    wizard
    configure_docker
    write_env
    build_image
    write_config
    host_network
    save_state
    start
    summary
}

load_state() {
    [[ -f "$STATE" ]] || die "роутер не установлен этим скриптом (нет $STATE)"
    # shellcheck disable=SC1090
    . "$STATE"
    read -ra LAN_PORTS <<<"$LAN_PORTS"
}

do_update() {
    [[ $EUID -eq 0 ]] || die "запустите через sudo"
    local cli_dns=$HOST_DNS
    load_state
    [[ -n "$cli_dns" ]] && HOST_DNS=$cli_dns          # sudo ./install.sh --update --host-dns "..."
    [[ -f "$DEPLOY/.env" ]] || die "нет $DEPLOY/.env — запустите установку заново"
    if [[ -z "$WAN_MODE" ]]; then                    # установлено до появления WAN_MODE в install.state
        WAN_MODE=dhcp
        grep -qsE "^Name=(.* )?$WAN( |\$)|interface-name:$WAN;" "$NETWORKD_FILE" "$NM_FILE" || WAN_MODE=none
    fi
    sed -i '/^WAN_MODE=/d;/^HOST_DNS=/d' "$STATE"
    printf 'WAN_MODE=%s\nHOST_DNS="%s"\n' "$WAN_MODE" "$HOST_DNS" >> "$STATE"
    docker_forward_open
    host_dns
    say "Обновляю: пересборка образа и перезапуск"
    "${COMPOSE[@]}" build
    "${COMPOSE[@]}" up -d --force-recreate
    wait_healthy "$API_PORT" && ok "роутер работает" || die "роутер не ответил — docker logs $CONTAINER"
    docker image prune -f >/dev/null 2>&1 || true
}

do_status() {
    if [[ -f "$STATE" ]]; then load_state; echo "  Установлен: $INSTALLED, из $ROOT"; fi
    docker ps -a --filter "name=^${CONTAINER}$" --format '  Контейнер: {{.Names}} — {{.Status}}' 2>/dev/null || echo "  Docker недоступен"
    if [[ -n "${API_PORT:-}" ]] && wait_healthy_once "$API_PORT"; then ok "API отвечает на :$API_PORT"; else warn "API не отвечает"; fi
    echo "  Порты под управлением роутера: $(grep -h '^Name=' "$NETWORKD_FILE" 2>/dev/null | cut -d= -f2 || echo —)"
}

wait_healthy_once() {
    python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$1/api/system/health', timeout=2)" 2>/dev/null
}

do_uninstall() {
    [[ $EUID -eq 0 ]] || die "запустите через sudo"
    [[ -f "$STATE" ]] && load_state
    warn "будут удалены: контейнер, настройки сети сервера от роутера, правила daemon.json"
    [[ $PURGE -eq 1 ]] && warn "и ВСЕ настройки и данные роутера: $CONF_DIR, $DATA_DIR"
    [[ $YES -eq 1 ]] || yesno "Удалить OutpostGate Pro?" n || exit 0
    if [[ $PURGE -eq 1 && $YES -eq 0 ]]; then
        read -rp "  Для удаления данных введите purge: " REPLY
        [[ "$REPLY" == purge ]] || die "отменено"
    fi
    if [[ -f "$DEPLOY/.env" ]]; then "${COMPOSE[@]}" down 2>/dev/null || true; fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    nft delete table inet outpost_gate_pro 2>/dev/null || true
    nft delete table inet outpost_acct 2>/dev/null || true
    for t in 101 102; do ip route flush table "$t" 2>/dev/null || true; done
    for p in $(seq 1000 1039); do ip rule del pref "$p" 2>/dev/null || true; done
    if [[ -f "$NETWORKD_FILE" ]]; then rm -f "$NETWORKD_FILE"; networkctl reload >/dev/null 2>&1 || systemctl restart systemd-networkd || true; fi
    if [[ -f "$NM_FILE" ]]; then rm -f "$NM_FILE"; nmcli general reload >/dev/null 2>&1 || true; fi
    rm -f "$SYSCTL_FILE" "$MODULES_FILE"
    if [[ -f "$RESOLVED_FILE" ]]; then rm -f "$RESOLVED_FILE"; systemctl restart systemd-resolved 2>/dev/null || true; fi
    if [[ -f "$CONF_DIR/daemon.json.orig" ]]; then
        if [[ -s "$CONF_DIR/daemon.json.orig" ]]; then cp -a "$CONF_DIR/daemon.json.orig" "$DAEMON_JSON"; else rm -f "$DAEMON_JSON"; fi
        rm -f "$CONF_DIR/daemon.json.orig"
        systemctl restart docker || true
        ok "daemon.json возвращён как был"
    fi
    rm -f "$STATE" "$DEPLOY/.env"
    if [[ $PURGE -eq 1 ]]; then
        rm -rf "$CONF_DIR" "$DATA_DIR"
        docker image rm "$IMAGE" >/dev/null 2>&1 || true
        ok "настройки и данные удалены"
    fi
    ok "OutpostGate Pro удалён. Порты снова под управлением netplan/NetworkManager (перезагрузка сервера вернёт всё начисто)"
}

case "$ACTION" in
    install) do_install ;;
    update) do_update ;;
    status) do_status ;;
    uninstall) do_uninstall ;;
esac
