#!/usr/bin/env bash
# =============================================================================
#  install.sh — install OutpostGate Pro on a virtual machine or a server (host mode)
#
#    sudo ./install.sh                 install: the wizard asks for the WAN / WAN2 / LAN ports and a password
#    sudo ./install.sh --update        update to the new version and restart
#    sudo ./install.sh --status        status
#    sudo ./install.sh --uninstall     remove (the settings and data are kept)
#    sudo ./install.sh --uninstall --purge   remove together with the settings and data
#    ./install.sh --help               all options (unattended install for Ansible etc.)
#
#  What the installation does:
#    1. installs Docker (official repository) and stops it from touching the firewall (daemon.json:
#       iptables=false); otherwise Docker blocks transit traffic (FORWARD DROP);
#    2. takes the selected ports away from netplan/systemd-networkd and NetworkManager:
#       the router manages them (the SSH port you are connected through is not touched without asking);
#    3. enables routing (ip_forward) and the kernel modules (WireGuard, L2TP, GRE, QoS);
#       clears a FORWARD DROP left by Docker and gives the server its own DNS (the router takes the WAN
#       port, so the provider's DNS no longer reaches the system; without it updates cannot download);
#    4. builds or downloads the image, writes the first /etc/outpost-gate-pro/router.yaml, starts the container.
#  After that, everything is configured in the web UI: http://<LAN address>  (port 80; another one: --api-port)
# =============================================================================
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPLOY="$ROOT/deploy/host"
COMPOSE=(docker compose -f "$DEPLOY/docker-compose.yml" --env-file "$DEPLOY/.env")
P="${OG_PREFIX:-}"              # root for installer tests (normally empty)
SYS_NET="${OG_SYS_NET:-/sys/class/net}"
CONF_DIR=$P/etc/outpost-gate-pro
DATA_DIR=$P/var/lib/outpost-gate-pro
STATE="$CONF_DIR/install.state"
IMAGE=outpost-gate-pro:latest
CONTAINER=outpost-gate-pro
DEFAULT_REMOTE=ghcr.io/fedor-afrin/outpost-gate-pro:latest
REMOTE_IMAGE="${OG_IMAGE:-}"   # set: download this ready image (GHCR) instead of building it here
INSTALLER="${OG_INSTALLER:-script}"
DOCKER_RESTART=now                     # later: restart_docker() handed it to systemd   # script | container (the installer image sets it)
NETWORKD_FILE=$P/etc/systemd/network/05-outpost-gate-unmanaged.network
NM_FILE=$P/etc/NetworkManager/conf.d/99-outpost-gate.conf
SYSCTL_FILE=$P/etc/sysctl.d/99-outpost-gate.conf
MODULES_FILE=$P/etc/modules-load.d/outpost-gate.conf
DAEMON_JSON=$P/etc/docker/daemon.json
RESOLVED_FILE=$P/etc/systemd/resolved.conf.d/outpost-gate.conf
MODULES=(wireguard ip_gre ppp_generic l2tp_ppp pppox sch_htb sch_fq_codel sch_ingress cls_u32 act_police nf_conntrack 8021q)

# --- output --------------------------------------------------------------------------------------
if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'; else B= G= Y= R= C= N=; fi
say()  { echo "${C}>>>${N} $*"; }
ok()   { echo "${G}  ✓${N} $*"; }
warn() { echo "${Y}  !${N} $*"; }
die()  { echo "${R}ERROR:${N} $*" >&2; exit 1; }
hr()   { echo "${C}--------------------------------------------------------------------------${N}"; }

# --- options ----------------------------------------------------------------------------------
ACTION=install; YES=0; PURGE=0
WAN=""; WAN_MODE=""; WAN_ADDR=""; WAN_GW=""; WAN_DNS=""
WAN2=""; WAN2_MODE=""; WAN2_ADDR=""; WAN2_GW=""; WAN2_DNS=""; MULTIWAN_MODE=""
LAN=""; LAN_ADDR=""; WAN_MGMT=""; PASSWORD=""; PASSWORD_SET=0
API_PORT=""; CLI_PORT=""; IDENTITY=""; KEEP_CONFIG=""; HOST_DNS=""

usage() {
    sed -n '3,9p' "$0" | sed -e 's/^#//' -e 's/^  //'
    cat <<'EOF'

Unattended install (anything not given uses the default):
  -y, --yes                 do not ask; use the defaults
  --wan IF                  provider port (default: the port of the default route)
  --wan-mode MODE           none: the system (netplan) sets the address; dhcp; static
  --wan-address A/M --wan-gateway GW --wan-dns D1,D2     for static
  --wan2 IF [--wan2-mode dhcp|static --wan2-address .. --wan2-gateway ..]   second provider
  --multiwan failover|balance
  --lan IF1,IF2             LAN ports ("-" = no LAN); default: all others except the SSH port
  --lan-address A/M         router address in the LAN (192.168.88.1/24)
  --wan-management yes|no   router web UI and SSH from WAN (default yes if you are connected via WAN)
  --password PASS           admin password for the first start (otherwise admin has no password, login from LAN only)
  --api-port N  --cli-port N   web UI port (80) and SSH CLI port (2222); with --update: change the web port
  --identity NAME           router name
  --keep-config | --new-config   what to do with an existing router.yaml
  --image REF               download a ready image instead of building (ghcr.io/fedor-afrin/outpost-gate-pro:latest)
  --host-dns "D1 D2"        DNS for the server itself while the router owns the WAN port (default 1.1.1.1 8.8.8.8)
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
        --image) REMOTE_IMAGE="$2"; shift ;;
        --keep-config) KEEP_CONFIG=yes ;;
        --new-config) KEEP_CONFIG=no ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option $1 (see --help)" ;;
    esac
    shift
done

# --- questions -------------------------------------------------------------------------------------
ask() {   # ask "Question" "default" -> REPLY
    local q="$1" def="${2:-}"
    if [[ $YES -eq 1 ]]; then REPLY="$def"; return; fi
    if [[ -n "$def" ]]; then read -rp "  $q [${def}]: " REPLY; else read -rp "  $q: " REPLY; fi
    REPLY="${REPLY:-$def}"
}

yesno() {   # yesno "Question" y|n
    local def="$2" hint
    [[ "$def" == y ]] && hint="Y/n" || hint="y/N"
    if [[ $YES -eq 1 ]]; then [[ "$def" == y ]]; return; fi
    read -rp "  $1 [$hint]: " REPLY
    REPLY="${REPLY:-$def}"
    [[ "${REPLY,,}" =~ ^(y|yes)$ ]]
}

in_list() { local x="$1" item; shift; for item in "$@"; do [[ "$item" == "$x" ]] && return 0; done; return 1; }

# --- checks -----------------------------------------------------------------------------------
preflight() {
    [[ $EUID -eq 0 || -n "$P" ]] || die "run it with sudo: sudo $0"
    [[ -f "$ROOT/Dockerfile" || -n "$REMOTE_IMAGE" ]] || REMOTE_IMAGE=$DEFAULT_REMOTE   # no sources: use GHCR
    [[ -f "$DEPLOY/docker-compose.yml" ]] || die "run it from the OutpostGate Pro project folder"
    [[ -e /.dockerenv && -z "$P" ]] && die "this is a container: install on a virtual machine or a server"
    command -v systemctl >/dev/null || die "systemd is required"
    command -v python3 >/dev/null || { say "Installing python3"; apt-get update -qq && apt-get install -y -qq python3 >/dev/null; }
    # shellcheck disable=SC1091
    . "$P/etc/os-release"
    OS_ID="$ID"; OS_CODENAME="${VERSION_CODENAME:-}"
    case "$OS_ID" in
        ubuntu|debian) ok "system: $PRETTY_NAME" ;;
        *) warn "$PRETTY_NAME has not been tested (made for Ubuntu 22.04/24.04 and Debian 12/13)"
           yesno "Continue?" n || exit 1 ;;
    esac
}

# --- interfaces ----------------------------------------------------------------------------------
list_ifaces() {
    local n
    for p in "$SYS_NET"/*; do
        n=${p##*/}
        case "$n" in lo|docker*|veth*|br-*|virbr*|wg*|awg*|tun*|tap*|l2tp*|ppp*|vnet*|dummy*|ifb*|*.*) continue ;; esac
        [[ -e "$p/device" || "$n" == en* || "$n" == eth* || "$n" == usb* ]] || continue
        echo "$n"
    done
}

ssh_ifaces() {   # interfaces that current SSH sessions to the server come through
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
    printf "  ${B}%-3s %-14s %-7s %-18s %-20s %s${N}\n" "#" "Port" "Link" "MAC" "IPv4" ""
    for n in "${IFACES[@]}"; do
        i=$((i + 1)); flags=""
        in_list "$n" "${SSH_IFS[@]}" && flags+="${Y}<- your SSH session${N} "
        [[ "$n" == "$DEF_IF" ]] && flags+="(default route)"
        printf "  %-3s %-14s %-7s %-18s %-20s %s\n" "$i" "$n" "$(cat "$SYS_NET/$n/operstate" 2>/dev/null)" \
            "$(cat "$SYS_NET/$n/address" 2>/dev/null)" "$(iface_ipv4 "$n")" "$flags"
    done
}

pick_iface() {   # pick_iface "question" "default" -> IFACE ("" = none)
    ask "$1" "$2"
    local v="$REPLY"
    [[ "$v" == "-" || -z "$v" ]] && { IFACE=""; return; }
    [[ "$v" =~ ^[0-9]+$ && $v -ge 1 && $v -le ${#IFACES[@]} ]] && v="${IFACES[$((v - 1))]}"
    in_list "$v" "${IFACES[@]}" || die "no such port: $v"
    IFACE="$v"
}

check_cidr() { python3 -c "import ipaddress,sys; ipaddress.ip_interface(sys.argv[1])" "$1" 2>/dev/null; }

# --- wizard --------------------------------------------------------------------------------------
wizard() {
    mapfile -t IFACES < <(list_ifaces)
    [[ ${#IFACES[@]} -ge 1 ]] || die "no network ports found"
    HOST_SSH_PORT=$(host_ssh_port); HOST_SSH_PORT=${HOST_SSH_PORT:-22}
    mapfile -t SSH_IFS < <(ssh_ifaces)
    DEF_IF=$(default_iface)
    hr; say "Server network ports"; show_ifaces; hr
    [[ ${#IFACES[@]} -lt 2 ]] && warn "only one port: the router will have no LAN; to test, add a second network adapter to the VM"

    ask "Router name" "${IDENTITY:-$(hostname -s)}"; IDENTITY="$REPLY"

    # WAN
    if [[ -z "$WAN" ]]; then pick_iface "WAN port (provider; number or name)" "${DEF_IF:-${IFACES[0]}}"; WAN="$IFACE"; fi
    in_list "$WAN" "${IFACES[@]}" || die "no such port: $WAN"
    local wan_ssh=0; in_list "$WAN" "${SSH_IFS[@]}" && wan_ssh=1
    if [[ -z "$WAN_MODE" ]]; then
        echo "  How to configure the WAN address:"
        echo "    none   - leave it to the system (netplan/server DHCP): safe if you are connected through this port"
        echo "    dhcp   - the router gets the address itself (router DHCP client)"
        echo "    static - set by hand"
        local def=dhcp
        [[ $wan_ssh -eq 1 || -n "$(iface_ipv4 "$WAN")" ]] && def=none
        ask "WAN mode" "$def"; WAN_MODE="$REPLY"
    fi
    [[ "$WAN_MODE" =~ ^(none|dhcp|static)$ ]] || die "WAN mode: none, dhcp or static"
    if [[ "$WAN_MODE" == static ]]; then
        [[ -n "$WAN_ADDR" ]] || { ask "WAN IP address with mask" "$(iface_ipv4 "$WAN" | cut -d, -f1)"; WAN_ADDR="$REPLY"; }
        [[ -n "$WAN_GW" ]] || { ask "Provider gateway" "$(ip -4 route show default dev "$WAN" 2>/dev/null | awk '{print $3; exit}')"; WAN_GW="$REPLY"; }
        [[ -n "$WAN_DNS" ]] || { ask "DNS (comma-separated)" "1.1.1.1,8.8.8.8"; WAN_DNS="$REPLY"; }
    fi
    if [[ $wan_ssh -eq 1 && "$WAN_MODE" != none ]]; then
        warn "you are connected through $WAN: if the mode changes, the address may change and SSH will drop"
        yesno "Give the $WAN address to the router anyway?" n || WAN_MODE=none
    fi

    # WAN2
    local rest=() n
    for n in "${IFACES[@]}"; do [[ "$n" != "$WAN" ]] && rest+=("$n"); done
    if [[ -z "$WAN2" && $YES -eq 0 && ${#rest[@]} -ge 2 ]]; then
        ask "Second provider WAN2 (port; Enter = none)" ""
        WAN2="$REPLY"
        [[ "$WAN2" =~ ^[0-9]+$ ]] && WAN2="${IFACES[$((WAN2 - 1))]:-}"
    fi
    if [[ -n "$WAN2" ]]; then
        in_list "$WAN2" "${rest[@]}" || die "WAN2: no free port $WAN2"
        [[ -n "$WAN2_MODE" ]] || { ask "WAN2 mode (dhcp / static)" dhcp; WAN2_MODE="$REPLY"; }
        [[ "$WAN2_MODE" =~ ^(dhcp|static)$ ]] || die "WAN2 mode: dhcp or static"
        if [[ "$WAN2_MODE" == static ]]; then
            [[ -n "$WAN2_ADDR" ]] || { ask "WAN2 IP address with mask" ""; WAN2_ADDR="$REPLY"; }
            [[ -n "$WAN2_GW" ]] || { ask "WAN2 gateway" ""; WAN2_GW="$REPLY"; }
        fi
        [[ -n "$MULTIWAN_MODE" ]] || { ask "Two providers: failover or balance" failover; MULTIWAN_MODE="$REPLY"; }
        [[ "$MULTIWAN_MODE" =~ ^(failover|balance)$ ]] || die "mode: failover or balance"
        local r2=(); for n in "${rest[@]}"; do [[ "$n" != "$WAN2" ]] && r2+=("$n"); done; rest=("${r2[@]}")
    fi

    # LAN
    if [[ -z "$LAN" ]]; then
        local def=() n
        for n in "${rest[@]}"; do in_list "$n" "${SSH_IFS[@]}" || def+=("$n"); done
        local d; d=$(IFS=,; echo "${def[*]}"); [[ -z "$d" ]] && d="-"
        ask "LAN ports (comma-separated; \"-\" = no LAN)" "$d"; LAN="$REPLY"
    fi
    LAN_PORTS=()
    if [[ "$LAN" != "-" && -n "$LAN" ]]; then
        IFS=, read -ra parts <<<"$LAN"
        for n in "${parts[@]}"; do
            n=$(echo "$n" | xargs)
            [[ "$n" =~ ^[0-9]+$ ]] && n="${IFACES[$((n - 1))]:-}"
            in_list "$n" "${rest[@]}" || die "LAN: port $n is used by WAN or does not exist"
            LAN_PORTS+=("$n")
        done
    fi
    for n in "${LAN_PORTS[@]}"; do
        if in_list "$n" "${SSH_IFS[@]}"; then
            warn "you are connected through $n: in the LAN bridge it loses its address and SSH will drop"
            warn "after that, connect from the LAN: http://<LAN address>"
            yesno "Put $n into the LAN anyway?" n || die "remove $n from the LAN and run again"
        fi
    done
    [[ -n "$LAN_ADDR" ]] || { ask "Router address in the LAN" "192.168.88.1/24"; LAN_ADDR="$REPLY"; }
    check_cidr "$LAN_ADDR" || die "LAN address: for example 192.168.88.1/24"

    # management from WAN
    if [[ -z "$WAN_MGMT" ]]; then
        local def=n; in_list "$WAN" "${SSH_IFS[@]}" && def=y
        [[ -n "$WAN2" ]] && in_list "$WAN2" "${SSH_IFS[@]}" && def=y
        echo "  Management from WAN: web UI (port ${API_PORT:-80}), CLI (SSH ${CLI_PORT:-2222}) and server SSH ($HOST_SSH_PORT)"
        echo "  will be reachable from the provider side. For a VM in a home network this is usually needed."
        if yesno "Allow management from WAN?" "$def"; then WAN_MGMT=yes; else WAN_MGMT=no; fi
    fi
    if [[ "$WAN_MGMT" == no ]] && in_list "$WAN" "${SSH_IFS[@]}"; then
        warn "you are connected via WAN ($WAN) but management from WAN is closed: SSH to the server will drop after the start"
        yesno "Keep it closed?" n || WAN_MGMT=yes
    fi

    if [[ -z "$API_PORT" ]]; then                     # web UI on 80; if busy (nginx, apache...), 8000
        API_PORT=80
        if port_busy 80; then warn "port 80 is busy on the server: the web UI will be on 8000 (another one: --api-port N)"; API_PORT=8000; fi
    fi
    CLI_PORT=${CLI_PORT:-2222}
    if [[ $YES -eq 0 && $PASSWORD_SET -eq 0 && ! -s "$CONF_DIR/users.json" ]]; then
        echo "  admin password (at least 8 characters). Enter = no password: then you can log in from the LAN only."
        local p2
        while true; do
            read -rsp "  Password: " PASSWORD; echo
            [[ -z "$PASSWORD" ]] && break
            [[ ${#PASSWORD} -ge 8 ]] || { warn "at least 8 characters"; continue; }
            read -rsp "  Again: " p2; echo
            [[ "$PASSWORD" == "$p2" ]] && break
            warn "the passwords do not match"
        done
    fi
    [[ -n "$PASSWORD" && ${#PASSWORD} -lt 8 ]] && die "the password must be at least 8 characters"
    [[ "$PASSWORD" == *"'"* || "$PASSWORD" == *'$'* ]] && die "the password cannot contain ' or \$ (set such a password later in the web UI)"
    if [[ -z "$PASSWORD" && "$WAN_MGMT" == yes && ! -s "$CONF_DIR/users.json" ]]; then
        warn "admin without a password can log in from the LAN only; login via WAN works after you set a password"
    fi

    hr; say "Summary"
    echo "  Name:           $IDENTITY"
    echo "  WAN:            $WAN ($WAN_MODE${WAN_ADDR:+, $WAN_ADDR via $WAN_GW})"
    [[ -n "$WAN2" ]] && echo "  WAN2:           $WAN2 ($WAN2_MODE${WAN2_ADDR:+, $WAN2_ADDR via $WAN2_GW}), mode $MULTIWAN_MODE"
    echo "  LAN:            ${LAN_PORTS[*]:-none}, router $LAN_ADDR, DHCP and DNS for the LAN"
    echo "  Management:     from WAN: $WAN_MGMT; web :$API_PORT, CLI ssh -p $CLI_PORT admin@..."
    echo "  admin password: $([[ -n "$PASSWORD" ]] && echo set || echo 'none (login from LAN)')"
    hr
    yesno "Install now?" y || exit 0
}

# --- Docker --------------------------------------------------------------------------------------
install_docker() {
    if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
        ok "Docker $(docker --version | awk '{print $3}' | tr -d ,) and compose are installed"
    else
        say "Installing Docker (official repository)"
        apt-get update -qq
        apt-get install -y -qq ca-certificates curl gnupg >/dev/null
        install -m 0755 -d /etc/apt/keyrings
        if curl -fsSL "https://download.docker.com/linux/$OS_ID/gpg" -o /etc/apt/keyrings/docker.asc; then
            chmod a+r /etc/apt/keyrings/docker.asc
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$OS_ID $OS_CODENAME stable" \
                > /etc/apt/sources.list.d/docker.list
            apt-get update -qq
            apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null \
                || { warn "the Docker repository failed, installing from the distribution repository"; rm -f /etc/apt/sources.list.d/docker.list
                     apt-get update -qq; apt-get install -y -qq docker.io docker-compose-v2 >/dev/null 2>&1 \
                         || apt-get install -y -qq docker.io docker-compose >/dev/null 2>&1 || true; }
        else
            warn "download.docker.com is not reachable, installing from the distribution repository"
            apt-get update -qq
            apt-get install -y -qq docker.io docker-compose-v2 >/dev/null 2>&1 \
                || apt-get install -y -qq docker.io docker-compose >/dev/null 2>&1 || true
        fi
        docker compose version >/dev/null 2>&1 || die "could not install docker compose"
        ok "Docker installed"
    fi
    systemctl enable --now docker >/dev/null 2>&1 || true
}

restart_docker() {
    # The installer container lives inside Docker: "systemctl restart docker" stops it and kills
    # this script halfway. In that mode the restart is handed to the host's systemd and runs
    # a few seconds after the installer has finished.
    if [[ "$INSTALLER" == container ]]; then
        if systemd-run --quiet --collect --on-active=5 /bin/systemctl restart docker 2>/dev/null; then
            DOCKER_RESTART=later
            return 0
        fi
        warn "systemd-run is not available; Docker restarts now and this installer window closes"
        warn "run the same command again afterwards: the installer continues from where it stopped"
    fi
    systemctl restart docker
}

other_containers() {
    # running containers except the router and the installer container itself (OG_SELF = its ID)
    docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null \
        | awk -v me="${OG_SELF:-none}" -v c="$CONTAINER" 'index($1, me) != 1 && $2 != c {print $2}'
}

configure_docker() {
    # Docker must not touch the firewall: its FORWARD DROP blocks the router's transit traffic
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
        sys.exit("daemon.json is broken, fix it by hand")
    if not os.path.exists(orig):
        shutil.copy2(path, orig)
elif not os.path.exists(orig):
    open(orig, "w").write("")            # empty: there was no file
new = {**cur, "iptables": False, "ip6tables": False}
if new != cur:
    json.dump(new, open(path, "w"), indent=2)
    print("yes")
EOF
)
    if [[ "$changed" == yes ]]; then
        local others
        others=$(other_containers)
        if [[ -n "$others" ]]; then
            warn "other containers are running on this server: $(echo $others)"
            warn "without Docker iptables, their published ports and internet access through Docker NAT stop working"
            yesno "Continue?" y || die "cancelled"
        fi
        restart_docker
        if [[ "$DOCKER_RESTART" == later ]]; then
            ok "daemon.json: iptables=false (Docker restarts when the installer has finished)"
        else
            ok "Docker no longer touches the firewall (daemon.json: iptables=false)"
        fi
    else
        ok "Docker is already configured (iptables=false)"
    fi
    docker_forward_open
}

docker_forward_open() {
    # with iptables=false Docker adds no new rules, but the existing ones live until a reboot:
    # a FORWARD DROP policy cuts LAN -> WAN transit (the router itself can ping, clients cannot)
    local t
    for t in iptables ip6tables; do
        command -v "$t" >/dev/null 2>&1 || continue
        if "$t" -S FORWARD 2>/dev/null | grep -qx -- '-P FORWARD DROP'; then
            "$t" -P FORWARD ACCEPT && ok "$t: cleared the FORWARD DROP policy left by Docker"
        fi
    done
}

host_dns() {
    # the router owns the WAN port: the provider's DNS may no longer reach systemd-resolved,
    # and then the server cannot resolve registry-1.docker.io. Our own DNS servers are always safe:
    # resolved asks both them and the port's DNS, if any
    [[ -n "$WAN" ]] || { rm -f "$RESOLVED_FILE"; return 0; }
    systemctl is-active -q systemd-resolved || return 0
    local dns=${HOST_DNS:-"1.1.1.1 8.8.8.8"}
    mkdir -p "$(dirname "$RESOLVED_FILE")"
    local new
    new=$(printf '%s\n' "# OutpostGate Pro: DNS of the server itself, the WAN port belongs to the router (removed by install.sh --uninstall)" \
        "[Resolve]" "DNS=$dns" "FallbackDNS=9.9.9.9")
    if [[ "$(cat "$RESOLVED_FILE" 2>/dev/null)" != "$new" ]]; then
        echo "$new" > "$RESOLVED_FILE"
        systemctl restart systemd-resolved || true
    fi
    ok "server DNS: $dns"
}

# --- server network --------------------------------------------------------------------------------
load_modules() {
    # kernel modules for VPN, GRE and QoS; the list also goes to autoload (after a server reboot)
    mkdir -p "$(dirname "$MODULES_FILE")"
    : > "$MODULES_FILE"
    local m
    for m in "${MODULES[@]}"; do
        modprobe "$m" 2>/dev/null && echo "$m" >> "$MODULES_FILE" || true
    done
    ok "kernel modules: $(paste -sd' ' "$MODULES_FILE")"
}

host_network() {
    say "Server network"
    mkdir -p "$(dirname "$SYSCTL_FILE")"
    load_modules

    cat > "$SYSCTL_FILE" <<'EOF'
# OutpostGate Pro: router
net.ipv4.ip_forward = 1
# two providers: replies may arrive on another link than the request left by
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
    if [[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
        # LAN bridges must not pass frames through iptables/nftables (otherwise the firewall cuts traffic inside the LAN)
        printf '%s\n' "net.bridge.bridge-nf-call-iptables = 0" "net.bridge.bridge-nf-call-ip6tables = 0" \
            "net.bridge.bridge-nf-call-arptables = 0" >> "$SYSCTL_FILE"
    fi
    sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
    ok "ip_forward=1, rp_filter=2"

    # ports managed by the router: neither netplan/networkd nor NetworkManager touches them
    MANAGED=("${LAN_PORTS[@]}")
    [[ "$WAN_MODE" != none ]] && MANAGED+=("$WAN")
    [[ -n "$WAN2" ]] && MANAGED+=("$WAN2")
    if [[ ${#MANAGED[@]} -gt 0 ]]; then
        if systemctl is-active -q systemd-networkd; then
            mkdir -p "$(dirname "$NETWORKD_FILE")"
            cat > "$NETWORKD_FILE" <<EOF
# OutpostGate Pro: the router manages these ports (removed by install.sh --uninstall)
[Match]
Name=${MANAGED[*]}

[Link]
Unmanaged=yes
EOF
            networkctl reload >/dev/null 2>&1 || systemctl restart systemd-networkd
            ok "systemd-networkd (netplan) no longer manages: ${MANAGED[*]}"
        fi
        if systemctl is-active -q NetworkManager; then
            mkdir -p "$(dirname "$NM_FILE")"
            { echo "# OutpostGate Pro: the router manages these ports"; echo "[keyfile]"
              echo "unmanaged-devices=$(printf 'interface-name:%s;' "${MANAGED[@]}")"; } > "$NM_FILE"
            nmcli general reload >/dev/null 2>&1 || systemctl reload NetworkManager || true
            ok "NetworkManager no longer manages: ${MANAGED[*]}"
        fi
        for m in "${MANAGED[@]}"; do
            in_list "$m" "${SSH_IFS[@]}" && continue          # do not break our own SSH, the router removes the address
            ip -4 addr flush dev "$m" 2>/dev/null || true      # addresses left over from the system's DHCP
            ip link set "$m" up 2>/dev/null || true
        done
    fi
    host_dns
}

# --- configuration --------------------------------------------------------------------------------
write_env() {
    local tz
    tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo UTC)
    umask 077
    cat > "$DEPLOY/.env" <<EOF
# OutpostGate Pro: run parameters (written by install.sh)
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
    if [[ -n "$REMOTE_IMAGE" ]]; then
        say "Downloading the image $REMOTE_IMAGE"
    else
        say "Building the image (a few minutes the first time)"
    fi
    get_image
    ok "image $IMAGE is ready"
}

get_image() {
    if [[ -n "$REMOTE_IMAGE" ]]; then
        # a ready image from GHCR (amd64 or arm64: Docker picks the right one)
        docker pull "$REMOTE_IMAGE" && docker tag "$REMOTE_IMAGE" "$IMAGE"
    else
        # Build on the server's own network (--network host): with iptables=false Docker has no NAT for the
        # temporary build containers, and they could not reach github.com / deb.debian.org
        docker build --network host -t "$IMAGE" "$ROOT"
    fi
}

update_hint() {   # how to update / remove, depending on how the router was installed
    local act=${1:---update}
    if [[ "$INSTALLER" == container ]]; then
        echo "docker run --pull=always --rm -it --privileged --pid=host ghcr.io/fedor-afrin/outpost-gate-pro-installer:latest $act"
    elif [[ "$act" == --update ]]; then
        echo "git pull in $ROOT, then  sudo ./install.sh --update"
    else
        echo "sudo ./install.sh $act"
    fi
}

write_config() {
    mkdir -p "$CONF_DIR" "$DATA_DIR"
    if [[ -s "$CONF_DIR/router.yaml" ]]; then
        if [[ -z "$KEEP_CONFIG" ]]; then
            warn "$CONF_DIR/router.yaml already exists"
            if yesno "Keep it (otherwise a new one is made from your answers and the old one is backed up)?" y; then KEEP_CONFIG=yes; else KEEP_CONFIG=no; fi
        fi
        if [[ "$KEEP_CONFIG" == yes ]]; then ok "router.yaml kept as is"; return; fi
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
        rm -f "$tmp"; die "could not create router.yaml (see the message above)"
    fi
    mv "$tmp" "$CONF_DIR/router.yaml"
    ok "wrote $CONF_DIR/router.yaml"
}

save_state() {
    cat > "$STATE" <<EOF
# what install.sh installed, for --update and --uninstall
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
REMOTE_IMAGE=$REMOTE_IMAGE
INSTALLER=$INSTALLER
EOF
}

# --- start --------------------------------------------------------------------------------------
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
    say "Starting"
    if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
        docker rm -f "$CONTAINER" >/dev/null      # old container (including one started by hand)
    fi
    "${COMPOSE[@]}" up -d --force-recreate --no-build
    if wait_healthy "$API_PORT"; then
        ok "the router is running"
    else
        docker logs --tail 40 "$CONTAINER" 2>&1 | sed 's/^/    /'
        die "the router did not answer within 3 minutes; see the log above and: docker logs $CONTAINER"
    fi
    sed -i '/^ROUTER_ADMIN_PASSWORD=/d' "$DEPLOY/.env"        # the password is needed only for the first start
}

summary() {
    local lan_ip=${LAN_ADDR%/*} wan_ip
    wan_ip=$(iface_ipv4 "$WAN" | cut -d, -f1); wan_ip=${wan_ip%/*}
    hr
    echo "${G}${B}OutpostGate Pro is installed.${N}"
    [[ ${#LAN_PORTS[@]} -gt 0 ]] && echo "  Web from LAN: $(web_url "$lan_ip")"
    [[ "$WAN_MGMT" == yes && -n "$wan_ip" ]] && echo "  Web from WAN: $(web_url "$wan_ip")"
    echo "  CLI:          ssh -p $CLI_PORT admin@${lan_ip}"
    echo "  Log:          docker logs -f $CONTAINER"
    echo "  Update:       $(update_hint)"
    echo "  Remove:       $(update_hint --uninstall)   (settings stay in $CONF_DIR and $DATA_DIR)"
    if [[ -z "$PASSWORD" && $HAD_USERS -eq 0 ]]; then
        echo "  ${Y}Set the admin password:${N} web UI -> \"Password not set\" banner (login without a password works from the LAN only)"
    fi
    hr
}

docker_restart_note() {
    [[ "$DOCKER_RESTART" == later ]] || return 0
    echo "  ${Y}Docker restarts in a few seconds${N} (daemon.json changed); the router container comes back by itself."
}

# --- actions ------------------------------------------------------------------------------------
do_install() {
    preflight
    hr; echo "${B}OutpostGate Pro: server installation${N}"; hr
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
    docker_restart_note
}

port_busy() {
    # something already listens on the TCP port (except the router itself: we restart its container)
    local p=$1 line
    line=$(ss -ltnpH "sport = :$p" 2>/dev/null) || return 1
    [[ -n "$line" ]] && ! grep -q "uvicorn" <<<"$line"
}

web_url() {
    if [[ "${API_PORT:-80}" == 80 ]]; then echo "http://$1"; else echo "http://$1:$API_PORT"; fi
}

load_state() {
    [[ -f "$STATE" ]] || die "the router was not installed by this script ($STATE is missing)"
    # shellcheck disable=SC1090
    . "$STATE"
    read -ra LAN_PORTS <<<"$LAN_PORTS"
    ROOT=${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
    if [[ -f "$ROOT/deploy/host/.env" ]]; then      # the router was installed from another folder
        DEPLOY="$ROOT/deploy/host"
        COMPOSE=(docker compose -f "$DEPLOY/docker-compose.yml" --env-file "$DEPLOY/.env")
    else
        ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    fi
}

do_update() {
    [[ $EUID -eq 0 ]] || die "run it with sudo"
    local cli_dns=$HOST_DNS cli_port=$API_PORT cli_image=$REMOTE_IMAGE cli_inst=$INSTALLER
    load_state
    [[ -n "$cli_image" ]] && REMOTE_IMAGE=$cli_image      # sudo ./install.sh --update --image ...
    [[ "$cli_inst" == container ]] && INSTALLER=container
    [[ -f "$ROOT/Dockerfile" || -n "$REMOTE_IMAGE" ]] || REMOTE_IMAGE=$DEFAULT_REMOTE
    [[ -n "$cli_dns" ]] && HOST_DNS=$cli_dns          # sudo ./install.sh --update --host-dns "..."
    [[ -f "$DEPLOY/.env" ]] || die "$DEPLOY/.env is missing; run the installation again"
    if [[ -n "$cli_port" && "$cli_port" != "$API_PORT" ]]; then   # sudo ./install.sh --update --api-port 80
        [[ "$cli_port" =~ ^[0-9]+$ ]] && (( cli_port >= 1 && cli_port <= 65535 )) || die "--api-port: a number 1-65535"
        port_busy "$cli_port" && die "port $cli_port is already busy on the server: $(ss -ltnpH "sport = :$cli_port" | head -1)"
        say "Web UI: port $API_PORT -> $cli_port"
        API_PORT=$cli_port
        sed -i "s/^API_PORT=.*/API_PORT=$API_PORT/" "$DEPLOY/.env" "$STATE"
    fi
    if [[ -z "$WAN_MODE" ]]; then                    # installed before install.state had WAN_MODE
        WAN_MODE=dhcp
        grep -qsE "^Name=(.* )?$WAN( |\$)|interface-name:$WAN;" "$NETWORKD_FILE" "$NM_FILE" || WAN_MODE=none
    fi
    sed -i '/^WAN_MODE=/d;/^HOST_DNS=/d;/^REMOTE_IMAGE=/d;/^INSTALLER=/d' "$STATE"
    printf 'WAN_MODE=%s\nHOST_DNS="%s"\nREMOTE_IMAGE=%s\nINSTALLER=%s\n' "$WAN_MODE" "$HOST_DNS" "$REMOTE_IMAGE" "$INSTALLER" >> "$STATE"
    load_modules                                     # new modules (for example ip_gre) without reinstalling
    docker_forward_open
    host_dns
    say "Updating: new image and restart"
    get_image
    "${COMPOSE[@]}" up -d --force-recreate --no-build
    wait_healthy "$API_PORT" && ok "the router is running" || die "the router did not answer: docker logs $CONTAINER"
    local lan_ip=${LAN_ADDR%/*}
    [[ -n "$lan_ip" ]] && echo "  Web:          $(web_url "$lan_ip")"
    docker image prune -f >/dev/null 2>&1 || true
}

do_status() {
    if [[ -f "$STATE" ]]; then load_state; echo "  Installed: $INSTALLED, from $ROOT"; fi
    docker ps -a --filter "name=^${CONTAINER}$" --format '  Container: {{.Names}}: {{.Status}}' 2>/dev/null || echo "  Docker is not available"
    if [[ -n "${API_PORT:-}" ]] && wait_healthy_once "$API_PORT"; then ok "the API answers on :$API_PORT"; else warn "the API does not answer"; fi
    echo "  Ports managed by the router: $(grep -h '^Name=' "$NETWORKD_FILE" 2>/dev/null | cut -d= -f2 || echo -)"
}

wait_healthy_once() {
    python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$1/api/system/health', timeout=2)" 2>/dev/null
}

do_uninstall() {
    [[ $EUID -eq 0 ]] || die "run it with sudo"
    [[ -f "$STATE" ]] && load_state
    warn "to be removed: the container, the router's server network settings, the daemon.json rules"
    [[ $PURGE -eq 1 ]] && warn "and ALL router settings and data: $CONF_DIR, $DATA_DIR"
    [[ $YES -eq 1 ]] || yesno "Remove OutpostGate Pro?" n || exit 0
    if [[ $PURGE -eq 1 && $YES -eq 0 ]]; then
        read -rp "  To delete the data, type purge: " REPLY
        [[ "$REPLY" == purge ]] || die "cancelled"
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
        restart_docker || true
        ok "daemon.json restored"
    fi
    rm -f "$STATE" "$DEPLOY/.env"
    if [[ $PURGE -eq 1 ]]; then
        rm -rf "$CONF_DIR" "$DATA_DIR"
        docker image rm "$IMAGE" >/dev/null 2>&1 || true
        ok "settings and data deleted"
    fi
    ok "OutpostGate Pro removed. The ports are back under netplan/NetworkManager (a server reboot gives a clean state)"
    docker_restart_note
}

case "$ACTION" in
    install) do_install ;;
    update) do_update ;;
    status) do_status ;;
    uninstall) do_uninstall ;;
esac
