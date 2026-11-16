# OutpostGate Pro

**A self-built Linux router in Docker** — a branch-office / home-lab gateway with a web UI,
a REST API and a command line that speaks both **MikroTik RouterOS** and **Linux** (`ip`, `nmcli`).
The Linux kernel of the host does the routing, NAT and firewalling; the container is the control plane.

Built from scratch as an engineering project: one configuration file (`router.yaml`) is the source of
truth, every change is validated, applied atomically and can be exported as RouterOS-style commands.

---

## What it can do

### Network basics
- **WAN** — DHCP, static or "leave to the system", provider VLAN (802.1Q).
  **Dual WAN**: failover or weighted load balancing, per-link health checks, connections stick to their link.
- **LAN segments** — several isolated networks, each with its own bridge, address, ports, domain and DNS;
  transit between segments is opt-in. **VLANs**: carry segments tagged on trunk ports (router on a stick).
  Changing a segment's network moves the DHCP pool and static leases along.
- **DHCP — ISC Kea**: pools, lease times, static leases, options (DNS, NTP, TFTP 66/67, Cisco 150,
  SIP 120, auto-provisioning 160, classless routes 121/249, WPAD, vendor 43, custom codes).
  Kea is rebound automatically when a bridge is re-created.
- **DNS — BIND 9**: recursive cache, forwarders, DNSSEC, authoritative zones
  (A/AAAA/CNAME/MX/TXT/SRV/PTR/NS/CAA); DHCP clients get names automatically
  (`laptop.office.lan`), reverse zones get PTR records. Router tools resolve local names too.
- **Firewall & NAT — nftables**: zone-based rules (WAN / LAN / VPN), port forwarding from WAN or from a
  VPN tunnel, lockout protection, counters, a readable "what the system rules do" view.
- **QoS** — per-segment and per-device limits, voice priority (SIP/RTP → DSCP EF), HTB + fq_codel
  against bufferbloat.
- **NTP** (chrony), **Wake-on-LAN**, **Samba file server** (shares, users/groups, recycle bin,
  server disks mounted by UUID).

### VPN — three tunnel types plus GRE
| Tunnel | Notes |
|---|---|
| **WireGuard** | import a `.conf`, full or split tunnel |
| **AmneziaWG** (up to 3.1) | DPI-resistant WireGuard; paste a `vpn://` link or `.vpn` file straight from the Amnezia app |
| **L2TP/IPsec** | strongSwan + xl2tpd, the classic corporate VPN |
| **GRE** | router-to-router tunnels *over* any of the above (or the internet) |

- **Connected networks with GRE.** A commercial VPN server (e.g. Amnezia) only knows each client's
  `/32` and will not route the LANs behind routers. GRE between two OutpostGate routers travels as
  ordinary client-to-client traffic, and inside it the LANs are routed with static routes or
  **OSPF** — like `interface Tunnel` on Cisco. The VPN server needs no changes.
- **Remote access**: manage the router through the tunnel (web, SSH, CLI, ping from a phone on the same
  VPN server) and forward ports from the tunnel to LAN devices (PBX, camera, NAS).
- **Full or split tunnel**, kill switch, NAT or site-to-site mode.
- **Watchdog**: if there is no WireGuard handshake for 3.5 minutes (host sleep, network change, a crashed
  `amneziawg-go`) the tunnel reconnects by itself, with back-off.
- In full-tunnel mode the **router's own traffic** (updates, Docker Hub, apt) can go straight via WAN, so
  maintenance never depends on the VPN; LAN devices still use the tunnel.

### Routing
**FRRouting**: static routes, **OSPF** (areas, point-to-point over tunnels, MD5, passive interfaces)
and **BGP** (peers, prefix lists, redistribution). The config is generated, dry-run checked and
reloaded without dropping sessions. The firewall opens OSPF/BGP only where they are configured.

### Monitoring
Built-in dashboard (WAN, latency/loss, CPU, memory, segments, VPN, per-client traffic) with
1 h / 24 h / 7 d / 30 d history. Exporters, each behind its own switch: **Prometheus** `/metrics`,
**SNMP** v2c/v3, **Zabbix agent**. A ready Prometheus + Grafana stack and a Zabbix template are in
`deploy/monitoring`.

### Operations
Scheduler (WoL, segments, rules, VPN, QoS, backups), users with full / read-only roles, audit log,
backups and snapshots, Safe Mode, RouterOS-style `/export`, time zone, an installer for VMs and servers.

---

## Command line: RouterOS or Linux — your choice

SSH into the router (`ssh -p 2222 admin@192.168.88.1`). On the first login it asks which syntax you
prefer; switch any time with `linux` / `routeros`.

**MikroTik RouterOS style** — menus, abbreviations, `print detail`, row numbers, Tab completion:
```
[admin@office] > /ip address print
[admin@office] > /ip firewall nat add chain=dstnat action=dst-nat protocol=tcp dst-port=8080 to-addresses=192.168.88.20 to-ports=80
[admin@office] > /interface gre add remote-address=10.8.1.3 address=172.16.0.1/30 underlay=awg0 ospf=yes
[admin@office] > /routing ospf neighbor print
[admin@office] > :resolve samba
```

**Linux style** — for people who live in a Linux shell. Viewing commands run the real tools;
changes go through the router configuration, so nothing is lost on the next apply:
```
admin@office:~$ ip -br a
admin@office:~$ ip route add 192.168.20.0/24 via 172.16.0.2
admin@office:~$ nmcli c
admin@office:~$ nmcli c mod lan1 ipv4.addresses 192.168.1.1/24
admin@office:~$ nmcli c up amneziawg
admin@office:~$ ss -tlnp
```
- Ubuntu-like colored prompt and output (iproute2 colors, nmcli states) in interactive sessions,
  plain text for scripts.
- Hints, help and messages in **English, Russian or Hebrew**: `sl1`, `sl2`, `sl3`.
- `/…` runs a RouterOS command from the Linux syntax as well.
- **Ansible**: log in as `admin+cet1024w` (as `community.routeros` recommends) and the session is plain
  RouterOS without questions; `without-paging` is accepted. Everything is also available over the REST API.

---

## Web UI and API
- Web UI on **port 80**: `http://<router LAN address>` — English, Russian and Hebrew (right-to-left),
  switchable without reload.
- REST API (FastAPI) on the same port, interactive docs at `/docs`.
- First login: user `admin` with an empty password, allowed only from the LAN until a password is set.

## Technologies
| Layer | Stack |
|---|---|
| Control plane | Python 3.12, FastAPI, Pydantic v2, uvicorn, pyroute2, asyncssh, prompt_toolkit |
| Web UI | plain HTML/CSS/JavaScript, no build step; i18n dictionary in `web/js/i18n-dict.js` |
| Data plane | Linux kernel: bridges, VLANs, nftables, policy routing, `tc` (HTB, fq_codel) |
| Services | ISC Kea (DHCP), BIND 9 (DNS), FRRouting (OSPF/BGP), chrony, Samba, net-snmp, Zabbix agent |
| VPN | wireguard-tools, amneziawg-go / amneziawg-tools, strongSwan + xl2tpd, Linux GRE |
| Packaging | Docker (one image, three run modes), Bash installer |
| Tests | pytest — 225 tests (models, firewall rulesets, CLI, VPN, DHCP/DNS, installer logic) |

## Run modes (one image)
| Mode | Where | Network | Files |
|---|---|---|---|
| dev | your workstation | own namespace, the host is untouched | `docker-compose.yml` |
| gns3 | GNS3 Docker node | own namespace, eth0..N from GNS3 | `deploy/gns3/` |
| host | VM / server / bare metal | the server's network (`network_mode: host`) | `deploy/host/`, `install.sh` |

### Quick start (dev)
```bash
docker compose up --build
```
Web UI: http://localhost:8001 · API docs: http://localhost:8001/docs · CLI: `ssh -p 2223 admin@localhost`

### Install on a VM or server
Ubuntu 22.04/24.04 or Debian 12/13 with at least two network adapters:
```bash
cd outpost-gate-pro
sudo ./install.sh                    # wizard: WAN, WAN2, LAN, admin password
sudo ./install.sh --status
sudo ./install.sh --update           # rebuild and restart after pulling new code
sudo ./install.sh --update --api-port 8080   # move the web UI to another port
sudo ./install.sh --uninstall        # --purge also removes the settings
```
Unattended: `sudo ./install.sh -y --wan ens18 --wan-mode none --lan ens19 --password '...'` (see `--help`).
The installer loads kernel modules, sets sysctls, hands the router ports over from netplan /
NetworkManager, keeps Docker out of the firewall and gives the server its own DNS.

## Project layout
```
app/api/        REST endpoints (FastAPI routers)
app/models/     Pydantic models — validation of every config section
app/services/   apply logic: nftables, netlink, Kea, BIND, FRR, VPN, GRE, QoS, monitoring …
app/cli/        SSH command line: RouterOS syntax (commands.py), Linux syntax (linux.py), colors/i18n (term.py)
web/            web UI
deploy/         run modes: host, gns3, monitoring stack
install.sh      installer for VMs and servers
tests/          pytest
```

## Author
Fedor Afrin — network & telecom engineer. Built with the help of Claude (Anthropic).
