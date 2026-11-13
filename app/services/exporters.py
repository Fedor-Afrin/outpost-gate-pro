"""
Экспорт метрик наружу — каждый включается своей галочкой (вкладка Monitoring → Экспорт).

  Prometheus — GET /metrics на порту веб-интерфейса, формат text/plain 0.0.4.
               Доступ: из LAN и из списка allowed; если задан токен — только с ним
               (Authorization: Bearer <токен>).
  SNMP       — snmpd внутри роутера, UDP 161, v2c (community) или v3 (SHA + AES).
               Стандартные MIB: IF-MIB (порты и трафик), HOST-RESOURCES (CPU, память, диски).
  Zabbix     — Zabbix agent 2 (или классический zabbix_agentd) внутри роутера, TCP 10050.
               Ключи роутера: outpost.get[...] и outpost.discovery[...] — шаблон в
               deploy/monitoring/zabbix_template_outpostgate.yaml.

Конфиги генерируются целиком в data/snmp и data/zabbix. Фаервол сам открывает порты
для адресов из списков (из LAN доступ открыт всегда).
"""
from __future__ import annotations

import hmac
import ipaddress
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from app.core.config import settings
from app.core.process import ManagedProcess
from app.core.store import store
from app.models.monitoring import ExporterState, MonitoringConfig, MonitoringSettings

ZBX_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "zbx.py"
_snmpd = ManagedProcess("snmpd")
_zabbix = ManagedProcess("zabbix-agent")
_lock = threading.RLock()
_errors: dict[str, str | None] = {"snmp": None, "zabbix": None}


class ExportError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _data(*parts: str) -> Path:
    return Path(settings.data_dir).joinpath(*parts)


def get_config() -> MonitoringConfig:
    return MonitoringConfig.model_validate(store.load().get("monitoring") or {})


def lan_networks() -> list[str]:
    from app.services import lan
    try:
        return [str(s.network) for s in lan.segments() if s.enabled]
    except Exception:  # noqa: BLE001
        return []


def identity() -> str:
    return (store.load().get("system") or {}).get("identity") or "outpost-gate-pro"


# --- Prometheus -------------------------------------------------------------------------------
def _lbl(v) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(d: dict) -> str:
    items = [(k, v) for k, v in d.items() if v is not None and v != ""]
    return "{" + ",".join(f'{k}="{_lbl(v)}"' for k, v in items) + "}" if items else ""


class _Metrics:
    def __init__(self):
        self.lines: list[str] = []
        self.declared: set[str] = set()

    def add(self, name: str, kind: str, help_: str, value, labels: dict | None = None) -> None:
        if value is None:
            return
        if name not in self.declared:
            self.declared.add(name)
            self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}"]
        if isinstance(value, bool):
            value = int(value)
        self.lines.append(f"{name}{_labels(labels or {})} {value}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def prometheus_text(snap: dict, ident: str, version: str) -> str:
    m = _Metrics()
    m.add("og_info", "gauge", "Router identity and version", 1, {"identity": ident, "version": version, "mode": settings.mode})
    if not snap.get("time"):
        m.add("og_up", "gauge", "Metrics collector has data", 0)
        return m.text()
    m.add("og_up", "gauge", "Metrics collector has data", 1)
    m.add("og_last_collect_timestamp_seconds", "gauge", "Time of the last collection", round(snap["time"], 3))
    s = snap["system"]
    m.add("og_uptime_seconds", "gauge", "System uptime", s.get("uptime"))
    m.add("og_cpu_usage_percent", "gauge", "CPU usage over the last interval", s.get("cpu"))
    m.add("og_cpu_count", "gauge", "Number of CPUs", s.get("cpu_count"))
    for period, v in zip(("1m", "5m", "15m"), s.get("load") or []):
        m.add("og_load_average", "gauge", "Load average", v, {"period": period})
    mem = s.get("memory") or {}
    m.add("og_memory_total_bytes", "gauge", "Total memory", mem.get("total"))
    m.add("og_memory_used_bytes", "gauge", "Used memory (total - available)", mem.get("used"))
    m.add("og_temperature_celsius", "gauge", "Highest thermal zone temperature", s.get("temperature"))
    for d in s.get("disks") or []:
        m.add("og_disk_total_bytes", "gauge", "Volume size", d["total"], {"volume": d["name"], "path": d["path"]})
        m.add("og_disk_used_bytes", "gauge", "Volume used space", d["used"], {"volume": d["name"], "path": d["path"]})

    for i in snap.get("interfaces") or []:
        lb = {"interface": i["name"], "role": i["role"], "label": i["label"]}
        m.add("og_interface_up", "gauge", "Interface link is up", i["up"], lb)
        m.add("og_interface_receive_bytes_total", "counter", "Bytes received", i["rx_bytes"], lb)
        m.add("og_interface_transmit_bytes_total", "counter", "Bytes transmitted", i["tx_bytes"], lb)
        m.add("og_interface_receive_errors_total", "counter", "Receive errors", i["rx_errors"], lb)
        m.add("og_interface_transmit_errors_total", "counter", "Transmit errors", i["tx_errors"], lb)
        m.add("og_interface_receive_drops_total", "counter", "Receive drops", i["rx_dropped"], lb)
        m.add("og_interface_transmit_drops_total", "counter", "Transmit drops", i["tx_dropped"], lb)
        m.add("og_interface_speed_bits", "gauge", "Link speed", i["speed"], lb)

    w = snap.get("wan") or {}
    m.add("og_wan_up", "gauge", "WAN link is up", bool(w.get("up")), {"interface": w.get("interface")})
    for p in snap.get("ping") or []:
        lb = {"target": p["target"], "name": p["name"]}
        m.add("og_ping_rtt_seconds", "gauge", "Average ping round-trip time", None if p["rtt"] is None else round(p["rtt"] / 1000, 6), lb)
        m.add("og_ping_loss_ratio", "gauge", "Ping packet loss (0..1)", None if p["loss"] is None else round(p["loss"] / 100, 4), lb)

    for d in snap.get("dhcp") or []:
        m.add("og_dhcp_leases_active", "gauge", "Active DHCP leases", d["leases"], {"segment": d["name"], "lan": d["id"]})
    m.add("og_client_accounting_enabled", "gauge", "Per-client traffic accounting works", bool(snap.get("accounting")))
    for c in snap.get("clients") or []:
        lb = {"ip": c["ip"], "name": c["name"], "mac": c["mac"], "segment": c["segment"]}
        m.add("og_client_receive_bytes_total", "counter", "Bytes downloaded by a LAN client", c["rx_bytes"], lb)
        m.add("og_client_transmit_bytes_total", "counter", "Bytes uploaded by a LAN client", c["tx_bytes"], lb)

    if snap.get("vpn"):
        m.add("og_vpn_up", "gauge", "VPN tunnel is connected", snap["vpn"]["up"], {"type": snap["vpn"]["kind"]})
    r = snap.get("routing") or {}
    m.add("og_ospf_neighbors_full", "gauge", "OSPF neighbors in Full state", r.get("ospf_neighbors"))
    for p in r.get("bgp") or []:
        lb = {"peer": p["peer"], "remote_as": p["remote_as"], "description": p["description"]}
        m.add("og_bgp_peer_up", "gauge", "BGP session is established", p["up"], lb)
        m.add("og_bgp_peer_prefixes_received", "gauge", "Prefixes received from the peer", p["prefixes"], lb)
    m.add("og_smb_sessions", "gauge", "Connected Samba sessions", snap.get("smb_sessions"))
    return m.text()


def metrics_access(cfg: MonitoringConfig, client_ip: str | None, authorization: str | None,
                   query_token: str | None, lan_nets: list[str]) -> tuple[int, str] | None:
    """None — пропустить, иначе (код, причина)."""
    p = cfg.prometheus
    if not p.enabled:
        return 404, "Prometheus metrics are disabled"
    try:
        addr = ipaddress.ip_address(client_ip or "")
    except ValueError:
        return 403, "forbidden"
    nets = [ipaddress.ip_network(n) for n in [*lan_nets, *p.allowed]]
    if not (addr.is_loopback or any(addr in n for n in nets)):
        return 403, "forbidden: address is not allowed"
    if p.token:
        given = query_token or ""
        if authorization and authorization.lower().startswith("bearer "):
            given = authorization[7:].strip()
        if not hmac.compare_digest(given.encode(), p.token.encode()):
            return 401, "bearer token required"
    return None


# --- SNMP -------------------------------------------------------------------------------------
def snmpd_conf(cfg: MonitoringConfig, lan_nets: list[str], name: str) -> str:
    s = cfg.snmp
    out = ["# сгенерировано OutpostGate Pro — не редактировать вручную",
           "agentAddress udp:161",
           f'sysName "{name}"',
           f'sysLocation "{s.location or ""}"',
           f'sysContact "{s.contact or ""}"',
           "sysServices 76",
           "dontLogTCPWrappersConnects yes",
           "# только чтение; откуда — LAN и список allowed"]
    sources = [*lan_nets, *[n for n in s.allowed if n not in lan_nets]] or ["127.0.0.1/32"]
    if s.version == "v2c":
        for src in sources:
            out.append(f"rocommunity {s.community} {src}")
    else:
        out.append(f'createUser {s.user} SHA "{s.auth_password}" AES "{s.priv_password}"')
        out.append(f"rouser {s.user} priv")
    if s.version == "v2c" and "127.0.0.1/32" not in sources:
        out.append(f"rocommunity {s.community} 127.0.0.1   # проверка с самого роутера")
    return "\n".join(out) + "\n"


def snmp_installed() -> bool:
    return shutil.which("snmpd") is not None


def _wait_alive(proc: ManagedProcess, seconds: float = 1.5) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if not proc.running():
            return False
        time.sleep(0.1)
    return proc.running()


def apply_snmp(cfg: MonitoringConfig) -> None:
    s = cfg.snmp
    _snmpd.stop()
    if not s.enabled:
        _errors["snmp"] = None
        return
    if not snmp_installed():
        raise ExportError(500, "нет snmpd в образе — пересоберите образ (docker compose build)")
    d = _data("snmp")
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    conf = d / "snmpd.conf"
    conf.write_text(snmpd_conf(cfg, lan_networks(), identity()))
    os.chmod(conf, 0o600)
    # v3: snmpd запоминает пользователей в persistent-каталоге — при смене паролей начать с чистого
    persist = d / "persist"
    shutil.rmtree(persist, ignore_errors=True)
    persist.mkdir(mode=0o700)
    env = {**os.environ, "SNMP_PERSISTENT_DIR": str(persist), "MIBS": ""}
    _snmpd.start(["snmpd", "-f", "-Lo", "-C", "-c", str(conf), "-p", str(d / "snmpd.pid")], env=env)
    if not _wait_alive(_snmpd):
        _snmpd.stop()
        raise ExportError(400, "snmpd не запустился — подробности в docker logs")
    _errors["snmp"] = None


# --- Zabbix agent -----------------------------------------------------------------------------
def zabbix_binary() -> tuple[str, str] | None:
    for flavor, name in (("agent2", "zabbix_agent2"), ("agentd", "zabbix_agentd")):
        path = shutil.which(name) or (f"/usr/sbin/{name}" if os.path.exists(f"/usr/sbin/{name}") else None)
        if path:
            return flavor, path
    return None


def zabbix_conf(cfg: MonitoringConfig, flavor: str, name: str, current_json: Path) -> str:
    z = cfg.zabbix
    py = sys.executable or "python3"
    cmd = f"{py} -I {ZBX_SCRIPT} {current_json}"
    out = ["# сгенерировано OutpostGate Pro — не редактировать вручную",
           f"Hostname={z.hostname or name}",
           "ListenPort=10050",
           "LogType=console",
           "Timeout=10",
           f"PidFile={_data('zabbix', 'agent.pid')}"]
    if z.server:
        out.append("Server=" + ",".join(z.server))
    else:
        out.append("Server=127.0.0.1")
    if z.server_active:
        out.append(f"ServerActive={z.server_active}")
    if z.metadata:
        out.append(f"HostMetadata={z.metadata}")
    if flavor == "agentd":
        out += ["AllowRoot=1", "StartAgents=3"]
    else:
        out.append(f"ControlSocket={_data('zabbix', 'agent.sock')}")
    out += [f'UserParameter=outpost.get[*],{cmd} get "$1"',
            f'UserParameter=outpost.discovery[*],{cmd} discovery "$1"']
    return "\n".join(out) + "\n"


def apply_zabbix(cfg: MonitoringConfig) -> None:
    _zabbix.stop()
    if not cfg.zabbix.enabled:
        _errors["zabbix"] = None
        return
    found = zabbix_binary()
    if not found:
        raise ExportError(500, "нет Zabbix agent в образе — пересоберите образ (docker compose build)")
    flavor, binary = found
    d = _data("zabbix")
    d.mkdir(parents=True, exist_ok=True)
    conf = d / f"zabbix_{flavor}.conf"
    conf.write_text(zabbix_conf(cfg, flavor, identity(), _data("monitor", "current.json")))
    os.chmod(conf, 0o644)
    try:
        r = subprocess.run([binary, "-c", str(conf), "-T"], capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        r = None
    msg = " ".join(((r.stderr or r.stdout) if r else "").split())[-300:]
    if r is not None and r.returncode != 0 and not any(x in msg.lower() for x in ("invalid option", "unrecognized option", "unknown option")):
        raise ExportError(400, f"Zabbix agent не принял настройки: {msg}")   # старый агент без -T просто запускается
    cmd = [binary, "-c", str(conf)] + (["-f"] if flavor == "agentd" else [])
    _zabbix.start(cmd)
    if not _wait_alive(_zabbix):
        _zabbix.stop()
        raise ExportError(400, "Zabbix agent не запустился — подробности в docker logs")
    _errors["zabbix"] = None


# --- общее ------------------------------------------------------------------------------------
def apply(cfg: MonitoringConfig | None = None) -> None:
    cfg = cfg or get_config()
    with _lock:
        apply_snmp(cfg)
        apply_zabbix(cfg)


def firewall_rules(cfg: MonitoringConfig | None = None) -> list[tuple[str, int, list[str], str]]:
    """[(протокол, порт, источники, комментарий)] — доступ к экспорту не из LAN."""
    try:
        cfg = cfg or get_config()
    except Exception:  # noqa: BLE001 — ошибка в настройках не должна ломать фаервол
        return []
    out = []
    if cfg.prometheus.enabled and cfg.prometheus.allowed:
        out.append(("tcp", int(os.getenv("API_PORT", "8000")), cfg.prometheus.allowed, "Prometheus /metrics"))
    if cfg.snmp.enabled and cfg.snmp.allowed:
        out.append(("udp", 161, cfg.snmp.allowed, "SNMP"))
    if cfg.zabbix.enabled and cfg.zabbix.server:
        out.append(("tcp", 10050, cfg.zabbix.server, "Zabbix agent"))
    return out


def update(raw: dict) -> MonitoringSettings:
    """Сохранить настройки целиком и применить; ошибка — откат.
    Пустые пароли SNMPv3 в форме — «не менять» (наружу они не отдаются)."""
    from pydantic import ValidationError
    from app.services import firewall
    old = get_config()
    raw = dict(raw or {})
    snmp = dict(raw.get("snmp") or {})
    for k in ("auth_password", "priv_password"):
        snmp[k] = snmp.get(k) or getattr(old.snmp, k)
    raw["snmp"] = snmp
    try:
        new = MonitoringConfig.model_validate(raw)
    except ValidationError as e:
        raise ExportError(422, "; ".join(str(x["msg"]).removeprefix("Value error, ") for x in e.errors())) from None
    raw_old = store.load().get("monitoring")
    with _lock:
        with store.transaction() as data:
            data["monitoring"] = new.to_yaml()
        try:
            apply(new)
            firewall.refresh()
        except ExportError:
            with store.transaction() as data:
                if raw_old is None:
                    data.pop("monitoring", None)
                else:
                    data["monitoring"] = raw_old
            try:
                apply(old)
            except ExportError as e:
                print(f"[monitoring] ERROR: откат не удался: {e.message}")
            raise
        except Exception as e:  # фаервол
            print(f"[monitoring] WARNING: фаервол: {e}")
    return status()


def apply_startup() -> None:
    try:
        cfg = get_config()
    except Exception as e:  # noqa: BLE001
        print(f"[monitoring] ERROR: настройки: {e}")
        return
    for name, fn in (("snmp", apply_snmp), ("zabbix", apply_zabbix)):
        try:
            fn(cfg)
        except ExportError as e:
            _errors[name] = e.message
            print(f"[monitoring] ERROR: {name}: {e.message}")


def stop() -> None:
    _zabbix.stop()
    _snmpd.stop()


def masked(cfg: MonitoringConfig) -> MonitoringConfig:
    c = cfg.model_copy(deep=True)
    c.snmp.auth_password = None
    c.snmp.priv_password = None
    return c


def status() -> MonitoringSettings:
    cfg = get_config()
    zb = zabbix_binary()
    snmp = ExporterState(enabled=cfg.snmp.enabled, installed=snmp_installed(), running=_snmpd.running(),
                         error=_errors["snmp"])
    if cfg.snmp.enabled and not snmp.running and not snmp.error:
        snmp.error = "snmpd не запущен — см. docker logs"
    zabbix = ExporterState(enabled=cfg.zabbix.enabled, installed=zb is not None, running=_zabbix.running(),
                           error=_errors["zabbix"], flavor=zb[0] if zb else None)
    if cfg.zabbix.enabled and not zabbix.running and not zabbix.error:
        zabbix.error = "Zabbix agent не запущен — см. docker logs"
    return MonitoringSettings(config=masked(cfg), snmp=snmp, zabbix=zabbix, lan_networks=lan_networks())
