"""
Агент применения конфигурации.

router.yaml — единый источник правды (аналог /export в RouterOS).
При старте API агент приводит систему к конфигу, строго по порядку:
  1. ip_forward
  2. WAN (адрес/шлюз или запуск DHCP-клиента)
  3. LAN: сегменты (мосты br-lan, br-lan2…), DHCP (Kea), DNS (BIND), NAT и фаервол
  4. VPN (WireGuard / AmneziaWG / L2TP: туннель, маршруты, kill switch)
  5. дополнительные адреса (CLI: /ip address)
  6. статические маршруты (CLI: /ip route)  — после адресов: шлюз должен быть доступен
  7. OSPF и BGP (FRRouting) — им нужны все интерфейсы и адреса;
     затем фаервол ещё раз (пропустить OSPF/BGP) и AllowedIPs туннеля (multicast OSPF)
  8. файловый сервер Samba — диски (автомонтирование), учётки, общие папки
  9. экспорт мониторинга: snmpd, Zabbix agent (сбор метрик запускает main.py)
Дальше: Status, Safe Mode.
"""
from app.services import addresses, exporters, files, firewall, lan, routes, routing, sysctl, vpn, wan


def _step(name: str, fn) -> None:
    try:
        fn()
    except Exception as e:  # агент не должен мешать запуску API
        print(f"[agent] ERROR: {name}: {e}")


def apply_startup() -> None:
    if sysctl.set_ip_forward(True):
        print("[agent] ip_forward = 1")
    else:
        print("[agent] WARNING: не удалось включить ip_forward "
              "(нужен NET_ADMIN / --sysctl net.ipv4.ip_forward=1)")

    _step("WAN", wan.apply_startup)
    _step("LAN", lan.apply_startup)
    _step("VPN", vpn.apply_startup)
    _step("адреса", addresses.apply_all)
    _step("маршруты", routes.apply_all)
    _step("OSPF/BGP", routing.apply_startup)
    if routing.active():
        _step("фаервол (OSPF/BGP)", firewall.refresh)
        _step("VPN (OSPF multicast)", vpn.sync_allowed_ips)
    _step("файловый сервер", files.apply_startup)
    _step("мониторинг (SNMP, Zabbix)", exporters.apply_startup)
