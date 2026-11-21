# Мониторинг OutpostGate Pro снаружи: Prometheus + Grafana и Zabbix

Встроенный дашборд (вкладка **Monitoring**) работает всегда и ничего не требует.
Здесь — как подключить внешние системы. Каждый способ включается своей галочкой:
**Monitoring → Экспорт**.

Доступ: из сегментов LAN открыт всегда. Для остальных адресов (через WAN, VPN или
из сети Docker) их нужно перечислить в поле «Откуда ещё» — роутер сам откроет порт
в фаерволе только для них.

| Способ | Порт роутера | Что нужно указать |
|---|---|---|
| Prometheus | TCP 80 (`/metrics`, порт веб-интерфейса) | токен (желательно), «откуда ещё» |
| SNMP | UDP 161 | v2c: community; v3: пользователь и два пароля |
| Zabbix agent | TCP 10050 | адрес Zabbix server; при желании ServerActive |

## Prometheus + Grafana (готовый стек в этой папке)

1. На роутере: Monitoring → Экспорт → **Prometheus** — включить, нажать «Сгенерировать»
   токен, в «Откуда ещё» добавить адрес компьютера с Prometheus.
2. В `prometheus.yml` указать адрес роутера и раскомментировать блок `authorization`
   с тем же токеном.
3. Запуск:
   ```bash
   cd deploy/monitoring
   docker compose up -d
   ```
4. Grafana: http://localhost:3000 (admin / admin) → папка **OutpostGate** → дашборд
   **OutpostGate Pro** (WAN, задержка, сегменты, CPU и память, топ клиентов, диски, BGP).

Проверка без Prometheus:
```bash
curl -H "Authorization: Bearer ТОКЕН" http://192.168.1.1/metrics
```

**Dev-режим (роутер в Docker на этом же компьютере).** Prometheus ходит на
`host.docker.internal:8001`, и роутер видит запрос с адреса шлюза сети Docker
(обычно `172.x.0.1`). Добавьте в «Откуда ещё» сеть Docker: `172.16.0.0/12`.

Метрики: `og_interface_*_bytes_total{interface,role,label}`, `og_cpu_usage_percent`,
`og_memory_*_bytes`, `og_ping_rtt_seconds{target,name}`, `og_ping_loss_ratio`,
`og_client_receive_bytes_total{ip,name,mac,segment}`, `og_dhcp_leases_active{segment}`,
`og_vpn_up`, `og_bgp_peer_up{peer}`, `og_ospf_neighbors_full`, `og_smb_sessions`, `og_wan_up`.

## Zabbix

### Вариант 1 — Zabbix agent (больше данных о роутере)

1. На роутере: Monitoring → Экспорт → **Zabbix agent** — включить, указать адрес Zabbix
   server (или proxy). Имя узла по умолчанию — имя роутера.
2. В Zabbix: **Data collection → Templates → Import** → файл
   `zabbix_template_outpostgate.yaml` (Zabbix 6.0 и новее, в том числе 7.x).
3. Создать узел: имя как на роутере, интерфейс Agent — адрес роутера, порт 10050,
   шаблон **OutpostGate Pro by Zabbix agent**. По желанию добавьте стандартный
   **Linux by Zabbix agent**.

Шаблон сам находит интерфейсы (WAN, сегменты, VLAN, VPN), адреса проверки связи и тома.
Триггеры: WAN упал, VPN упал, BGP-сессия не поднята, потери > 50 %, задержка > 200 мс,
CPU > 90 %, диск > 90 %, роутер перезапустился, данные мониторинга устарели.

Проверка с Zabbix server:
```bash
zabbix_get -s 192.168.1.1 -k 'outpost.get[wan.up]'
zabbix_get -s 192.168.1.1 -k 'outpost.discovery[if]'
```

В dev-режиме порт агента проброшен на хост как 10060 (10050 обычно занят агентом
самого компьютера): `zabbix_get -s 127.0.0.1 -p 10060 -k agent.ping`. В «Адрес Zabbix
server» добавьте `172.16.0.0/12`.

### Вариант 2 — SNMP (стандартно, понимает любая система)

1. На роутере: Monitoring → Экспорт → **SNMP** — включить; v2c — задать свой community
   (не `public`), v3 — пользователь, пароль аутентификации (SHA) и шифрования (AES).
2. В Zabbix: узел с интерфейсом SNMP, шаблоны **Linux by SNMP** и/или
   **Network Generic Device by SNMP**. Макрос `{$SNMP_COMMUNITY}` — ваш community.

Проверка:
```bash
snmpwalk -v2c -c office 192.168.1.1 IF-MIB::ifDescr
snmpwalk -v3 -l authPriv -u zbx -a SHA -A 'пароль1' -x AES -X 'пароль2' 192.168.1.1 system
```
В dev-режиме: `snmpwalk -v2c -c office localhost:1161 system` и `172.16.0.0/12` в «Откуда ещё».
