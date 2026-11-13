# OutpostGate Pro

**Офисный VPN-шлюз** на любом Linux с Docker: WAN в интернет, LAN-порты, туннель в корпоративную
сеть (WireGuard / AmneziaWG / L2TP), динамическая маршрутизация OSPF и BGP (FRRouting).
Старшая версия OutpostGate: для филиалов и офисов, где нужны маршрутизация и службы.
Управление через **FastAPI**, веб-интерфейс и CLI в стиле **MikroTik RouterOS**;
конфиг как единый источник правды, Safe Mode, встроенные инструменты диагностики.

## Архитектура
- **Data plane** — ядро Linux хоста: маршрутизация, nftables, NAT.
- **Control plane** — Docker: FastAPI, веб-интерфейс, CLI по SSH, агент применения конфига.
- Работает на любом Linux с Docker (Debian, Ubuntu, Fedora, Armbian на NanoPi…): сеть делает ядро хоста.
  Внутри контейнера — Debian (python:3.12-slim).

## Режимы запуска (один образ)
| Режим | Где | Сеть | Файл |
|-------|-----|------|------|
| dev   | рабочий ПК | свой namespace, хост не трогается | `docker-compose.yml` |
| gns3  | GNS3 Docker-узел | свой namespace, eth0..N от GNS3 | `deploy/gns3/` |
| host  | VM / сервер / железо | сеть сервера (`network_mode: host`) | `deploy/host/` |

## Быстрый старт (dev)
```bash
docker compose up --build
```
- Веб-интерфейс: http://localhost:8001 — пользователь `admin`, пароль пустой (только из локальной сети)
- CLI в стиле MikroTik: `ssh -p 2223 admin@localhost` или `docker exec -it outpost-gate-pro-dev outpost`
- Swagger: http://localhost:8001/docs

## Языки интерфейса
English (по умолчанию), Русский, עברית — переключатель внизу левого меню и на странице входа, без перезагрузки.
Выбор запоминается в браузере; для иврита страница переходит в режим справа налево.
Словарь — `web/js/i18n-dict.js` (ключ — русская фраза, значение — `[English, иврит]`);
`tests/test_i18n.py` проверяет, что каждая фраза `index.html` в нём есть.

## CLI
Синтаксис MikroTik RouterOS, включая сокращения (`/ip addr pr`), `print detail`, номера строк из `print`.
```
[admin@office] > /ip address print
[admin@office] > /ip route
[admin@office] /ip route> add dst-address=10.0.0.0/8 gateway=192.168.88.254
[admin@office] /ip route> set 0 distance=5 comment="резерв"
[admin@office] > /ip arp print
[admin@office] > /ip dhcp-server lease make-static 3
[admin@office] > /ip firewall filter add chain=input protocol=tcp dst-port=22 in-interface-list=WAN src-address=203.0.113.0/24
[admin@office] > /ip firewall nat add chain=dstnat action=dst-nat protocol=tcp dst-port=8080 to-addresses=192.168.88.20 to-ports=80
[admin@office] > /interface monitor-traffic eth0
[admin@office] > /tool ip-scan address-range=192.168.88.0/24
[admin@office] > /user add name=ivan group=read
[admin@office] > /system shell        # bash; назад — exit или Ctrl-D
[admin@office] > /routing ospf network add network=192.168.88.0/24 area=backbone
[admin@office] > /routing ospf interface add interface=wg0 network-type=point-to-point cost=10
[admin@office] > /routing ospf instance set router-id=10.255.0.1 disabled=no
[admin@office] > /routing bgp instance set as=65010 disabled=no
[admin@office] > /routing bgp peer add remote-address=10.8.0.1 remote-as=65000 comment=HQ
[admin@office] > /routing bgp peer print
```
Меню: `/interface` (ethernet, bridge, wireguard, l2tp-client, monitor-traffic), `/ip` (address, route, arp,
neighbor, pool, dhcp-server, dhcp-client, dns, service, firewall filter/nat), `/wan`, `/lan`, `/vpn`, `/system`
(resource, identity, clock, routerboard, package, shell, reboot), `/user`, `/password`, `/log`, `/tool`
(ping, traceroute, ip-scan, dns-lookup), `/routing` (ospf instance/network/interface/neighbor,
bgp instance/network/peer/session, route), `/export`.

## LAN-сегменты, DHCP (Kea) и DNS (BIND 9)
- **LAN**: несколько сегментов — у каждого свой мост (br-lan, br-lan2…), адрес, порты, DNS и домен.
  Основной сегмент забирает все свободные порты, кроме WAN и портов других сегментов. Между сегментами
  транзит закрыт, пока он не разрешён в настройках сегмента (фаервол пропускает только выбранное направление).
- **DHCP** (Kea): у каждого сегмента свой пул, срок аренды, опции и закреплённые адреса; DHCP можно
  выключить (адреса вручную). Опции: DNS, домен и суффиксы поиска, NTP, смещение времени, MTU, WINS,
  TFTP 66/67, Cisco 150, SIP 120, автонастройка 160, статические маршруты 121/249, WPAD 252, vendor 43
  и любые свои опции по коду (ip, text, hex, uint8/16/32, bool). Платные модули Kea не используются.
- **DNS** (BIND 9): рекурсия и кэш для сегментов, forwarders (по умолчанию — DNS провайдера или
  туннеля), DNSSEC, зоны и записи A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, CAA. Имена устройств из DHCP
  и закреплённых адресов попадают в зону домена сегмента (laptop.office.lan), обратные зоны сами
  получают PTR. Зона по умолчанию — `office.lan` (можно переименовать и добавить свои).
- CLI: `/ip dhcp-server print`, `/ip dhcp-server network print`, `/ip dns print`, `/ip dns set servers=…`,
  `/ip dns static print | add name=pbx.office.lan address=192.168.88.5 | remove`.

## Файловый сервер Samba (вкладка Files)
- Общие папки на сегментах LAN (с WAN — никогда): чтение и запись по пользователям и группам,
  гостевой доступ, корзина (.recycle/<пользователь>), совместимость с macOS (Finder, Time Machine).
- Пользователи и группы файлового сервера (пароли хранит Samba в data/samba, в router.yaml их нет).
- Тома: data — встроенное хранилище (data/shares); в режиме host — диски сервера: обнаружение,
  подключение по UUID в /mnt/disks/<имя>, автоподключение при запуске, форматирование в ext4.
  Диск, на котором стоит сам сервер, роутер не трогает. NTFS, exFAT и FAT32 подключаются с правами
  для общих папок.
- Подключения: кто, с какого компьютера, по какому протоколу, сколько файлов открыто.
- CLI: `/ip smb print | set`, `/ip smb shares`, `/ip smb users`, `/ip smb groups`, `/ip smb sessions`,
  `/ip smb disks`.
- Режим host: в deploy/host/docker-compose.yml включены `privileged` и `/dev` — это нужно для дисков.

## OSPF и BGP (FRRouting)
Вкладка **Routing**: соседи и маршруты, настройки OSPF и BGP. Роутер генерирует `/etc/frr/frr.conf`
целиком, проверяет его (`vtysh --dryrun`) и применяет без разрыва сессий (`frr-reload.py`).
- OSPF: сети и области, стоимость и тип сети интерфейсов, пассивные интерфейсы, MD5, redistribute,
  раздача маршрута по умолчанию. Поверх WireGuard/AmneziaWG — тип point-to-point; адреса OSPF
  (224.0.0.5/6) добавляются в AllowedIPs туннеля автоматически.
- BGP: свой AS, соседи (пароль MD5, multihop, update-source, таймеры), объявляемые сети,
  redistribute, фильтры prefix-list на вход и выход.
- Фаервол сам пропускает OSPF (протокол 89) на интерфейсах OSPF и BGP (TCP 179) от своих соседей.
- Маршруты от OSPF и BGP видны и в `/ip route print` (флаги `o` и `b`).
`?` — помощь в меню, `команда ?` — параметры команды, Tab — подсказки (и значения: интерфейсы, chain=, action=).
Одна команда без входа: `ssh admin@router "/ip route print"`.

## Мониторинг (вкладка Monitoring)
Сбор метрик раз в 10 секунд, история хранится в data/monitor (1 час / 24 часа / 7 дней / 30 дней).
- Обзор: WAN, CPU, память, диск, задержка до шлюза, клиенты DHCP, время работы, VPN, BGP, Samba;
  графики трафика WAN, задержки и потерь (шлюз провайдера + свои адреса), CPU и памяти, сегментов LAN и VPN.
- Интерфейсы: скорость, счётчики, ошибки и потери каждого порта, моста, VLAN и туннеля, график по клику.
- Клиенты: кто сколько качает — учёт по адресам в своей таблице nftables (на фаервол не влияет).
- Экспорт, каждый — своей галочкой: Prometheus (`/metrics`, токен), SNMP v2c/v3 (snmpd),
  Zabbix agent (пассивные и активные проверки). Из LAN доступ открыт всегда, остальным — по списку.
- Готовый стек Prometheus + Grafana с дашбордом и шаблон Zabbix — в deploy/monitoring (см. README там).
- CLI: `/tool torch`, `/snmp print | set`, `/system monitoring print`, `/interface monitor-traffic`.

## Два провайдера (WAN → WAN2, «Резерв и балансировка»)
- WAN2 — второй провайдер на отдельном порту (DHCP или вручную, при необходимости VLAN).
- Резерв: весь трафик через основной канал; упал — через запасной, вернулся — обратно.
  Балансировка: оба канала сразу, новые соединения делятся по весам.
- Проверка связи — ping до заданных адресов через каждый канал; пороги «упал» и «вернулся».
- У каждого канала своя таблица маршрутов, соединения помечаются (ct mark) и не перескакивают
  между каналами; проброс портов работает с обоих WAN. Подробно — в app/services/multiwan.py.
- CLI: `/ip wan2 print | set`, `/ip multiwan print | set`.

## Время (System → Время (NTP)) и Wake-on-LAN
- chrony синхронизирует время и раздаёт его LAN; DHCP-опция 42 указывает на роутер. В Docker часы
  подводит хост, роутер только раздаёт время; в режиме host — подводит сам.
- Wake-on-LAN: кнопка «Разбудить» у устройств в DHCP и вкладка Tools → Wake-on-LAN; CLI `/tool wol`.
- CLI: `/system ntp client print | set`, `/system ntp server print | set`.

## Планировщик (Scheduler)
Задачи по расписанию: каждый день, по дням недели, каждые N минут, один раз или cron.
Действия: разбудить ПК (WoL), включить/выключить сегмент LAN, правило фаервола, проброс порта, VPN,
ограничение QoS; резервная копия конфигурации (data/backups), обновить аренду WAN, сменить основной WAN,
перезапуск. Журнал запусков и «Выполнить сейчас». Время — по часовому поясу роутера (System → Время).
CLI: `/system scheduler print | add | set | enable | disable | remove | run`, `/system clock set time-zone-name=`.

## QoS
- Ограничение скорости сегментов (загрузка и отдача) и отдельных устройств по IP.
- Приоритет голосу: SIP и RTP получают DSCP EF и идут первыми — и к устройствам, и в интернет.
- Скорость провайдера: очередь на роутере, а не в модеме (fq_codel против bufferbloat).
- Linux tc: HTB + fq_codel на мостах сегментов и WAN, police на входе мостов. Счётчики очередей во вкладке QoS.
- CLI (как в RouterOS, max-limit=отдача/загрузка): `/queue settings`, `/queue segment`, `/queue simple`.

## Экспорт командами
System → Резервные копии → «Экспорт командами» или `/export` в CLI: вся конфигурация командами, как `/export`
в RouterOS. Секреты скрыты; `/export show-sensitive` — с ними; `/export format=yaml` — router.yaml.

## Установка на виртуальную машину или сервер
Скопируйте папку проекта на ВМ (Ubuntu 22.04/24.04 или Debian 12/13, минимум два сетевых адаптера) и:
```bash
cd outpost-gate-pro
sudo ./install.sh              # мастер: WAN, WAN2, LAN, пароль admin
sudo ./install.sh --status
sudo ./install.sh --update     # после update_pro_*.sh
sudo ./install.sh --uninstall  # (--purge — вместе с настройками)
```
Без вопросов: `sudo ./install.sh -y --wan ens18 --wan-mode none --lan ens19 --password '...'` (`--help`).

## Дорожная карта
- [x] Каркас
- [x] Advanced: IP Addresses, IP Routes (двигатель)
- [x] WAN: DHCP-клиент / статика, автоопределение интерфейса
- [x] LAN: мост br-lan, dnsmasq (DHCP + DNS), закреплённые адреса, NAT, базовый фаервол
- [x] VPN → WireGuard: импорт .conf, full / split, kill switch, NAT или site-to-site
- [x] VPN → AmneziaWG (amneziawg-go, обфускация), L2TP/IPsec (strongSwan + xl2tpd)
- [x] Firewall: правила в стиле OCI Security Lists (входящие, транзит), проброс портов, счётчики, итоговый nftables
- [x] Tools: ping (IPv4/IPv6), сканер портов, traceroute, DNS, соседи (ARP), сканер сети (ping + ARP)
- [x] System: вход (admin без пароля при первом входе, как MikroTik), роли, пользователи, журнал, резервные копии и снимки, Safe Mode, ресурсы, перезапуск
- [x] Status: WAN, VPN, LAN, система, трафик интерфейсов
- [x] CLI в стиле MikroTik по SSH: ~70 команд, сокращения, print detail, set/move, Tab со значениями, /system shell
- [x] Веб-интерфейс без раздела Advanced: адреса и маршруты — в CLI
- [x] Pro: OSPF/BGP, LAN-сегменты + Kea + BIND 9, Samba, VLAN 802.1Q, мониторинг (дашборд, Prometheus, SNMP, Zabbix)
- [x] Pro: два провайдера (резерв и балансировка), NTP, Wake-on-LAN
- [x] Pro: планировщик, QoS (лимиты, приоритет голосу), экспорт командами, часовой пояс
- [ ] Дальше: скрипт установки на ВМ и железо; отдельно — Proxy Manager (HTTPS), удалённый доступ
