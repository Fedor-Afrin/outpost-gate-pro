# Запуск в GNS3 (Docker-узел)

Контейнер работает в собственном namespace — хост не затрагивается.
GNS3 сам создаёт интерфейсы eth0..ethN по числу адаптеров.

1. Собрать образ:
   ```bash
   docker build -t outpost-gate-pro:gns3 .
   ```
2. GNS3 → Edit → Preferences → Docker containers → New
   - Image: `outpost-gate-pro:gns3`
   - Adapters: 2 (eth0 = WAN, eth1 = LAN) или больше
   - Environment: `ROUTER_MODE=gns3`
   - Console type: telnet; HTTP-порт для веб-интерфейса: 80
3. Перетащить узел на схему, соединить eth0 с NAT/облаком, eth1 — с клиентами.

## Сохранение конфига
Изменения из веб-интерфейса записываются в `/etc/outpost-gate-pro/router.yaml`.
Чтобы они переживали перезапуск узла, в настройках шаблона GNS3 укажите
**Persistent directories**:
```
/etc/outpost-gate-pro
/var/lib/outpost-gate-pro
```

## Командная строка (CLI в стиле MikroTik)
* Правой кнопкой по узлу -> **Auxiliary console** -> команда `outpost`.
* Или по SSH с любого устройства в LAN: `ssh admin@192.168.88.1`.

Основная консоль узла показывает журнал роутера — **Ctrl-C там не нажимайте**: это остановит роутер.

После обновления кода пересоберите образ (`docker compose build`) и пересоздайте узел:
GNS3 берёт код из образа, а не из папки проекта.
