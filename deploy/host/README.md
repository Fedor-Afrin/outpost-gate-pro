# Развёртывание на сервере / VM

Docker по умолчанию ставит политику `FORWARD` в `DROP` — транзитный трафик
роутера перестанет ходить. Поэтому Docker'у запрещаем трогать фаервол:

```bash
sudo cp daemon.json.example /etc/docker/daemon.json
sudo systemctl restart docker

sudo mkdir -p /etc/outpost-gate-pro /var/lib/outpost-gate-pro
sudo cp ../../config/router.yaml /etc/outpost-gate-pro/

docker compose up -d --build
```

Также отключите/ограничьте netplan и NetworkManager на управляемых интерфейсах,
чтобы они не перетирали настройки роутера.

## Переход со старых названий (ubuntu-router или outpost-gate -> outpost-gate-pro)

Если роутер уже работал под старым названием, перенесите настройки один раз:
```bash
docker compose -p ubuntu-router down 2>/dev/null || true
# было outpost-gate:
sudo mv /etc/outpost-gate /etc/outpost-gate-pro
sudo mv /var/lib/outpost-gate /var/lib/outpost-gate-pro
# или было ubuntu-router:
# sudo mv /etc/ubuntu-router /etc/outpost-gate-pro && sudo mv /var/lib/ubuntu-router /var/lib/outpost-gate-pro
docker compose up -d --build
```
Старые таблицы фаервола (`inet ubuntu_router`, `inet outpost_gate`) удаляются автоматически.

## Командная строка (CLI)
`ssh -p 2222 admin@<адрес роутера>` — оболочка в стиле MikroTik. Порт 22 остаётся SSH самого сервера.
