"""Точка входа FastAPI-приложения OutpostGate Pro."""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.agent import apply as agent
from app.api.routes import auth as auth_routes
from app.api.routes import dhcp, dns, files, firewall, gre, interfaces, ip_addresses, ip_routes, lan, monitor, qos, routing, scheduler, status, system, tools, vpn, wan
from app.core import auth
from app.core.config import settings
from app.services import ssh_server
from app.services import system as system_svc
from app.services import lan as lan_svc
from app.services import routing as routing_svc
from app.services import exporters as exporters_svc
from app.services import files as files_svc
from app.services import monitor as monitor_svc
from app.services import multiwan as multiwan_svc
from app.services import ntp as ntp_svc
from app.services import scheduler as scheduler_svc
from app.services import vpn as vpn_svc
from app.services import wan as wan_svc


@asynccontextmanager
async def lifespan(_: FastAPI):
    auth.ensure_admin()                        # первый запуск: admin + пароль в docker logs
    system_svc.safe_mode.recover_on_startup()  # перезапуск посреди Safe Mode = откат
    # Агент работает внутри процесса API: DHCP-клиентом WAN управляет этот процесс
    # в отдельном потоке: pyroute2 не должен видеть цикл событий uvicorn
    await asyncio.to_thread(agent.apply_startup)
    ssh = await ssh_server.start()             # CLI в стиле MikroTik по SSH
    monitor_svc.collector.start()              # метрики для дашборда и экспорта (раз в 10 с)
    multiwan_svc.checker.start()               # два провайдера: проверка связи и переключение
    scheduler_svc.runner.start()               # задачи по расписанию
    yield
    if ssh:
        ssh.close()
    scheduler_svc.runner.stop()
    multiwan_svc.checker.stop()
    monitor_svc.collector.stop()
    ntp_svc.stop()
    exporters_svc.stop()           # snmpd и Zabbix agent
    routing_svc.stop()
    vpn_svc.stop_all()
    files_svc.stop()
    lan_svc.stop_services()        # Kea и BIND
    wan_svc.stop_dhcp()   # корректно отпустить аренду при остановке


app = FastAPI(
    title="OutpostGate Pro",
    version=settings.version,
    description="OutpostGate Pro — офисный VPN-шлюз с OSPF и BGP: REST API (идеи RouterOS)",
    lifespan=lifespan,
)


@app.middleware("http")
async def security(request: Request, call_next):
    """Вход и права для /api, журнал изменений, свежие веб-файлы."""
    path, method = request.url.path, request.method
    user = auth.user_from_token(auth.token_from(request.cookies, request.headers)) if path.startswith("/api") else None
    if denied := auth.check_access(path, method, user):
        return JSONResponse(status_code=denied[0], content={"detail": denied[1]})
    request.state.user = user.name if user else "-"

    response = await call_next(request)

    if path.startswith("/api") and method in ("POST", "PUT", "PATCH", "DELETE") \
            and not path.startswith("/api/auth/"):
        system_svc.audit(request.state.user, method, path, response.status_code,
                         request.client.host if request.client else "-")
    if not path.startswith("/api"):
        # браузер всегда сверяет веб-файлы с сервером — после обновления не будет старого app.js
        response.headers["Cache-Control"] = "no-cache"
    return response


# API: основные разделы
app.include_router(auth_routes.router, prefix="/api/auth", tags=["Auth"])
app.include_router(status.router, prefix="/api/status", tags=["Status"])
app.include_router(system.router, prefix="/api/system", tags=["System"])
app.include_router(wan.router, prefix="/api/wan", tags=["WAN"])
app.include_router(lan.router, prefix="/api/lan", tags=["LAN"])
app.include_router(dhcp.router, prefix="/api/dhcp", tags=["DHCP"])
app.include_router(dns.router, prefix="/api/dns", tags=["DNS"])
app.include_router(files.router, prefix="/api/files", tags=["Files"])
app.include_router(vpn.router, prefix="/api/vpn", tags=["VPN"])
app.include_router(gre.router, prefix="/api/gre", tags=["GRE"])
app.include_router(firewall.router, prefix="/api/firewall", tags=["Firewall"])
app.include_router(routing.router, prefix="/api/routing", tags=["Routing"])
app.include_router(tools.router, prefix="/api/tools", tags=["Tools"])
app.include_router(monitor.router, prefix="/api/monitor", tags=["Monitoring"])
app.include_router(qos.router, prefix="/api/qos", tags=["QoS"])
app.include_router(scheduler.router, prefix="/api/scheduler", tags=["Scheduler"])
app.include_router(monitor.metrics_router)   # GET /metrics для Prometheus — до веб-файлов

# API: интерфейсы, адреса, маршруты — двигатель под WAN / LAN / VPN; в вебе их нет, есть в CLI
app.include_router(interfaces.router, prefix="/api/interfaces", tags=["Interfaces"])
app.include_router(ip_addresses.router, prefix="/api/ip/addresses", tags=["IP Addresses"])
app.include_router(ip_routes.router, prefix="/api/ip/routes", tags=["IP Routes"])

# Веб-интерфейс (статические файлы) — монтируется последним
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
