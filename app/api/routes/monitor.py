"""
Раздел Monitoring: дашборд и экспорт метрик.

  GET /api/monitor                      последний замер: система, интерфейсы, связь, клиенты, сервисы
  GET /api/monitor/history?keys=..&range=1h|24h|7d|30d
                                        история для графиков (ключи: cpu, mem, temp, load, clients,
                                        if:<имя>:rx|tx, ping:<имя>:rtt|loss)
  GET /api/monitor/settings             настройки экспорта и состояние snmpd / Zabbix agent
  PUT /api/monitor/settings             сохранить настройки экспорта целиком и применить

  GET /metrics                          для Prometheus (вне /api: свой доступ — LAN, список, токен)
"""
from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from app.core.config import settings
from app.models.monitoring import MonitoringSettings
from app.services import exporters, monitor

router = APIRouter()
metrics_router = APIRouter()


@router.get("")
def current():
    return monitor.current()


@router.get("/history")
def history(keys: str = Query(..., description="через запятую"), range: str = Query("1h")):  # noqa: A002
    try:
        return monitor.history([k for k in keys.split(",") if k], range)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/settings", response_model=MonitoringSettings)
def get_settings():
    return exporters.status()


@router.put("/settings", response_model=MonitoringSettings)
def put_settings(data: dict = Body(..., examples=[{"prometheus": {"enabled": True, "allowed": ["10.0.0.5"]}}])):
    try:
        return exporters.update(data)
    except exporters.ExportError as e:
        raise HTTPException(status_code=e.status, detail=e.message)


@metrics_router.get("/metrics", include_in_schema=True, tags=["Monitoring"],
                    response_class=PlainTextResponse)
def metrics(request: Request, token: str | None = None):
    cfg = exporters.get_config()
    denied = exporters.metrics_access(cfg, request.client.host if request.client else None,
                                      request.headers.get("authorization"), token, exporters.lan_networks())
    if denied:
        return PlainTextResponse(denied[1] + "\n", status_code=denied[0],
                                 headers={"WWW-Authenticate": "Bearer"} if denied[0] == 401 else None)
    text = exporters.prometheus_text(monitor.collector.snapshot, exporters.identity(), settings.version)
    return PlainTextResponse(text, media_type="text/plain; version=0.0.4; charset=utf-8")
