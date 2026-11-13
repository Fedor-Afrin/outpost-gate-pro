"""
Раздел QoS: ограничение скорости сегментов и устройств, приоритет голосу (SIP/RTP).

  GET /api/qos     настройки, сегменты, счётчики очередей
  PUT /api/qos     сохранить целиком и применить (tc + метки DSCP в фаерволе)
"""
from fastapi import APIRouter, HTTPException

from app.models.qos import QosConfig, QosStatus
from app.services import qos as svc

router = APIRouter()


@router.get("", response_model=QosStatus)
def get_qos():
    return svc.status()


@router.put("", response_model=QosStatus)
def put_qos(data: QosConfig):
    try:
        return svc.update(data)
    except svc.QosError as e:
        raise HTTPException(status_code=e.status, detail=e.message)
