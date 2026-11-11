"""Status: GET /api/status — сводка для стартовой страницы."""
from fastapi import APIRouter

from app.services import status as svc

router = APIRouter()


@router.get("")
def get_status():
    return svc.overview()
