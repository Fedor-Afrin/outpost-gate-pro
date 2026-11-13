"""
Раздел Scheduler (/system scheduler): задачи по расписанию.

  GET    /api/scheduler                  задачи, ближайший запуск, журнал, из чего выбирать в форме
  POST   /api/scheduler/tasks            добавить задачу
  PUT    /api/scheduler/tasks/{id}       изменить
  DELETE /api/scheduler/tasks/{id}       удалить
  POST   /api/scheduler/tasks/{id}/run   выполнить сейчас
"""
from fastapi import APIRouter, HTTPException

from app.models.scheduler import RunRecord, SchedulerStatus, Task
from app.services import scheduler as svc

router = APIRouter()


def _call(fn, *args):
    try:
        return fn(*args)
    except svc.SchedulerError as e:
        raise HTTPException(status_code=e.status, detail=e.message)


@router.get("", response_model=SchedulerStatus)
def get_scheduler():
    return svc.status()


@router.post("/tasks", response_model=Task, status_code=201)
def add_task(data: Task):
    return _call(svc.add, data)


@router.put("/tasks/{tid}", response_model=Task)
def update_task(tid: int, data: Task):
    return _call(svc.update, tid, data)


@router.delete("/tasks/{tid}", status_code=204)
def delete_task(tid: int):
    _call(svc.delete, tid)


@router.post("/tasks/{tid}/run", response_model=RunRecord)
def run_task(tid: int):
    return _call(svc.run_now, tid)
