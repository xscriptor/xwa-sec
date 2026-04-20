import json
from datetime import datetime
from typing import List

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import database, models
from ..auth.deps import get_current_user, require_roles
from .schemas import ScheduleCreate, ScheduleRead, ScheduleUpdate

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


def _compute_next_run(cron_expression: str, base: datetime | None = None) -> datetime:
    iterator = croniter(cron_expression, base or datetime.utcnow())
    return iterator.get_next(datetime)


def _to_read(record: models.ScheduledScan) -> ScheduleRead:
    try:
        config = json.loads(record.config_json or "{}")
    except json.JSONDecodeError:
        config = {}
    return ScheduleRead(
        id=record.id,
        name=record.name,
        scan_type=record.scan_type,
        target=record.target,
        config=config,
        cron_expression=record.cron_expression,
        is_enabled=record.is_enabled,
        created_by_id=record.created_by_id,
        created_at=record.created_at,
        updated_at=record.updated_at,
        last_run_at=record.last_run_at,
        next_run_at=record.next_run_at,
        last_scan_id=record.last_scan_id,
    )


@router.get("", response_model=List[ScheduleRead])
def list_schedules(
    db: Session = Depends(database.get_db),
    _user: models.User = Depends(get_current_user),
):
    records = db.query(models.ScheduledScan).order_by(models.ScheduledScan.id.desc()).all()
    return [_to_read(r) for r in records]


@router.post("", response_model=ScheduleRead, status_code=status.HTTP_201_CREATED)
def create_schedule(
    payload: ScheduleCreate,
    db: Session = Depends(database.get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
):
    try:
        validated_target = payload.validated_target()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    record = models.ScheduledScan(
        name=payload.name,
        scan_type=payload.scan_type,
        target=validated_target,
        config_json=json.dumps(payload.config),
        cron_expression=payload.cron_expression,
        is_enabled=payload.is_enabled,
        created_by_id=user.id,
        next_run_at=_compute_next_run(payload.cron_expression) if payload.is_enabled else None,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return _to_read(record)


@router.patch("/{schedule_id}", response_model=ScheduleRead)
def update_schedule(
    schedule_id: int,
    payload: ScheduleUpdate,
    db: Session = Depends(database.get_db),
    _user: models.User = Depends(require_roles("admin", "operator")),
):
    record = db.query(models.ScheduledScan).filter(models.ScheduledScan.id == schedule_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if payload.name is not None:
        record.name = payload.name
    if payload.target is not None:
        from ..validators import validate_host_target, validate_url_target, InvalidTargetError
        try:
            record.target = (
                validate_url_target(payload.target)
                if record.scan_type == "vuln_crawl"
                else validate_host_target(payload.target)
            )
        except InvalidTargetError as exc:
            raise HTTPException(status_code=400, detail=exc.detail)
    if payload.config is not None:
        record.config_json = json.dumps(payload.config)
    if payload.cron_expression is not None:
        record.cron_expression = payload.cron_expression
    if payload.is_enabled is not None:
        record.is_enabled = payload.is_enabled

    record.next_run_at = (
        _compute_next_run(record.cron_expression) if record.is_enabled else None
    )
    db.commit()
    db.refresh(record)
    return _to_read(record)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: int,
    db: Session = Depends(database.get_db),
    _user: models.User = Depends(require_roles("admin", "operator")),
):
    record = db.query(models.ScheduledScan).filter(models.ScheduledScan.id == schedule_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(record)
    db.commit()
    return None
