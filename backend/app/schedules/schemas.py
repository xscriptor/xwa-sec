from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator
from croniter import croniter

from ..validators import validate_host_target, validate_url_target, InvalidTargetError


ALLOWED_SCAN_TYPES = {"port_scan", "web_recon", "vuln_crawl"}


class ScheduleBase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    scan_type: str
    target: str
    config: Dict[str, Any] = Field(default_factory=dict)
    cron_expression: str = Field(min_length=1, max_length=128)
    is_enabled: bool = True

    @field_validator("scan_type")
    @classmethod
    def _check_scan_type(cls, value: str) -> str:
        if value not in ALLOWED_SCAN_TYPES:
            raise ValueError(f"scan_type must be one of {sorted(ALLOWED_SCAN_TYPES)}")
        return value

    @field_validator("cron_expression")
    @classmethod
    def _check_cron(cls, value: str) -> str:
        value = value.strip()
        if not croniter.is_valid(value):
            raise ValueError("invalid cron expression (expected 5 fields)")
        return value

    def validated_target(self) -> str:
        try:
            if self.scan_type == "vuln_crawl":
                return validate_url_target(self.target)
            return validate_host_target(self.target)
        except InvalidTargetError as exc:
            raise ValueError(exc.detail) from exc


class ScheduleCreate(ScheduleBase):
    pass


class ScheduleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    target: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    cron_expression: Optional[str] = Field(default=None, min_length=1, max_length=128)
    is_enabled: Optional[bool] = None

    @field_validator("cron_expression")
    @classmethod
    def _check_cron(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        if not croniter.is_valid(value):
            raise ValueError("invalid cron expression (expected 5 fields)")
        return value


class ScheduleRead(BaseModel):
    id: int
    name: str
    scan_type: str
    target: str
    config: Dict[str, Any]
    cron_expression: str
    is_enabled: bool
    created_by_id: Optional[int]
    created_at: datetime
    updated_at: datetime
    last_run_at: Optional[datetime]
    next_run_at: Optional[datetime]
    last_scan_id: Optional[int]
