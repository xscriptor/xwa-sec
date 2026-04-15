from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol


class LogCallback(Protocol):
    async def __call__(self, message: str) -> None:
        ...


@dataclass
class ReconRuntimeConfig:
    target: str
    recon_types: List[str]
    timeout_seconds: int = 300


@dataclass
class ReconSummary:
    target: str
    executed_modules: List[str]
    sections_collected: int
    status: str
    timestamp: str


@dataclass
class ReconEnvelope:
    event_type: str
    target: str
    results: Dict[str, Any]
    timestamp: str
    error: Optional[str] = None
