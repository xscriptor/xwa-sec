from typing import Dict

import httpx

from ..target import ensure_base_url
from ..types import LogCallback


SECURITY_HEADERS = {
    "content-security-policy": "mitigates script injection",
    "x-content-type-options": "prevents mime sniffing",
    "x-frame-options": "prevents clickjacking",
    "strict-transport-security": "enforces https",
    "referrer-policy": "reduces referrer leakage",
}


async def run(target: str, log: LogCallback) -> Dict[str, object]:
    base_url = ensure_base_url(target)
    present: Dict[str, Dict[str, str]] = {}
    missing = []
    recommendations = []

    await log(f"[headers] auditing security headers for {base_url}")

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        response = await client.get(base_url)
        headers = {k.lower(): v for k, v in response.headers.items()}

    for key, description in SECURITY_HEADERS.items():
        if key in headers:
            present[key] = {
                "value": headers[key],
                "description": description,
            }
            await log(f"  ok {key}")
        else:
            missing.append(key)
            recommendations.append(f"missing {key}: {description}")
            await log(f"  miss {key}")

    missing_count = len(missing)
    if missing_count == 0:
        risk_level = "LOW"
    elif missing_count <= 2:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return {
        "present": present,
        "missing": missing,
        "risk_level": risk_level,
        "recommendations": recommendations,
    }
