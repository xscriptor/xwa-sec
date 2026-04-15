import re
from typing import Dict, List

import httpx

from ..target import ensure_base_url
from ..types import LogCallback


FRONTEND_SIGNATURES = {
    "react": [r"react", r"__react"],
    "vue": [r"vue", r"__vue__"],
    "angular": [r"angular", r"ng-version"],
    "jquery": [r"jquery"],
    "bootstrap": [r"bootstrap", r"bs-"],
}


async def run(target: str, log: LogCallback) -> Dict[str, object]:
    base_url = ensure_base_url(target)
    backend: List[str] = []
    frontend: List[str] = []
    cdn = None
    interesting_findings: List[str] = []

    await log(f"[tech] inspecting stack for {base_url}")

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        response = await client.get(base_url)

    server_header = response.headers.get("Server", "").lower()

    if "nginx" in server_header:
        backend.append("nginx")
    elif "apache" in server_header:
        backend.append("apache")
    elif "iis" in server_header or "asp.net" in server_header:
        backend.append("iis/dotnet")

    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    if "cf-cache-status" in headers_lower:
        cdn = "cloudflare"
    elif "x-cache" in headers_lower:
        cdn = "fastly"

    html = response.text.lower()
    for name, patterns in FRONTEND_SIGNATURES.items():
        if any(re.search(pattern, html) for pattern in patterns):
            frontend.append(name)

    if any(token in html for token in (".env", "config.php", "settings.py")):
        interesting_findings.append("possible config reference in html")

    await log(f"  backend={','.join(backend) if backend else 'unknown'}")
    await log(f"  frontend={','.join(frontend) if frontend else 'unknown'}")
    if cdn:
        await log(f"  cdn={cdn}")

    return {
        "frontend": frontend,
        "backend": backend,
        "cdn": cdn,
        "interesting_findings": interesting_findings,
    }
