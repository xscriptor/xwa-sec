import re
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import httpx

from ..target import ensure_base_url
from ..types import LogCallback


API_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui",
    "/swagger-ui/",
    "/api-docs",
    "/graphql",
    "/actuator",
    "/actuator/health",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/rest",
    "/rest/api",
    "/.well-known/openapi.json",
    "/docs",
    "/redoc",
    "/api/",
    "/v1",
    "/v2",
    "/wp-json",
]


SIGNAL_STATUSES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}
PATH_SIGNAL_REGEX = re.compile(r"[\"'](/(?:api|graphql|rest|v\d+/api|wp-json)[^\"'\s?#]{0,120})[\"']", re.IGNORECASE)
DOC_SIGNAL_REGEX = re.compile(r"[\"'](/(?:docs?|swagger(?:-ui)?|openapi(?:\.json)?|redoc)[^\"'\s?#]{0,120})[\"']", re.IGNORECASE)


FRAMEWORK_HINTS = {
    "django": ["csrftoken", "django"],
    "rails": ["x-runtime", "rails"],
    "laravel": ["laravel_session", "x-powered-by"],
    "flask": ["werkzeug", "flask"],
    "spring-boot": ["application/hal+json", "spring"],
    "dotnet": ["x-aspnet-version", "asp.net"],
}


def _candidate_base_urls(target: str) -> List[str]:
    normalized = ensure_base_url(target)
    parsed = urlparse(normalized)
    host = (parsed.netloc or parsed.path).strip("/")
    if not host:
        return []

    preferred = parsed.scheme if parsed.scheme in ("http", "https") else "https"
    ordered: List[str] = []
    for scheme in (preferred, "https", "http"):
        candidate = f"{scheme}://{host}"
        if candidate not in ordered:
            ordered.append(candidate)
    return ordered


def _sanitize_path(path: str) -> str:
    sanitized = path.strip()
    if not sanitized:
        return ""
    if not sanitized.startswith("/"):
        sanitized = f"/{sanitized}"
    sanitized = sanitized.split("?", 1)[0].split("#", 1)[0]
    return sanitized


def _extract_signal_paths(html: str) -> Set[str]:
    paths: Set[str] = set()
    for match in PATH_SIGNAL_REGEX.findall(html):
        path = _sanitize_path(match)
        if path:
            paths.add(path)
    return paths


def _extract_doc_paths(html: str) -> Set[str]:
    paths: Set[str] = set()
    for match in DOC_SIGNAL_REGEX.findall(html):
        path = _sanitize_path(match)
        if path:
            paths.add(path)
    return paths


async def run(target: str, log: LogCallback) -> Dict[str, object]:
    apis_found: List[Dict[str, object]] = []
    docs: Set[str] = set()
    framework = None
    headers: Dict[str, str] = {}
    selected_origin = ""
    candidate_paths: List[str] = []
    base_candidates = _candidate_base_urls(target)

    if not base_candidates:
        await log("[apis] could not build a valid base url")
        return {
            "apis_found": [],
            "documentation": [],
            "framework": None,
            "headers_analysis": {
                "server": "unknown",
                "x-powered-by": "unknown",
                "x-aspnet-version": "unknown",
            },
            "graphql_enabled": False,
            "base_url": "unreachable",
            "probed_paths": 0,
        }

    await log(f"[apis] scanning endpoint candidates on {', '.join(base_candidates)}")

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        root_response = None
        for base_url in base_candidates:
            try:
                probe = await client.get(base_url)
                if probe.status_code < 500:
                    root_response = probe
                    parsed = urlparse(str(probe.url))
                    selected_origin = f"{parsed.scheme}://{parsed.netloc}"
                    await log(f"  selected base={selected_origin} ({probe.status_code})")
                    break
            except Exception:
                continue

        if not selected_origin and base_candidates:
            selected_origin = base_candidates[0]

        candidate_set: Set[str] = set(_sanitize_path(path) for path in API_PATHS)

        if root_response is not None:
            headers = {k.lower(): v.lower() for k, v in root_response.headers.items()}
            html_text = root_response.text or ""
            candidate_set.update(_extract_signal_paths(html_text))
            docs.update(_extract_doc_paths(html_text))

        seen: Set[str] = set()
        for path in list(API_PATHS) + sorted(candidate_set):
            normalized = _sanitize_path(path)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            candidate_paths.append(normalized)

        for path in candidate_paths:
            try:
                url = urljoin(f"{selected_origin}/", path.lstrip("/"))
                response = await client.get(url)
                if response.status_code in SIGNAL_STATUSES:
                    content_type = response.headers.get("content-type", "")
                    apis_found.append(
                        {
                            "path": path,
                            "status": response.status_code,
                            "content_type": content_type,
                        }
                    )
                    await log(f"  ok {path} ({response.status_code})")
                    if any(marker in path for marker in ("swagger", "docs", "openapi", "redoc")):
                        docs.add(path)
            except Exception:
                continue

        try:
            if not headers and selected_origin:
                root_response = await client.get(selected_origin)
                headers = {k.lower(): v.lower() for k, v in root_response.headers.items()}

            header_blob = " ".join(list(headers.keys()) + list(headers.values()))
            for name, markers in FRAMEWORK_HINTS.items():
                if any(marker in header_blob for marker in markers):
                    framework = name
                    await log(f"  framework hint: {framework}")
                    break
        except Exception:
            pass

    return {
        "apis_found": apis_found,
        "documentation": sorted(docs),
        "framework": framework,
        "headers_analysis": {
            "server": headers.get("server", "unknown"),
            "x-powered-by": headers.get("x-powered-by", "unknown"),
            "x-aspnet-version": headers.get("x-aspnet-version", "unknown"),
        },
        "graphql_enabled": any("graphql" in entry["path"] for entry in apis_found),
        "base_url": selected_origin or "unreachable",
        "probed_paths": len(candidate_paths),
    }
