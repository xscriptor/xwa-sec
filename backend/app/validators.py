"""Input validators for user-provided targets.

Protects against argument injection to nmap/sqlmap/playwright/etc. and
URL-shaped input that could exfiltrate credentials or escape the intended scope.
"""
import ipaddress
import re
from urllib.parse import urlparse

from fastapi import HTTPException, status


_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_DISALLOWED_CHARS = re.compile(r"[\s;|&`$<>\\\"']")


class InvalidTargetError(HTTPException):
    def __init__(self, reason: str):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid target: {reason}")


def _is_valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    labels = host.rstrip(".").split(".")
    return all(_HOSTNAME_LABEL.match(label) for label in labels)


def _is_valid_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate_host_target(raw: str) -> str:
    """Accept a bare host/IP (optionally with :port) for nmap-style scans.

    Rejects anything that contains shell metacharacters, dashes at the start
    (which nmap could interpret as a flag), or URL schemes.
    """
    if not raw or not isinstance(raw, str):
        raise InvalidTargetError("target is required")

    candidate = raw.strip()
    if len(candidate) > 253:
        raise InvalidTargetError("target too long")

    if _DISALLOWED_CHARS.search(candidate):
        raise InvalidTargetError("target contains disallowed characters")

    if candidate.startswith("-"):
        raise InvalidTargetError("target cannot start with '-' (argument injection)")

    if "://" in candidate:
        raise InvalidTargetError("URLs not accepted here, provide a host or IP")

    host = candidate
    if ":" in candidate and not _is_valid_ip(candidate):
        host, _, port = candidate.rpartition(":")
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            raise InvalidTargetError("invalid port")

    if _is_valid_ip(host) or _is_valid_hostname(host):
        return candidate

    raise InvalidTargetError("target must be a hostname or IP")


def validate_url_target(raw: str) -> str:
    """Accept a full http(s) URL for DAST/recon scans.

    Rejects URLs with embedded credentials, non-http schemes, or shell metacharacters.
    """
    if not raw or not isinstance(raw, str):
        raise InvalidTargetError("target is required")

    candidate = raw.strip()
    if len(candidate) > 2048:
        raise InvalidTargetError("target URL too long")

    if _DISALLOWED_CHARS.search(candidate):
        raise InvalidTargetError("target contains disallowed characters")

    if "://" not in candidate:
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        raise InvalidTargetError("only http/https schemes allowed")

    if parsed.username or parsed.password:
        raise InvalidTargetError("credentials in URL not allowed")

    host = parsed.hostname or ""
    if not (_is_valid_ip(host) or _is_valid_hostname(host)):
        raise InvalidTargetError("invalid host in URL")

    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise InvalidTargetError("invalid port in URL")

    return candidate
