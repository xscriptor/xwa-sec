"""Centralised rate limiter.

Uses Redis as the shared backend when REDIS_URL is set; falls back to an
in-memory limiter for dev if not. Key function prefers the authenticated
user id (via JWT sub) over the remote IP so abusive users are limited
across IPs.
"""
import os

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from .auth.security import JWTError, decode_access_token


def _key_func(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1]
        try:
            payload = decode_access_token(token)
            sub = payload.get("sub")
            if sub:
                return f"user:{sub}"
        except JWTError:
            pass
    return f"ip:{get_remote_address(request)}"


_storage_uri = os.getenv("REDIS_URL") or "memory://"

limiter = Limiter(key_func=_key_func, storage_uri=_storage_uri)
