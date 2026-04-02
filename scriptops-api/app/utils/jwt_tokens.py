"""JWT access tokens for password-based dashboard login."""

from __future__ import annotations

import os
import time
from typing import Optional

import jwt

from app.models.schemas import Role, TokenUser

_ALGO = "HS256"
_DEFAULT_SECRET = "scriptops-dev-only-set-SCRIPTOPS_JWT_SECRET-in-production-min-32-chars"


def _secret() -> str:
    return os.environ.get("SCRIPTOPS_JWT_SECRET", _DEFAULT_SECRET)


def _ttl_seconds() -> int:
    raw = os.environ.get("SCRIPTOPS_JWT_EXPIRE_HOURS", "24")
    try:
        hours = max(1, min(720, int(raw)))
    except ValueError:
        hours = 24
    return hours * 3600


def create_access_token(user: TokenUser) -> str:
    now = int(time.time())
    payload = {
        "typ": "access",
        "user_id": user.user_id,
        "name": user.name,
        "email": user.email,
        "role": user.role.value,
        "key_name": user.key_name,
        "iat": now,
        "exp": now + _ttl_seconds(),
    }
    return jwt.encode(payload, _secret(), algorithm=_ALGO)


def decode_access_token(token: str) -> Optional[TokenUser]:
    try:
        payload = jwt.decode(token, _secret(), algorithms=[_ALGO])
        if payload.get("typ") != "access":
            return None
        return TokenUser(
            user_id=payload["user_id"],
            name=payload["name"],
            email=payload["email"],
            role=Role(payload["role"]),
            key_name=payload.get("key_name") or "session",
        )
    except Exception:
        return None
