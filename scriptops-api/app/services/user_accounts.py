"""In-memory username/password accounts (replace with DB in production)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import bcrypt

from app.models.schemas import Role, TokenUser

_RAW_ACCOUNTS: List[Dict[str, Any]] = [
    {
        "username": "arjun",
        "password": "demo",
        "user_id": "usr_001",
        "name": "Arjun Desai",
        "email": "arjun@corp.internal",
        "role": Role.admin,
    },
    {
        "username": "priya",
        "password": "demo",
        "user_id": "usr_002",
        "name": "Priya Mehta",
        "email": "priya@corp.internal",
        "role": Role.manager,
    },
    {
        "username": "rahul",
        "password": "demo",
        "user_id": "usr_003",
        "name": "Rahul Khanna",
        "email": "rahul@corp.internal",
        "role": Role.operator,
    },
    {
        "username": "sneha",
        "password": "demo",
        "user_id": "usr_004",
        "name": "Sneha Joshi",
        "email": "sneha@corp.internal",
        "role": Role.viewer,
    },
]

_USER_DB: Dict[str, Dict[str, Any]] = {}


def _build_db() -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for row in _RAW_ACCOUNTS:
        un = row["username"].lower()
        h = bcrypt.hashpw(row["password"].encode("utf-8"), bcrypt.gensalt())
        out[un] = {
            "user_id": row["user_id"],
            "name": row["name"],
            "email": row["email"],
            "role": row["role"],
            "password_hash": h,
        }
    return out


_USER_DB = _build_db()


def verify_user_password(username: str, password: str) -> Optional[TokenUser]:
    if not username or password is None:
        return None
    row = _USER_DB.get(username.strip().lower())
    if not row:
        return None
    if not bcrypt.checkpw(password.encode("utf-8"), row["password_hash"]):
        return None
    return TokenUser(
        user_id=row["user_id"],
        name=row["name"],
        email=row["email"],
        role=row["role"],
        key_name="password",
    )
