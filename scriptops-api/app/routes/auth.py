"""
ScriptOps — Auth Routes (API key management)
"""

from fastapi import APIRouter, Depends, HTTPException
from app.middleware.auth import (
    get_current_user,
    register_api_key,
    require_role,
    resolve_api_key,
    unregister_api_key,
)
from app.models.schemas import Role, TokenUser, APIKeyCreate, APIKeyResponse, LoginRequest, LoginResponse
from app.services.user_accounts import verify_user_password
from app.utils.jwt_tokens import create_access_token
from app.utils.logger import setup_logger
from datetime import datetime, timezone
import uuid, hashlib

logger = setup_logger(__name__)
router = APIRouter()

_KEYS = {}   # key_id -> record


@router.post("/login", summary="Login", response_model=LoginResponse)
async def login(req: LoginRequest):
    """
    **API key:** `{ "api_key": "sk_live_..." }` — returns `user` only; send the key on later requests.

    **Password:** `{ "username": "arjun", "password": "demo" }` — returns `user`, `access_token`, `token_type: bearer`.
    Use `Authorization: Bearer <access_token>` (or `X-ScriptOps-Key` with the token value) on later requests.
    """
    if req.api_key:
        user = resolve_api_key(req.api_key)
        if not user:
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_api_key", "message": "API key not recognised or has been revoked."},
            )
        return LoginResponse(user=user)

    user = verify_user_password(req.username or "", req.password or "")
    if not user:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_credentials", "message": "Invalid username or password."},
        )
    token = create_access_token(user)
    return LoginResponse(user=user, access_token=token, token_type="bearer")


@router.get("/me", summary="Current User Info")
async def whoami(user: TokenUser = Depends(get_current_user)):
    return user

@router.post("/keys", summary="Create API Key", response_model=APIKeyResponse, status_code=201)
async def create_key(
    req: APIKeyCreate,
    user: TokenUser = Depends(require_role(Role.admin)),
):
    raw  = f"sk_live_{uuid.uuid4().hex}"
    kid  = f"key_{uuid.uuid4().hex[:8]}"
    record = {
        "key_id": kid, "name": req.name, "key": raw,
        "scope": req.scope, "created_at": datetime.now(timezone.utc),
        "created_by": user.name,
    }
    _KEYS[kid] = record
    key_user = TokenUser(
        user_id=kid,
        name=user.name,
        email=user.email,
        role=req.scope,
        key_name=req.name,
    )
    register_api_key(raw, key_user)
    logger.info(f"API key '{req.name}' created by {user.name} with scope={req.scope}")
    return record

@router.delete("/keys/{key_id}", summary="Revoke API Key", status_code=204)
async def revoke_key(key_id: str, user: TokenUser = Depends(require_role(Role.admin))):
    if key_id not in _KEYS:
        raise HTTPException(404, detail={"error":"not_found"})
    rec = _KEYS[key_id]
    if rec.get("key"):
        unregister_api_key(rec["key"])
    del _KEYS[key_id]
    logger.info(f"API key {key_id} revoked by {user.name}")
    return None

@router.get("/keys", summary="List API Keys")
async def list_keys(user: TokenUser = Depends(require_role(Role.admin))):
    safe = [{k: v for k, v in rec.items() if k != "key"} for rec in _KEYS.values()]
    return {"items": safe, "total": len(safe)}
