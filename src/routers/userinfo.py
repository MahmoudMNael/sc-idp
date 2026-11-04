import uuid

from fastapi import APIRouter, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.deps import db_dep, s_dep
from src.core.oauth_errors import token_error
from src.core.settings import Settings
from src.models import User
from src.services.tokens import TokenError, verify_access_token

router = APIRouter()


@router.get("/userinfo")
async def userinfo(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    header = request.headers.get("authorization") or ""
    if not header.lower().startswith("bearer "):
        return token_error("invalid_request", "missing bearer token", 401)
    token = header.split(" ", 1)[1]
    try:
        claims = await verify_access_token(session, settings, token)
    except (TokenError, Exception):
        return token_error("invalid_token", status=401)
    try:
        user = await session.get(User, uuid.UUID(str(claims["sub"])))
    except (KeyError, ValueError):
        return token_error("invalid_token", status=401)
    if user is None or not user.is_active:
        return token_error("invalid_token", status=401)
    body = {"sub": str(user.id)}
    scopes_set = set((claims.get("scope") or "").split())
    if "email" in scopes_set:
        body["email"] = user.email
        body["email_verified"] = user.email_verified
    if "profile" in scopes_set:
        if user.first_name:
            body["given_name"] = user.first_name
        if user.last_name:
            body["family_name"] = user.last_name
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
        if full_name:
            body["name"] = full_name
    if "idp_roles" in scopes_set or "roles" in scopes_set:
        from src.services.roles import get_user_roles

        body["idp_roles"] = await get_user_roles(session, user.id)
    return body
