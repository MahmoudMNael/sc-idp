import hmac
import secrets

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit import audit
from src.crypto import hash_token
from src.deps import db_dep, s_dep
from src.keys import rotate_keys
from src.models import IdpRole, OAuthClient, User
from src.roles import (
    assign_role_to_user,
    ensure_role_exists,
    get_email_preassigned_roles,
    get_user_roles,
    preassign_role_to_email,
    remove_preassigned_role_from_email,
    remove_role_from_user,
)
from src.settings import Settings

router = APIRouter(prefix="/admin")


class ClientIn(BaseModel):
    name: str
    redirect_uris: list[str] = Field(min_length=1)
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(default_factory=lambda: ["openid", "email"])
    is_first_party: bool = True
    client_id: str | None = None


def _admin(settings: Settings, authorization: str | None) -> None:
    if not settings.idp_admin_api_key:
        raise HTTPException(503, "IDP_ADMIN_API_KEY is not set")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing admin bearer token")
    got = authorization.split(" ", 1)[1]
    if not hmac.compare_digest(got, settings.idp_admin_api_key):
        raise HTTPException(401, "invalid admin bearer token")


@router.post("/clients")
async def create_client(
    body: ClientIn,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    authorization: str | None = Header(default=None),
):
    _admin(settings, authorization)
    cid = body.client_id or secrets.token_urlsafe(16)
    if await session.get(OAuthClient, cid):
        raise HTTPException(409, "client_id already exists")
    secret = secrets.token_urlsafe(32)
    session.add(
        OAuthClient(
            client_id=cid,
            name=body.name,
            client_secret_hash=hash_token(settings.token_hash_pepper, secret),
            redirect_uris=body.redirect_uris,
            post_logout_redirect_uris=body.post_logout_redirect_uris,
            allowed_scopes=body.allowed_scopes,
            is_first_party=body.is_first_party,
        )
    )
    await audit(session, "admin_create_client", client_id=cid, detail={"name": body.name})
    return {"client_id": cid, "client_secret": secret}


@router.post("/keys/rotate")
async def rotate(
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    authorization: str | None = Header(default=None),
):
    _admin(settings, authorization)
    kid = await rotate_keys(session, settings)
    await audit(session, "admin_rotate_keys", detail={"kid": kid})
    return {"kid": kid, "status": "active"}


class RoleIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = None


class RoleAssignIn(BaseModel):
    email: str = Field(min_length=3)
    role: str = Field(min_length=1, max_length=64)


@router.post("/roles")
async def create_role(
    body: RoleIn,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    authorization: str | None = Header(default=None),
):
    _admin(settings, authorization)
    role_name = body.name.strip().lower()
    if await session.get(IdpRole, role_name):
        raise HTTPException(409, "role already exists")
    role = IdpRole(name=role_name, description=body.description)
    session.add(role)
    await session.flush()
    await audit(session, "admin_create_role", detail={"role": role_name})
    return {"name": role.name, "description": role.description}


@router.get("/roles")
async def list_roles(
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    authorization: str | None = Header(default=None),
):
    _admin(settings, authorization)
    rows = (await session.execute(select(IdpRole).order_by(IdpRole.name))).scalars().all()
    return [{"name": r.name, "description": r.description} for r in rows]


@router.post("/roles/assign")
async def assign_role(
    body: RoleAssignIn,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    authorization: str | None = Header(default=None),
):
    _admin(settings, authorization)
    email_n = body.email.strip().lower()
    role_name = body.role.strip().lower()
    await ensure_role_exists(session, role_name)
    await preassign_role_to_email(session, email_n, role_name)

    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    user_assigned = False
    if user:
        user_assigned = await assign_role_to_user(session, user.id, role_name)

    await audit(session, "admin_assign_role", detail={"email": email_n, "role": role_name})
    return {
        "email": email_n,
        "role": role_name,
        "preassigned": True,
        "assigned_to_active_user": user_assigned or (user is not None),
    }


@router.post("/roles/unassign")
async def unassign_role(
    body: RoleAssignIn,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    authorization: str | None = Header(default=None),
):
    _admin(settings, authorization)
    email_n = body.email.strip().lower()
    role_name = body.role.strip().lower()
    removed_pre = await remove_preassigned_role_from_email(session, email_n, role_name)

    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    removed_user = False
    if user:
        removed_user = await remove_role_from_user(session, user.id, role_name)

    await audit(session, "admin_unassign_role", detail={"email": email_n, "role": role_name})
    return {
        "email": email_n,
        "role": role_name,
        "removed_preassignment": removed_pre,
        "removed_user_role": removed_user,
    }


@router.get("/roles/assignments")
async def get_assignments(
    email: str,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    authorization: str | None = Header(default=None),
):
    _admin(settings, authorization)
    email_n = email.strip().lower()
    preassigned = await get_email_preassigned_roles(session, email_n)
    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    user_roles = await get_user_roles(session, user.id) if user else []
    return {
        "email": email_n,
        "user_id": str(user.id) if user else None,
        "user_roles": user_roles,
        "preassigned_roles": preassigned,
    }

