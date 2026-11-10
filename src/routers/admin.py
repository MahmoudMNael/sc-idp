import hmac
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Form, Header, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.crypto import csrf_ok, hash_password, hash_token
from src.core.deps import db_dep, ip_of, s_dep
from src.core.keys import rotate_keys
from src.core.settings import Settings
from src.html import page
from src.models import AuthSession, IdpRole, OAuthClient, User, UserIdpRole
from src.services.audit import audit
from src.services.roles import (
    RoleName,
    assign_role_to_user,
    ensure_role_exists,
    get_email_preassigned_roles,
    get_user_roles,
    preassign_role_to_email,
    remove_preassigned_role_from_email,
    remove_role_from_user,
)
from src.services.sessions import load_session

router = APIRouter(prefix="/admin")


class ClientIn(BaseModel):
    name: str
    redirect_uris: list[str] = Field(min_length=1)
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
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


def _parse_lines(text: str) -> list[str]:
    lines: list[str] = []
    for line in text.replace(",", "\n").splitlines():
        item = line.strip()
        if item and item not in lines:
            lines.append(item)
    return lines


async def _get_admin_user(
    request: Request,
    session: AsyncSession,
    settings: Settings,
) -> tuple[User | None, Response | None]:
    cookie = request.cookies.get(settings.cookie_name)
    auth_session = await load_session(session, settings, cookie) if cookie else None
    if not auth_session:
        return None, RedirectResponse("/login?next=/admin/dashboard", status_code=303)
    user = await session.get(User, auth_session.user_id)
    if not user or not user.is_active:
        return None, RedirectResponse("/login?next=/admin/dashboard", status_code=303)
    user_roles = await get_user_roles(session, user.id)
    if RoleName.ADMIN not in user_roles:
        return None, page(request, settings, "error.html", status=403, error="Access forbidden: IdP admin role required.")
    return user, None


@router.get("")
@router.get("/")
async def admin_root():
    return RedirectResponse("/admin/dashboard", status_code=303)


@router.get("/dashboard")
async def admin_dashboard(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    admin_user, err_resp = await _get_admin_user(request, session, settings)
    if err_resp:
        return err_resp

    clients = (
        await session.execute(select(OAuthClient).order_by(OAuthClient.created_at.desc()))
    ).scalars().all()
    return page(
        request,
        settings,
        "admin_dashboard.html",
        current_user=admin_user,
        is_admin=True,
        clients=clients,
    )


@router.post("/dashboard/clients")
async def admin_register_client(
    request: Request,
    name: str = Form(...),
    redirect_uris: str = Form(...),
    post_logout_redirect_uris: str = Form(""),
    scopes: list[str] = Form(default_factory=list),
    is_first_party: str | None = Form(None),
    csrf_token: str = Form(...),
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    admin_user, err_resp = await _get_admin_user(request, session, settings)
    if err_resp:
        return err_resp

    clients = (
        await session.execute(select(OAuthClient).order_by(OAuthClient.created_at.desc()))
    ).scalars().all()

    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(
            request,
            settings,
            "admin_dashboard.html",
            status=400,
            current_user=admin_user,
            clients=clients,
            flash_error="Invalid or expired form token. Please try again.",
        )

    r_uris = _parse_lines(redirect_uris)
    if not r_uris:
        return page(
            request,
            settings,
            "admin_dashboard.html",
            status=400,
            current_user=admin_user,
            clients=clients,
            flash_error="At least one valid redirect URI is required.",
        )

    post_logout_uris = _parse_lines(post_logout_redirect_uris)
    allowed_scopes = list(dict.fromkeys(["openid"] + [s.strip() for s in scopes if s.strip()]))
    is_first_party_bool = is_first_party is not None and is_first_party.lower() in ("true", "1", "on", "yes")

    cid = secrets.token_urlsafe(16)
    secret = secrets.token_urlsafe(32)

    new_client = OAuthClient(
        client_id=cid,
        name=name.strip(),
        client_secret_hash=hash_token(settings.token_hash_pepper, secret),
        redirect_uris=r_uris,
        post_logout_redirect_uris=post_logout_uris,
        allowed_scopes=allowed_scopes,
        is_first_party=is_first_party_bool,
        is_active=True,
    )
    session.add(new_client)
    await audit(session, "admin_create_client", client_id=cid, detail={"name": name.strip(), "via": "dashboard"})
    await session.commit()

    all_clients = (
        await session.execute(select(OAuthClient).order_by(OAuthClient.created_at.desc()))
    ).scalars().all()

    return page(
        request,
        settings,
        "admin_dashboard.html",
        current_user=admin_user,
        clients=all_clients,
        new_client_name=name.strip(),
        new_client_id=cid,
        new_secret=secret,
        flash_message=f"Client '{name.strip()}' registered successfully.",
    )


@router.post("/dashboard/clients/{client_id}/rotate-secret")
async def admin_rotate_client_secret(
    client_id: str,
    request: Request,
    csrf_token: str = Form(...),
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    admin_user, err_resp = await _get_admin_user(request, session, settings)
    if err_resp:
        return err_resp

    client = await session.get(OAuthClient, client_id)
    clients = (
        await session.execute(select(OAuthClient).order_by(OAuthClient.created_at.desc()))
    ).scalars().all()

    if not client:
        return page(
            request,
            settings,
            "admin_dashboard.html",
            status=404,
            current_user=admin_user,
            clients=clients,
            flash_error="Client not found.",
        )

    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(
            request,
            settings,
            "admin_dashboard.html",
            status=400,
            current_user=admin_user,
            clients=clients,
            flash_error="Invalid or expired form token. Please try again.",
        )

    new_secret = secrets.token_urlsafe(32)
    client.client_secret_hash = hash_token(settings.token_hash_pepper, new_secret)
    await audit(session, "admin_rotate_client_secret", client_id=client_id, detail={"name": client.name, "via": "dashboard"})
    await session.commit()

    return page(
        request,
        settings,
        "admin_dashboard.html",
        current_user=admin_user,
        clients=clients,
        new_client_name=client.name,
        new_client_id=client.client_id,
        new_secret=new_secret,
        flash_message=f"New secret generated for client '{client.name}'.",
    )


@router.post("/dashboard/clients/{client_id}/toggle-status")
async def admin_toggle_client_status(
    client_id: str,
    request: Request,
    csrf_token: str = Form(...),
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    admin_user, err_resp = await _get_admin_user(request, session, settings)
    if err_resp:
        return err_resp

    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(request, settings, "error.html", status=400, error="Invalid form token.")

    client = await session.get(OAuthClient, client_id)
    if not client:
        raise HTTPException(404, "Client not found")

    client.is_active = not client.is_active
    await audit(session, "admin_toggle_client_status", client_id=client_id, detail={"is_active": client.is_active, "via": "dashboard"})
    await session.commit()

    return RedirectResponse("/admin/dashboard", status_code=303)


@router.get("/dashboard/users")
async def admin_dashboard_users(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    admin_user, err_resp = await _get_admin_user(request, session, settings)
    if err_resp:
        return err_resp

    users = (
        await session.execute(select(User).order_by(User.created_at.desc()))
    ).scalars().all()

    role_rows = (await session.execute(select(UserIdpRole.user_id, UserIdpRole.role_name))).all()
    user_roles_map: dict[uuid.UUID, list[str]] = {}
    for uid, rname in role_rows:
        user_roles_map.setdefault(uid, []).append(rname)

    sc_member_count = sum(1 for roles in user_roles_map.values() if RoleName.SC_MEMBER in roles)
    all_roles = (await session.execute(select(IdpRole).order_by(IdpRole.name))).scalars().all()

    return page(
        request,
        settings,
        "admin_users.html",
        current_user=admin_user,
        is_admin=True,
        users=users,
        user_roles_map=user_roles_map,
        sc_member_count=sc_member_count,
        all_roles=all_roles,
    )


@router.post("/dashboard/users/{user_id}/reset-password")
async def admin_user_reset_password(
    user_id: str,
    request: Request,
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    csrf_token: str = Form(...),
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    admin_user, err_resp = await _get_admin_user(request, session, settings)
    if err_resp:
        return err_resp

    try:
        target_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(400, "Invalid user ID")

    target_user = await session.get(User, target_uuid)

    users = (
        await session.execute(select(User).order_by(User.created_at.desc()))
    ).scalars().all()
    role_rows = (await session.execute(select(UserIdpRole.user_id, UserIdpRole.role_name))).all()
    user_roles_map: dict[uuid.UUID, list[str]] = {}
    for uid, rname in role_rows:
        user_roles_map.setdefault(uid, []).append(rname)
    sc_member_count = sum(1 for roles in user_roles_map.values() if RoleName.SC_MEMBER in roles)
    all_roles = (await session.execute(select(IdpRole).order_by(IdpRole.name))).scalars().all()

    def _render_page(error: str | None = None, message: str | None = None, status: int = 200):
        return page(
            request,
            settings,
            "admin_users.html",
            status=status,
            current_user=admin_user,
            is_admin=True,
            users=users,
            user_roles_map=user_roles_map,
            sc_member_count=sc_member_count,
            all_roles=all_roles,
            flash_error=error,
            flash_message=message,
        )

    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _render_page(error="Invalid or expired form token. Please try again.", status=400)

    if not target_user:
        return _render_page(error="Target user not found.", status=404)

    target_roles = user_roles_map.get(target_user.id, [])
    allowed_roles = {RoleName.SC_MEMBER, RoleName.ADMIN}
    if not any(r in allowed_roles for r in target_roles):
        return _render_page(error="Password reset is only permitted for members and administrators.", status=403)

    if len(new_password) < 8:
        return _render_page(error="Password must be at least 8 characters long.", status=400)

    if new_password != confirm_password:
        return _render_page(error="Passwords do not match.", status=400)

    target_user.password_hash = hash_password(settings, new_password)
    target_user.failed_login_count = 0
    target_user.locked_until = None

    now = datetime.now(UTC)
    await session.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == target_user.id,
            AuthSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    await audit(
        session,
        "admin_user_password_reset",
        user_id=target_user.id,
        ip=ip_of(request),
        detail={"by_admin": str(admin_user.id), "email": target_user.email, "via": "dashboard"},
    )
    await session.commit()

    return _render_page(message=f"Password for {target_user.email} was reset successfully.")


@router.post("/dashboard/users/{user_id}/roles/assign")
async def admin_user_assign_role(
    user_id: str,
    request: Request,
    role_name: str = Form(...),
    csrf_token: str = Form(...),
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    admin_user, err_resp = await _get_admin_user(request, session, settings)
    if err_resp:
        return err_resp

    try:
        target_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(400, "Invalid user ID")

    target_user = await session.get(User, target_uuid)
    if not target_user:
        raise HTTPException(404, "User not found")

    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(request, settings, "error.html", status=400, error="Invalid form token.")

    clean_role = role_name.strip().lower()
    if not clean_role:
        raise HTTPException(400, "Role name cannot be empty")

    assigned = await assign_role_to_user(session, target_user.id, clean_role)
    if assigned:
        await audit(
            session,
            "admin_assign_role",
            user_id=target_user.id,
            ip=ip_of(request),
            detail={"role": clean_role, "by_admin": str(admin_user.id), "via": "dashboard"},
        )
        await session.commit()

    return RedirectResponse("/admin/dashboard/users", status_code=303)


@router.post("/dashboard/users/{user_id}/roles/remove")
async def admin_user_remove_role(
    user_id: str,
    request: Request,
    role_name: str = Form(...),
    csrf_token: str = Form(...),
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    admin_user, err_resp = await _get_admin_user(request, session, settings)
    if err_resp:
        return err_resp

    try:
        target_uuid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(400, "Invalid user ID")

    target_user = await session.get(User, target_uuid)
    if not target_user:
        raise HTTPException(404, "User not found")

    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(request, settings, "error.html", status=400, error="Invalid form token.")

    clean_role = role_name.strip().lower()
    if target_user.id == admin_user.id and clean_role == RoleName.ADMIN:
        return page(request, settings, "error.html", status=400, error="You cannot remove the admin role from your own account.")

    removed = await remove_role_from_user(session, target_user.id, clean_role)
    if removed:
        await audit(
            session,
            "admin_unassign_role",
            user_id=target_user.id,
            ip=ip_of(request),
            detail={"role": clean_role, "by_admin": str(admin_user.id), "via": "dashboard"},
        )
        await session.commit()

    return RedirectResponse("/admin/dashboard/users", status_code=303)



