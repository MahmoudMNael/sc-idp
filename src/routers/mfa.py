from datetime import UTC, datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pyotp import TOTP, random_base32
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.crypto import (
    csrf_ok,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    hash_token,
    random_token,
    verify_password,
)
from src.core.deps import db_dep, ip_of, s_dep
from src.core.settings import Settings
from src.html import page
from src.models import AuthSession, MfaRecoveryCode, User
from src.routers.accounts import after_login_target, oauth_context
from src.services.audit import audit
from src.services.roles import RoleName, get_user_roles
from src.services.sessions import create_session, load_session, set_session_cookie

router = APIRouter()


def _norm_recovery(code: str) -> str:
    return code.replace("-", "").replace(" ", "").upper()


async def _user_session(request, session, settings) -> tuple:
    sess = await load_session(session, settings, request.cookies.get(settings.cookie_name))
    if sess is None:
        return None, None
    user = await session.get(User, sess.user_id)
    return sess, user


async def _check_otp_or_recovery(session, settings, user: User, code: str) -> bool:
    code = code.strip()
    if user.totp_secret_enc:
        secret = decrypt_secret(settings.key_encryption_key, user.totp_secret_enc)
        if TOTP(secret).verify(code, valid_window=1):
            return True
    h = hash_token(settings.token_hash_pepper, _norm_recovery(code))
    row = (
        await session.execute(
            select(MfaRecoveryCode).where(
                MfaRecoveryCode.user_id == user.id,
                MfaRecoveryCode.code_hash == h,
                MfaRecoveryCode.used_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    row.used_at = datetime.now(UTC)
    return True


@router.get("/login/mfa")
async def mfa_form(request: Request, next: str = "", settings: Settings = s_dep, session: AsyncSession = db_dep):
    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None:
        return RedirectResponse("/login", status_code=302)
    client_name, cancel_url = await oauth_context(session, settings, next)
    return page(request, settings, "mfa.html", next=next, client_name=client_name, cancel_url=cancel_url, error=None, action="/login/mfa")


@router.post("/login/mfa")
async def mfa_submit(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    code: str = Form(""),
    csrf_token: str = Form(""),
    next: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(request, settings, "error.html", status=400, error="Invalid or expired form token.")
    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None:
        return RedirectResponse("/login", status_code=303)
    if not await _check_otp_or_recovery(session, settings, user, code):
        await audit(session, "mfa_failure", user_id=user.id, ip=ip_of(request))
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(request, settings, "mfa.html", status=401, next=next, client_name=client_name, cancel_url=cancel_url, error="Invalid code.", action="/login/mfa")

    raw = await create_session(
        session,
        settings,
        user,
        ["pwd", "otp"],
        ip=ip_of(request),
        user_agent=request.headers.get("user-agent"),
        replace=sess,
    )
    await audit(session, "mfa_success", user_id=user.id, ip=ip_of(request))
    response = RedirectResponse(after_login_target(settings, next), status_code=303)
    set_session_cookie(response, settings, raw)
    return response


@router.get("/account")
@router.get("/account/mfa")
async def account_mfa(
    request: Request,
    tab: str = "profile",
    message: str | None = None,
    error: str | None = None,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None:
        return RedirectResponse("/login", status_code=302)
    user_roles = await get_user_roles(session, user.id)
    is_admin = RoleName.ADMIN in user_roles

    pending_uri = None
    if user.totp_secret_enc and not user.totp_enabled:
        secret = decrypt_secret(settings.key_encryption_key, user.totp_secret_enc)
        pending_uri = TOTP(secret).provisioning_uri(name=user.email, issuer_name="sc-idp")
    return page(
        request,
        settings,
        "account.html",
        current_user=user,
        is_admin=is_admin,
        first_name=user.first_name or "",
        last_name=user.last_name or "",
        email=user.email,
        email_verified=user.email_verified,
        totp_enabled=user.totp_enabled,
        pending_uri=pending_uri,
        recovery_codes=None,
        tab=tab,
        message=message,
        error=error,
    )


@router.post("/account/profile")
@router.patch("/account/profile")
async def account_profile(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    first_name: str | None = Form(None),
    last_name: str | None = Form(None),
    csrf_token: str | None = Form(None),
):
    content_type = request.headers.get("content-type", "")
    is_json = "application/json" in content_type
    if is_json:
        data = await request.json()
        first_name = data.get("first_name")
        last_name = data.get("last_name")
        csrf_token = request.headers.get("x-csrf-token") or request.cookies.get("csrf")
    else:
        if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
            return page(request, settings, "error.html", status=400, error="Invalid or expired form token.")

    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None:
        if is_json:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return RedirectResponse("/login", status_code=303)

    if first_name is not None:
        user.first_name = first_name.strip() or None
    if last_name is not None:
        user.last_name = last_name.strip() or None

    await audit(session, "profile_updated", user_id=user.id, ip=ip_of(request))

    if is_json:
        return {"first_name": user.first_name, "last_name": user.last_name}
    return RedirectResponse(f"/account?{urlencode({'tab': 'profile', 'message': 'Profile updated successfully.'})}", status_code=303)


@router.post("/account/password")
@router.patch("/account/password")
async def account_password(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    csrf_token: str | None = Form(None),
):
    content_type = request.headers.get("content-type", "")
    is_json = "application/json" in content_type
    if is_json:
        data = await request.json()
        current_password = data.get("current_password", "")
        new_password = data.get("new_password", "")
        confirm_password = data.get("confirm_password", "")
        csrf_token = request.headers.get("x-csrf-token") or request.cookies.get("csrf")
    else:
        if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
            return page(request, settings, "error.html", status=400, error="Invalid or expired form token.")

    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None:
        if is_json:
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return RedirectResponse("/login", status_code=303)

    if not current_password or not new_password or not confirm_password:
        msg = "All password fields are required."
        if is_json:
            return JSONResponse({"error": msg}, status_code=400)
        return RedirectResponse(f"/account?{urlencode({'tab': 'security', 'error': msg})}", status_code=303)

    ok, _ = verify_password(settings, user.password_hash, current_password)
    if not ok:
        msg = "Current password is incorrect."
        if is_json:
            return JSONResponse({"error": msg}, status_code=400)
        return RedirectResponse(f"/account?{urlencode({'tab': 'security', 'error': msg})}", status_code=303)

    if len(new_password) < 8:
        msg = "New password must be at least 8 characters."
        if is_json:
            return JSONResponse({"error": msg}, status_code=400)
        return RedirectResponse(f"/account?{urlencode({'tab': 'security', 'error': msg})}", status_code=303)

    if new_password != confirm_password:
        msg = "New password and confirmation do not match."
        if is_json:
            return JSONResponse({"error": msg}, status_code=400)
        return RedirectResponse(f"/account?{urlencode({'tab': 'security', 'error': msg})}", status_code=303)

    user.password_hash = hash_password(settings, new_password)
    user.failed_login_count = 0
    user.locked_until = None

    # Revoke all other active sessions for this user
    now = datetime.now(UTC)
    await session.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == user.id,
            AuthSession.id != sess.id,
            AuthSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    await audit(session, "password_changed", user_id=user.id, ip=ip_of(request))

    if is_json:
        return {"ok": True, "message": "Password updated successfully."}
    return RedirectResponse(f"/account?{urlencode({'tab': 'security', 'message': 'Password updated successfully.'})}", status_code=303)




@router.post("/account/mfa/setup")
async def mfa_setup(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(request, settings, "error.html", status=400, error="Invalid or expired form token.")
    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None:
        return RedirectResponse("/login", status_code=303)
    if user.totp_enabled:
        return RedirectResponse("/account/mfa", status_code=303)
    secret = random_base32()
    user.totp_secret_enc = encrypt_secret(settings.key_encryption_key, secret)
    return RedirectResponse("/account/mfa", status_code=303)


@router.post("/account/mfa/enable")
async def mfa_enable(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    code: str = Form(""),
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(request, settings, "error.html", status=400, error="Invalid or expired form token.")
    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None or not user.totp_secret_enc:
        return RedirectResponse("/login", status_code=303)
    secret = decrypt_secret(settings.key_encryption_key, user.totp_secret_enc)
    if not TOTP(secret).verify(code.strip(), valid_window=1):
        uri = TOTP(secret).provisioning_uri(name=user.email, issuer_name="sc-idp")
        return page(
            request,
            settings,
            "account.html",
            status=400,
            email=user.email,
            email_verified=user.email_verified,
            totp_enabled=False,
            pending_uri=uri,
            recovery_codes=None,
        )
    user.totp_enabled = True
    codes = []
    for _ in range(10):
        raw = f"{random_token(4)[:4].upper()}-{random_token(4)[:4].upper()}"
        codes.append(raw)
        session.add(MfaRecoveryCode(user_id=user.id, code_hash=hash_token(settings.token_hash_pepper, _norm_recovery(raw))))
    raw_sess = await create_session(
        session,
        settings,
        user,
        ["pwd", "otp"],
        ip=ip_of(request),
        user_agent=request.headers.get("user-agent"),
        replace=sess,
    )
    await audit(session, "mfa_enabled", user_id=user.id, ip=ip_of(request))
    pending_uri = None
    response = page(
        request,
        settings,
        "account.html",
        email=user.email,
        email_verified=user.email_verified,
        totp_enabled=True,
        pending_uri=pending_uri,
        recovery_codes=codes,
    )
    set_session_cookie(response, settings, raw_sess)
    return response


@router.post("/account/mfa/disable")
async def mfa_disable(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    code: str = Form(""),
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(request, settings, "error.html", status=400, error="Invalid or expired form token.")
    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None:
        return RedirectResponse("/login", status_code=303)
    if not await _check_otp_or_recovery(session, settings, user, code):
        return RedirectResponse("/account/mfa", status_code=303)
    user.totp_enabled = False
    user.totp_secret_enc = None
    await session.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    raw = await create_session(
        session,
        settings,
        user,
        ["pwd"],
        ip=ip_of(request),
        user_agent=request.headers.get("user-agent"),
        replace=sess,
    )
    await audit(session, "mfa_disabled", user_id=user.id, ip=ip_of(request))
    response = RedirectResponse("/account/mfa", status_code=303)
    set_session_cookie(response, settings, raw)
    return response
