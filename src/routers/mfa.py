from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from pyotp import TOTP, random_base32
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from idp.audit import audit
from idp.crypto import csrf_ok, decrypt_secret, encrypt_secret, hash_token, random_token
from idp.deps import db_dep, ip_of, s_dep
from idp.html import page
from idp.models import MfaRecoveryCode, User
from idp.routers.accounts import after_login_target
from idp.sessions import create_session, load_session, set_session_cookie
from idp.settings import Settings

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
    from datetime import UTC, datetime

    row.used_at = datetime.now(UTC)
    return True


@router.get("/login/mfa")
async def mfa_form(request: Request, next: str = "", settings: Settings = s_dep, session: AsyncSession = db_dep):
    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None:
        return RedirectResponse("/login", status_code=302)
    return page(request, settings, "mfa.html", next=next, error=None, action="/login/mfa")


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
        return page(request, settings, "mfa.html", status=401, next=next, error="Invalid code.", action="/login/mfa")
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


@router.get("/account/mfa")
async def account_mfa(request: Request, session: AsyncSession = db_dep, settings: Settings = s_dep):
    sess, user = await _user_session(request, session, settings)
    if sess is None or user is None:
        return RedirectResponse("/login", status_code=302)
    pending_uri = None
    if user.totp_secret_enc and not user.totp_enabled:
        secret = decrypt_secret(settings.key_encryption_key, user.totp_secret_enc)
        pending_uri = TOTP(secret).provisioning_uri(name=user.email, issuer_name="sc-idp")
    return page(
        request,
        settings,
        "account.html",
        email=user.email,
        email_verified=user.email_verified,
        totp_enabled=user.totp_enabled,
        pending_uri=pending_uri,
        recovery_codes=None,
    )


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
