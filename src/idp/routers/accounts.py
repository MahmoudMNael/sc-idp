from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from idp.audit import audit
from idp.crypto import (
    csrf_ok,
    dummy_verify,
    hash_password,
    hash_token,
    random_token,
    sign,
    unsign,
    verify_password,
)
from idp.deps import db_dep, ip_of, s_dep
from idp.html import page
from idp.mail import send_mail
from idp.models import EmailToken, User
from idp.ratelimit import allow
from idp.sessions import clear_session_cookie, create_session, load_session, set_session_cookie
from idp.settings import Settings

router = APIRouter()
LOGIN_ERROR = "Invalid email or password"
NEXT_MAX_AGE = 600


def sign_next(settings: Settings, query: str) -> str:
    return sign(settings.secret_key, "next", query)


def load_next(settings: Settings, value: str | None) -> str | None:
    if not value:
        return None
    return unsign(settings.secret_key, "next", value, NEXT_MAX_AGE)


def after_login_target(settings: Settings, nxt: str | None) -> str:
    query = load_next(settings, nxt)
    return f"/authorize?{query}" if query else "/"


def _csrf_fail(request, settings):
    return page(request, settings, "error.html", status=400, error="Invalid or expired form token.")


async def _rate(session, settings, kind: str, ip: str | None, limit: int) -> bool:
    return await allow(session, f"{kind}:{ip or 'unknown'}", limit, settings.rate_limit_window)


@router.get("/")
async def home(request: Request, settings: Settings = s_dep):
    return page(request, settings, "home.html")


@router.get("/register")
async def register_form(request: Request, settings: Settings = s_dep):
    return page(request, settings, "register.html", email="", error=None)


@router.post("/register")
async def register(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    email: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    if not await _rate(session, settings, "register", ip_of(request), settings.rate_limit_register):
        return page(request, settings, "register.html", status=429, email=email, error="Too many attempts. Try later.")
    email_n = email.strip().lower()
    if "@" not in email_n or len(password) < 8:
        return page(request, settings, "register.html", status=400, email=email, error="Valid email and password (8+ characters) required.")
    exists = (await session.execute(select(User.id).where(User.email == email_n))).scalar_one_or_none()
    if exists:
        return page(request, settings, "register.html", status=400, email=email, error="Could not create that account.")
    user = User(email=email_n, password_hash=hash_password(settings, password))
    session.add(user)
    await session.flush()
    raw = random_token(32)
    session.add(
        EmailToken(
            token_hash=hash_token(settings.token_hash_pepper, raw),
            user_id=user.id,
            purpose="verify_email",
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        )
    )
    send_mail(
        settings,
        email_n,
        "Verify your email",
        f"Confirm your account: {settings.mail_link_base}/verify-email?token={raw}",
    )
    await audit(session, "register", user_id=user.id, ip=ip_of(request))
    return page(
        request,
        settings,
        "message.html",
        title="Check your email",
        message="If the address is valid, a verification link is on its way. You can sign in now.",
    )


@router.get("/verify-email")
async def verify_email(
    request: Request,
    token: str = "",
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    row = (
        await session.execute(
            select(EmailToken).where(EmailToken.token_hash == hash_token(settings.token_hash_pepper, token))
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None or row.consumed_at or row.purpose != "verify_email" or row.expires_at < now:
        return page(request, settings, "error.html", status=400, error="Invalid or expired verification link.")
    user = await session.get(User, row.user_id)
    if user:
        user.email_verified = True
    row.consumed_at = now
    await audit(session, "email_verified", user_id=row.user_id, ip=ip_of(request))
    return page(request, settings, "message.html", title="Email verified", message="You can sign in now.")


@router.get("/login")
async def login_form(request: Request, next: str = "", settings: Settings = s_dep):
    return page(request, settings, "login.html", next=next, email="", error=None)


@router.post("/login")
async def login(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    email: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
    next: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    if not await _rate(session, settings, "login", ip_of(request), settings.rate_limit_login):
        return page(request, settings, "login.html", status=429, next=next, email=email, error="Too many attempts. Try later.")
    email_n = email.strip().lower()
    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    now = datetime.now(UTC)
    if user is None or not user.is_active:
        dummy_verify(settings, password)
        await audit(session, "login_failure", ip=ip_of(request), detail={"reason": "unknown"})
        return page(request, settings, "login.html", status=401, next=next, email=email, error=LOGIN_ERROR)
    if user.locked_until and user.locked_until > now:
        dummy_verify(settings, password)
        await audit(session, "login_failure", user_id=user.id, ip=ip_of(request), detail={"reason": "locked"})
        return page(request, settings, "login.html", status=401, next=next, email=email, error=LOGIN_ERROR)
    ok, new_hash = verify_password(settings, user.password_hash, password)
    if not ok:
        user.failed_login_count += 1
        if user.failed_login_count >= settings.login_max_failures:
            user.locked_until = now + timedelta(seconds=settings.lockout_seconds)
            user.failed_login_count = 0
        await audit(session, "login_failure", user_id=user.id, ip=ip_of(request), detail={"reason": "password"})
        return page(request, settings, "login.html", status=401, next=next, email=email, error=LOGIN_ERROR)
    user.failed_login_count = 0
    user.locked_until = None
    if new_hash:
        user.password_hash = new_hash
    existing = await load_session(session, settings, request.cookies.get(settings.cookie_name))
    raw = await create_session(
        session,
        settings,
        user,
        ["pwd"],
        ip=ip_of(request),
        user_agent=request.headers.get("user-agent"),
        replace=existing,
    )
    await audit(session, "login_success", user_id=user.id, ip=ip_of(request))
    if user.totp_enabled:
        dest = f"/login/mfa?next={next}" if next else "/login/mfa"
    else:
        dest = after_login_target(settings, next)
    response = RedirectResponse(dest, status_code=303)
    set_session_cookie(response, settings, raw)
    return response


@router.get("/forgot-password")
async def forgot_form(request: Request, settings: Settings = s_dep):
    return page(request, settings, "forgot.html", message=None)


@router.post("/forgot-password")
async def forgot(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    email: str = Form(""),
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    email_n = email.strip().lower()
    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    msg = "If that account exists, a reset link is on its way."
    if user and user.is_active:
        raw = random_token(32)
        session.add(
            EmailToken(
                token_hash=hash_token(settings.token_hash_pepper, raw),
                user_id=user.id,
                purpose="reset_password",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        send_mail(
            settings,
            email_n,
            "Reset your password",
            f"Reset: {settings.mail_link_base}/reset-password?token={raw}",
        )
        await audit(session, "password_reset_requested", user_id=user.id, ip=ip_of(request))
    return page(request, settings, "forgot.html", message=msg)


@router.get("/reset-password")
async def reset_form(request: Request, token: str = "", settings: Settings = s_dep):
    return page(request, settings, "reset.html", token=token, error=None)


@router.post("/reset-password")
async def reset(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    token: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    if len(password) < 8:
        return page(request, settings, "reset.html", token=token, error="Password must be 8+ characters.")
    row = (
        await session.execute(
            select(EmailToken).where(EmailToken.token_hash == hash_token(settings.token_hash_pepper, token))
        )
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None or row.consumed_at or row.purpose != "reset_password" or row.expires_at < now:
        return page(request, settings, "reset.html", status=400, token=token, error="Invalid or expired reset link.")
    user = await session.get(User, row.user_id)
    if user is None:
        return page(request, settings, "reset.html", status=400, token=token, error="Invalid or expired reset link.")
    user.password_hash = hash_password(settings, password)
    user.failed_login_count = 0
    user.locked_until = None
    row.consumed_at = now
    await audit(session, "password_reset", user_id=user.id, ip=ip_of(request))
    return page(request, settings, "message.html", title="Password updated", message="You can sign in with the new password.")
