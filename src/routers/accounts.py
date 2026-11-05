from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.crypto import (
    csrf_ok,
    dummy_verify,
    generate_otp,
    hash_otp,
    hash_password,
    hash_token,
    random_token,
    sign,
    unsign,
    verify_password,
)
from src.core.deps import db_dep, ip_of, s_dep
from src.core.settings import Settings
from src.html import page
from src.models import AuthSession, EmailToken, OAuthClient, User
from src.services.audit import audit
from src.services.mail import (
    send_account_created_mail,
    send_mail,
    send_otp_forgot_password_mail,
    send_otp_register_mail,
)
from src.services.ratelimit import allow, reset_rate_limit
from src.services.roles import RoleName, apply_preassigned_roles, get_user_roles
from src.services.sessions import clear_session_cookie, create_session, load_session, set_session_cookie

router = APIRouter()
LOGIN_ERROR = "Invalid email or password"
NEXT_MAX_AGE = 600


def sign_next(settings: Settings, query: str) -> str:
    return sign(settings.secret_key, "next", query)


def load_next(settings: Settings, value: str | None) -> str | None:
    if not value:
        return None
    return unsign(settings.secret_key, "next", value, NEXT_MAX_AGE)


async def oauth_context(session: AsyncSession, settings: Settings, nxt: str | None) -> tuple[str | None, str | None]:
    query = load_next(settings, nxt)
    if not query:
        return None, None
    from urllib.parse import parse_qs

    parsed = {k: v[0] if v else "" for k, v in parse_qs(query, keep_blank_values=True).items()}
    client_id = parsed.get("client_id")
    if not client_id:
        return None, None
    client = await session.get(OAuthClient, client_id)
    if client and client.is_active:
        return client.name, f"/cancel?next={nxt}"
    return None, None


def after_login_target(settings: Settings, nxt: str | None) -> str:
    query = load_next(settings, nxt)
    return f"/authorize?{query}" if query else "/"


def _csrf_fail(request, settings):
    return page(request, settings, "error.html", status=400, error="Invalid or expired form token.")


async def _invalidate_prior_tokens(
    session: AsyncSession,
    user_id: uuid.UUID,
    purpose: str,
) -> None:
    # ponytail: mark prior unconsumed tokens for (user, purpose) as consumed on new code issuance
    await session.execute(
        update(EmailToken)
        .where(
            EmailToken.user_id == user_id,
            EmailToken.purpose == purpose,
            EmailToken.consumed_at.is_(None),
        )
        .values(consumed_at=datetime.now(UTC))
    )
    key_prefix = "pwd_otp_attempt" if purpose == "reset_password" else "otp_attempt"
    await reset_rate_limit(session, f"{key_prefix}:{user_id}")


async def _get_resend_cooldown(
    session: AsyncSession,
    settings: Settings,
    user_id: uuid.UUID,
    purpose: str,
) -> int:
    latest_created_at = (
        await session.execute(
            select(EmailToken.created_at)
            .where(EmailToken.user_id == user_id, EmailToken.purpose == purpose)
            .order_by(EmailToken.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if not latest_created_at:
        return 0
    now = datetime.now(UTC)
    if latest_created_at.tzinfo is None:
        latest_created_at = latest_created_at.replace(tzinfo=UTC)
    elapsed = max(0.0, (now - latest_created_at).total_seconds())
    return max(0, int(settings.otp_resend_cooldown - elapsed))


async def _get_cooldown_for_email(
    session: AsyncSession,
    settings: Settings,
    email: str,
    purpose: str,
) -> int:
    email_n = email.strip().lower()
    if not email_n:
        return 0
    user_id = (await session.execute(select(User.id).where(User.email == email_n))).scalar_one_or_none()
    if not user_id:
        return 0
    return await _get_resend_cooldown(session, settings, user_id, purpose)


async def _otp_page(
    request: Request,
    session: AsyncSession,
    settings: Settings,
    *,
    is_reset: bool,
    email: str,
    next: str = "",
    status: int = 200,
    error: str | None = None,
    message: str | None = None,
    cooldown: int | None = None,
):
    client_name, cancel_url = await oauth_context(session, settings, next)
    action = "/reset-password/verify" if is_reset else "/verify-email"
    resend = "/reset-password/resend" if is_reset else "/verify-email/resend"
    title = "Reset password" if is_reset else "Verify your email"
    heading = "Enter reset code" if is_reset else "Verify your email"
    desc = f"We sent a 6-digit code to {email}." if email else "Enter the 6-digit code."
    if cooldown is None:
        cooldown = await _get_cooldown_for_email(
            session, settings, email, "reset_password" if is_reset else "verify_email"
        )
    return page(
        request,
        settings,
        "verify_otp.html",
        status=status,
        title=title,
        heading=heading,
        description=desc,
        action=action,
        resend_action=resend,
        email=email,
        next=next,
        client_name=client_name,
        cancel_url=cancel_url,
        error=error,
        message=message,
        cooldown=cooldown,
    )


async def _rate(session, settings, kind: str, ip: str | None, limit: int) -> bool:
    return await allow(session, f"{kind}:{ip or 'unknown'}", limit, settings.rate_limit_window)


@router.get("/")
async def home(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    sess = await load_session(session, settings, request.cookies.get(settings.cookie_name))
    if sess:
        user = await session.get(User, sess.user_id)
        if user and user.is_active:
            if user.totp_enabled and "otp" not in (sess.amr or []):
                return RedirectResponse("/login/mfa", status_code=303)
            return RedirectResponse("/account", status_code=303)
    return RedirectResponse("/login", status_code=303)


@router.get("/register")
async def register_form(
    request: Request,
    next: str = "",
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    client_name, cancel_url = await oauth_context(session, settings, next)
    return page(
        request,
        settings,
        "register.html",
        first_name="",
        last_name="",
        email="",
        next=next,
        client_name=client_name,
        cancel_url=cancel_url,
        error=None,
    )


@router.post("/register")
async def register(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
    confirm_password: str | None = Form(None),
    csrf_token: str = Form(""),
    next: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    if not await _rate(session, settings, "register", ip_of(request), settings.rate_limit_register):
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "register.html",
            status=429,
            first_name=first_name,
            last_name=last_name,
            email=email,
            next=next,
            client_name=client_name,
            cancel_url=cancel_url,
            error="Too many attempts. Try later.",
        )
    first_name_clean = first_name.strip()
    last_name_clean = last_name.strip()
    if not first_name_clean or not last_name_clean:
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "register.html",
            status=400,
            first_name=first_name,
            last_name=last_name,
            email=email,
            next=next,
            client_name=client_name,
            cancel_url=cancel_url,
            error="First name and last name are required.",
        )
    if confirm_password is not None and confirm_password != password:
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "register.html",
            status=400,
            first_name=first_name,
            last_name=last_name,
            email=email,
            next=next,
            client_name=client_name,
            cancel_url=cancel_url,
            error="Passwords do not match.",
        )
    email_n = email.strip().lower()
    if "@" not in email_n or len(password) < 8:
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "register.html",
            status=400,
            first_name=first_name,
            last_name=last_name,
            email=email,
            next=next,
            client_name=client_name,
            cancel_url=cancel_url,
            error="Valid email and password (8+ characters) required.",
        )
    existing_user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    if existing_user:
        if not existing_user.email_verified:
            existing_user.password_hash = hash_password(settings, password)
            existing_user.first_name = first_name_clean
            existing_user.last_name = last_name_clean
            await _invalidate_prior_tokens(session, existing_user.id, "verify_email")
            code = generate_otp(6)
            session.add(
                EmailToken(
                    token_hash=hash_otp(settings.token_hash_pepper, existing_user.id, "verify_email", code),
                    user_id=existing_user.id,
                    purpose="verify_email",
                    expires_at=datetime.now(UTC) + timedelta(seconds=settings.otp_ttl),
                )
            )
            send_otp_register_mail(settings, email_n, code)
            query = {"email": email_n}
            if next:
                query["next"] = next
            return RedirectResponse(f"/verify-email?{urlencode(query)}", status_code=303)
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "register.html",
            status=400,
            first_name=first_name,
            last_name=last_name,
            email=email,
            next=next,
            client_name=client_name,
            cancel_url=cancel_url,
            error="Could not create that account.",
        )
    user = User(
        email=email_n,
        password_hash=hash_password(settings, password),
        first_name=first_name_clean,
        last_name=last_name_clean,
        email_verified=False,
    )
    session.add(user)
    await session.flush()
    await apply_preassigned_roles(session, user.id, email_n)
    code = generate_otp(6)

    session.add(
        EmailToken(
            token_hash=hash_otp(settings.token_hash_pepper, user.id, "verify_email", code),
            user_id=user.id,
            purpose="verify_email",
            expires_at=datetime.now(UTC) + timedelta(seconds=settings.otp_ttl),
        )
    )
    send_otp_register_mail(settings, email_n, code)
    await audit(session, "register", user_id=user.id, ip=ip_of(request))
    query = {"email": email_n}
    if next:
        query["next"] = next
    return RedirectResponse(f"/verify-email?{urlencode(query)}", status_code=303)


@router.get("/verify-email")
async def verify_email_form(
    request: Request,
    email: str = "",
    next: str = "",
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    return await _otp_page(request, session, settings, is_reset=False, email=email, next=next)


@router.post("/verify-email")
async def verify_email(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    email: str = Form(""),
    code: str = Form(""),
    csrf_token: str = Form(""),
    next: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    email_n = email.strip().lower()
    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    now = datetime.now(UTC)
    if user is None:
        return await _otp_page(request, session, settings, is_reset=False, email=email_n, next=next, status=400, error="Invalid or expired verification code.")

    if not await allow(session, f"otp_attempt:{user.id}", settings.otp_max_attempts, settings.otp_ttl):
        return await _otp_page(request, session, settings, is_reset=False, email=email_n, next=next, status=429, error="Too many failed attempts. Please request a new code.")

    expected_hash = hash_otp(settings.token_hash_pepper, user.id, "verify_email", code)
    row = (
        await session.execute(
            select(EmailToken).where(
                EmailToken.token_hash == expected_hash,
                EmailToken.user_id == user.id,
                EmailToken.purpose == "verify_email",
            )
        )
    ).scalar_one_or_none()

    if row is None or row.consumed_at or row.expires_at < now:
        return await _otp_page(request, session, settings, is_reset=False, email=email_n, next=next, status=400, error="Invalid or expired verification code.")

    user.email_verified = True
    row.consumed_at = now
    await apply_preassigned_roles(session, user.id, email_n)
    send_account_created_mail(settings, email_n)
    await audit(session, "email_verified", user_id=user.id, ip=ip_of(request))

    # ponytail: automatically sign in verified user and redirect to after-login target
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
    dest = after_login_target(settings, next)
    response = RedirectResponse(dest, status_code=303)
    set_session_cookie(response, settings, raw)
    return response


@router.post("/verify-email/resend")
async def verify_email_resend(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    email: str = Form(""),
    csrf_token: str = Form(""),
    next: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    email_n = email.strip().lower()
    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    if user and not user.email_verified:
        cooldown = await _get_resend_cooldown(session, settings, user.id, "verify_email")
        if cooldown > 0:
            return await _otp_page(
                request,
                session,
                settings,
                is_reset=False,
                email=email_n,
                next=next,
                status=429,
                error=f"Please wait {cooldown} seconds before requesting a new code.",
                cooldown=cooldown,
            )
        if not await allow(session, f"otp_resend:{user.id}", 3, 600):
            return await _otp_page(
                request,
                session,
                settings,
                is_reset=False,
                email=email_n,
                next=next,
                status=429,
                error="Too many resend attempts. Please wait a few minutes.",
            )
        await _invalidate_prior_tokens(session, user.id, "verify_email")
        code = generate_otp(6)
        session.add(
            EmailToken(
                token_hash=hash_otp(settings.token_hash_pepper, user.id, "verify_email", code),
                user_id=user.id,
                purpose="verify_email",
                expires_at=datetime.now(UTC) + timedelta(seconds=settings.otp_ttl),
            )
        )
        send_otp_register_mail(settings, email_n, code)
        return await _otp_page(
            request,
            session,
            settings,
            is_reset=False,
            email=email_n,
            next=next,
            message="A new verification code has been sent.",
            cooldown=settings.otp_resend_cooldown,
        )
    return await _otp_page(
        request,
        session,
        settings,
        is_reset=False,
        email=email_n,
        next=next,
        message="A new verification code has been sent.",
        cooldown=settings.otp_resend_cooldown,
    )


@router.get("/login")
async def login_form(
    request: Request,
    next: str = "",
    message: str = "",
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    client_name, cancel_url = await oauth_context(session, settings, next)
    return page(
        request,
        settings,
        "login.html",
        next=next,
        message=message,
        email="",
        client_name=client_name,
        cancel_url=cancel_url,
        error=None,
        verify_url=None,
    )


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
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "login.html",
            status=429,
            next=next,
            message=None,
            email=email,
            client_name=client_name,
            cancel_url=cancel_url,
            error="Too many attempts. Try later.",
            verify_url=None,
        )
    email_n = email.strip().lower()
    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    now = datetime.now(UTC)
    if user is None or not user.is_active:
        dummy_verify(settings, password)
        await audit(session, "login_failure", ip=ip_of(request), detail={"reason": "unknown"})
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "login.html",
            status=401,
            next=next,
            message=None,
            email=email,
            client_name=client_name,
            cancel_url=cancel_url,
            error=LOGIN_ERROR,
            verify_url=None,
        )
    if user.locked_until and user.locked_until > now:
        dummy_verify(settings, password)
        await audit(session, "login_failure", user_id=user.id, ip=ip_of(request), detail={"reason": "locked"})
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "login.html",
            status=401,
            next=next,
            message=None,
            email=email,
            client_name=client_name,
            cancel_url=cancel_url,
            error=LOGIN_ERROR,
            verify_url=None,
        )
    ok, new_hash = verify_password(settings, user.password_hash, password)
    if not ok:
        user.failed_login_count += 1
        if user.failed_login_count >= settings.login_max_failures:
            user.locked_until = now + timedelta(seconds=settings.lockout_seconds)
            user.failed_login_count = 0
        await audit(session, "login_failure", user_id=user.id, ip=ip_of(request), detail={"reason": "password"})
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "login.html",
            status=401,
            next=next,
            message=None,
            email=email,
            client_name=client_name,
            cancel_url=cancel_url,
            error=LOGIN_ERROR,
            verify_url=None,
        )

    # Gate unverified email
    if not user.email_verified:
        await audit(session, "login_failure", user_id=user.id, ip=ip_of(request), detail={"reason": "unverified"})
        verify_query = {"email": email_n}
        if next:
            verify_query["next"] = next
        verify_url = f"/verify-email?{urlencode(verify_query)}"
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(
            request,
            settings,
            "login.html",
            status=403,
            next=next,
            message=None,
            email=email,
            client_name=client_name,
            cancel_url=cancel_url,
            error="Please verify your email before signing in.",
            verify_url=verify_url,
        )

    user.failed_login_count = 0
    user.locked_until = None
    if new_hash:
        user.password_hash = new_hash
    await apply_preassigned_roles(session, user.id, email_n)
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
async def forgot_form(
    request: Request,
    next: str = "",
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    client_name, cancel_url = await oauth_context(session, settings, next)
    return page(
        request,
        settings,
        "forgot.html",
        next=next,
        client_name=client_name,
        cancel_url=cancel_url,
        message=None,
    )


@router.post("/forgot-password")
async def forgot(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    email: str = Form(""),
    next: str = Form(""),
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    email_n = email.strip().lower()
    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    if user and user.is_active:
        if await allow(session, f"pwd_otp_send:{user.id}", 3, 600):
            await _invalidate_prior_tokens(session, user.id, "reset_password")
            code = generate_otp(6)
            session.add(
                EmailToken(
                    token_hash=hash_otp(settings.token_hash_pepper, user.id, "reset_password", code),
                    user_id=user.id,
                    purpose="reset_password",
                    expires_at=datetime.now(UTC) + timedelta(seconds=settings.otp_ttl),
                )
            )
            send_otp_forgot_password_mail(settings, email_n, code)
            await audit(session, "password_reset_requested", user_id=user.id, ip=ip_of(request))
    # ponytail: avoid email enumeration by redirecting to verify screen regardless
    query = {"email": email_n}
    if next:
        query["next"] = next
    return RedirectResponse(f"/reset-password/verify?{urlencode(query)}", status_code=303)


@router.get("/reset-password/verify")
async def reset_verify_form(
    request: Request,
    email: str = "",
    next: str = "",
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    return await _otp_page(request, session, settings, is_reset=True, email=email, next=next)


@router.post("/reset-password/verify")
async def reset_verify(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    email: str = Form(""),
    code: str = Form(""),
    next: str = Form(""),
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    email_n = email.strip().lower()
    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    now = datetime.now(UTC)
    if user is None:
        return await _otp_page(request, session, settings, is_reset=True, email=email_n, next=next, status=400, error="Invalid or expired reset code.")

    if not await allow(session, f"pwd_otp_attempt:{user.id}", settings.otp_max_attempts, settings.otp_ttl):
        return await _otp_page(request, session, settings, is_reset=True, email=email_n, next=next, status=429, error="Too many failed attempts. Please request a new code.")

    expected_hash = hash_otp(settings.token_hash_pepper, user.id, "reset_password", code)
    row = (
        await session.execute(
            select(EmailToken).where(
                EmailToken.token_hash == expected_hash,
                EmailToken.user_id == user.id,
                EmailToken.purpose == "reset_password",
            )
        )
    ).scalar_one_or_none()

    if row is None or row.consumed_at or row.expires_at < now:
        return await _otp_page(request, session, settings, is_reset=True, email=email_n, next=next, status=400, error="Invalid or expired reset code.")

    row.consumed_at = now
    # Signed ticket valid for 10 minutes to set new password in step 2
    ticket = sign(settings.secret_key, "pwd_reset_ticket", str(user.id))
    query = {"ticket": ticket}
    if next:
        query["next"] = next
    return RedirectResponse(f"/reset-password?{urlencode(query)}", status_code=303)


@router.post("/reset-password/resend")
async def reset_resend(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    email: str = Form(""),
    next: str = Form(""),
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    email_n = email.strip().lower()
    user = (await session.execute(select(User).where(User.email == email_n))).scalar_one_or_none()
    if user and user.is_active:
        cooldown = await _get_resend_cooldown(session, settings, user.id, "reset_password")
        if cooldown > 0:
            return await _otp_page(
                request,
                session,
                settings,
                is_reset=True,
                email=email_n,
                next=next,
                status=429,
                error=f"Please wait {cooldown} seconds before requesting a new code.",
                cooldown=cooldown,
            )
        if not await allow(session, f"pwd_otp_resend:{user.id}", 3, 600):
            return await _otp_page(
                request,
                session,
                settings,
                is_reset=True,
                email=email_n,
                next=next,
                status=429,
                error="Too many resend attempts. Please wait a few minutes.",
            )
        await _invalidate_prior_tokens(session, user.id, "reset_password")
        code = generate_otp(6)
        session.add(
            EmailToken(
                token_hash=hash_otp(settings.token_hash_pepper, user.id, "reset_password", code),
                user_id=user.id,
                purpose="reset_password",
                expires_at=datetime.now(UTC) + timedelta(seconds=settings.otp_ttl),
            )
        )
        send_otp_forgot_password_mail(settings, email_n, code)
        return await _otp_page(
            request,
            session,
            settings,
            is_reset=True,
            email=email_n,
            next=next,
            message="A new reset code has been sent.",
            cooldown=settings.otp_resend_cooldown,
        )
    return await _otp_page(
        request,
        session,
        settings,
        is_reset=True,
        email=email_n,
        next=next,
        message="A new reset code has been sent.",
        cooldown=settings.otp_resend_cooldown,
    )


@router.get("/reset-password")
async def reset_form(
    request: Request,
    ticket: str = "",
    next: str = "",
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    user_id_str = unsign(settings.secret_key, "pwd_reset_ticket", ticket, max_age=600)
    if not user_id_str:
        return page(request, settings, "error.html", status=400, error="Invalid or expired reset session. Please request a new code.")
    client_name, cancel_url = await oauth_context(session, settings, next)
    return page(request, settings, "reset.html", ticket=ticket, next=next, client_name=client_name, cancel_url=cancel_url, error=None)


@router.post("/reset-password")
async def reset(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    ticket: str = Form(""),
    password: str = Form(""),
    next: str = Form(""),
    csrf_token: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return _csrf_fail(request, settings)
    user_id_str = unsign(settings.secret_key, "pwd_reset_ticket", ticket, max_age=600)
    if not user_id_str:
        return page(request, settings, "error.html", status=400, error="Invalid or expired reset session. Please request a new code.")
    if len(password) < 8:
        client_name, cancel_url = await oauth_context(session, settings, next)
        return page(request, settings, "reset.html", ticket=ticket, next=next, client_name=client_name, cancel_url=cancel_url, error="Password must be 8+ characters.")
    user = await session.get(User, uuid.UUID(user_id_str))
    if user is None or not user.is_active:
        return page(request, settings, "error.html", status=400, error="Invalid or expired reset session.")
    user.password_hash = hash_password(settings, password)
    user.failed_login_count = 0
    user.locked_until = None

    # Revoke all active sessions for this user on password reset
    now = datetime.now(UTC)
    await session.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == user.id,
            AuthSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    await audit(session, "password_reset", user_id=user.id, ip=ip_of(request))
    query = {"message": "Password updated. Please sign in."}
    if next:
        query["next"] = next
    return RedirectResponse(f"/login?{urlencode(query)}", status_code=303)

