from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.crypto import hash_token, random_token
from src.models import AuthSession, User
from src.settings import Settings

SESSION_SALT_MAX_AGE = 60 * 60 * 24 * 14


def client_ip(request) -> str | None:
    return request.client.host if request.client else None


async def load_session(session: AsyncSession, settings: Settings, token: str | None) -> AuthSession | None:
    if not token:
        return None
    now = datetime.now(UTC)
    row = (
        await session.execute(
            select(AuthSession).where(AuthSession.session_token_hash == hash_token(settings.token_hash_pepper, token))
        )
    ).scalar_one_or_none()
    if (
        row is None
        or row.revoked_at is not None
        or row.idle_expires_at < now
        or row.absolute_expires_at < now
    ):
        return None
    row.idle_expires_at = now + timedelta(seconds=settings.session_idle_ttl)
    return row


async def create_session(
    session: AsyncSession,
    settings: Settings,
    user: User,
    amr: list[str],
    *,
    ip: str | None,
    user_agent: str | None,
    replace: AuthSession | None = None,
) -> str:
    now = datetime.now(UTC)
    if replace is not None:
        replace.revoked_at = now
    raw = random_token(32)
    session.add(
        AuthSession(
            session_token_hash=hash_token(settings.token_hash_pepper, raw),
            user_id=user.id,
            auth_time=now,
            amr=amr,
            ip=ip,
            user_agent=user_agent,
            idle_expires_at=now + timedelta(seconds=settings.session_idle_ttl),
            absolute_expires_at=now + timedelta(seconds=settings.session_absolute_ttl),
        )
    )
    return raw


def set_session_cookie(response, settings: Settings, token: str) -> None:
    response.set_cookie(
        settings.cookie_name,
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.session_absolute_ttl,
        path="/",
    )


def clear_session_cookie(response, settings: Settings) -> None:
    response.delete_cookie(settings.cookie_name, path="/")


def set_csrf_cookie(response, settings: Settings, token: str) -> None:
    response.set_cookie(
        "csrf",
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=3600,
        path="/",
    )
