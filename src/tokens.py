from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from joserfc import jwt
from joserfc.jwk import RSAKey
from joserfc.jwt import JWTClaimsRegistry
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from idp.crypto import at_hash, hash_token, pkce_ok, random_token
from idp.keys import public_jwks, signing_key, verify_key_set
from idp.models import AuthorizationCode, OAuthClient, RefreshToken, User
from idp.settings import Settings

ALLOWED_CLAIMS = frozenset(
    {
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "jti",
        "auth_time",
        "nonce",
        "at_hash",
        "amr",
        "scope",
        "client_id",
        "typ",
        "email",
        "email_verified",
        "idp_roles",
    }
)


class TokenError(Exception):
    def __init__(self, error: str, description: str | None = None):
        self.error = error
        self.description = description


def mint_idp_jwt(claims: dict[str, Any], key: RSAKey) -> str:
    extra = set(claims) - ALLOWED_CLAIMS
    if extra:
        raise ValueError(f"forbidden claims: {sorted(extra)}")
    typ = "at+jwt" if claims.get("typ") == "at+jwt" else "JWT"
    return jwt.encode({"alg": "RS256", "kid": key.kid, "typ": typ}, claims, key)


def _now() -> datetime:
    return datetime.now(UTC)


def _ts(dt: datetime) -> int:
    return int(dt.timestamp())


async def issue_code(
    session: AsyncSession,
    settings: Settings,
    *,
    client: OAuthClient,
    user: User,
    redirect_uri: str,
    scope: str,
    nonce: str | None,
    code_challenge: str,
    auth_time: datetime,
    amr: list[str],
) -> str:
    raw = random_token(32)
    now = _now()
    session.add(
        AuthorizationCode(
            code_hash=hash_token(settings.token_hash_pepper, raw),
            client_id=client.client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
            auth_time=auth_time,
            amr=amr,
            expires_at=now + timedelta(seconds=settings.auth_code_ttl),
        )
    )
    return raw


async def revoke_family(session: AsyncSession, family_id: uuid.UUID, reason: str) -> None:
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=_now(), revoked_reason=reason)
    )


async def _mint_pair(
    session: AsyncSession,
    settings: Settings,
    *,
    user: User,
    client: OAuthClient,
    scope: str,
    nonce: str | None,
    auth_time: datetime,
    amr: list[str],
    family_id: uuid.UUID,
    family_expires_at: datetime,
    parent_id: uuid.UUID | None,
) -> dict:
    now = _now()
    key = await signing_key(session, settings)
    access_claims = {
        "iss": settings.public_base,
        "sub": str(user.id),
        "aud": client.client_id,
        "exp": _ts(now) + settings.idp_access_ttl,
        "iat": _ts(now),
        "jti": str(uuid.uuid4()),
        "typ": "at+jwt",
        "scope": scope,
        "client_id": client.client_id,
        "auth_time": _ts(auth_time),
        "amr": amr,
    }
    access = mint_idp_jwt(access_claims, key)
    id_claims: dict[str, Any] = {
        "iss": settings.public_base,
        "sub": str(user.id),
        "aud": client.client_id,
        "exp": _ts(now) + settings.idp_access_ttl,
        "iat": _ts(now),
        "auth_time": _ts(auth_time),
        "amr": amr,
        "at_hash": at_hash(access),
    }
    if nonce:
        id_claims["nonce"] = nonce
    scopes_set = set(scope.split())
    if "email" in scopes_set:
        id_claims["email"] = user.email
        id_claims["email_verified"] = user.email_verified
    if "idp_roles" in scopes_set or "roles" in scopes_set:
        from idp.roles import get_user_roles

        id_claims["idp_roles"] = await get_user_roles(session, user.id)
    id_token = mint_idp_jwt(id_claims, key)
    refresh_raw = random_token(48)
    row = RefreshToken(
        token_hash=hash_token(settings.token_hash_pepper, refresh_raw),
        family_id=family_id,
        parent_id=parent_id,
        user_id=user.id,
        client_id=client.client_id,
        scope=scope,
        auth_time=auth_time,
        amr=amr,
        expires_at=now + timedelta(seconds=settings.idp_refresh_ttl),
        family_expires_at=family_expires_at,
    )
    session.add(row)
    await session.flush()
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": settings.idp_access_ttl,
        "refresh_token": refresh_raw,
        "id_token": id_token,
        "scope": scope,
    }


async def exchange_code(
    session: AsyncSession,
    settings: Settings,
    *,
    client: OAuthClient,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict:
    now = _now()
    row = (
        await session.execute(
            select(AuthorizationCode)
            .where(AuthorizationCode.code_hash == hash_token(settings.token_hash_pepper, code))
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        raise TokenError("invalid_grant", "unknown code")
    if row.consumed_at is not None:
        if row.issued_family_id is not None:
            await revoke_family(session, row.issued_family_id, "authorization_code_replay")
        raise TokenError("invalid_grant", "code already used")
    if row.expires_at < now:
        raise TokenError("invalid_grant", "code expired")
    if row.client_id != client.client_id:
        raise TokenError("invalid_grant", "client mismatch")
    if row.redirect_uri != redirect_uri:
        raise TokenError("invalid_grant", "redirect_uri mismatch")
    if not pkce_ok(code_verifier, row.code_challenge):
        raise TokenError("invalid_grant", "pkce verification failed")
    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise TokenError("invalid_grant", "user disabled")
    family_id = uuid.uuid4()
    row.consumed_at = now
    row.issued_family_id = family_id
    return await _mint_pair(
        session,
        settings,
        user=user,
        client=client,
        scope=row.scope,
        nonce=row.nonce,
        auth_time=row.auth_time,
        amr=row.amr,
        family_id=family_id,
        family_expires_at=now + timedelta(seconds=settings.idp_refresh_absolute_ttl),
        parent_id=None,
    )


async def rotate_refresh(
    session: AsyncSession,
    settings: Settings,
    *,
    client: OAuthClient,
    refresh_token: str,
) -> dict:
    now = _now()
    row = (
        await session.execute(
            select(RefreshToken)
            .where(RefreshToken.token_hash == hash_token(settings.token_hash_pepper, refresh_token))
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None:
        raise TokenError("invalid_grant", "unknown refresh token")
    dead = row.used_at is not None or row.revoked_at is not None
    if dead:
        await revoke_family(session, row.family_id, "refresh_reuse")
        raise TokenError("invalid_grant", "refresh token reuse")
    if row.expires_at < now or row.family_expires_at < now:
        raise TokenError("invalid_grant", "refresh token expired")
    if row.client_id != client.client_id:
        raise TokenError("invalid_grant", "client mismatch")
    user = await session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise TokenError("invalid_grant", "user disabled")
    row.used_at = now
    return await _mint_pair(
        session,
        settings,
        user=user,
        client=client,
        scope=row.scope,
        nonce=None,
        auth_time=row.auth_time,
        amr=row.amr,
        family_id=row.family_id,
        family_expires_at=row.family_expires_at,
        parent_id=row.id,
    )


async def verify_access_token(session: AsyncSession, settings: Settings, token: str) -> dict:
    jwks = await public_jwks(session, settings)
    obj = jwt.decode(token, verify_key_set(jwks))
    JWTClaimsRegistry(
        iss={"essential": True, "value": settings.public_base},
        exp={"essential": True},
    ).validate(obj.claims)
    if obj.claims.get("typ") != "at+jwt":
        raise TokenError("invalid_token", "not an access token")
    return obj.claims
