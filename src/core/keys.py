import json
import secrets
import time

from joserfc.jwk import KeySet, RSAKey
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.crypto import decrypt_secret, encrypt_secret
from src.models import SigningKey
from src.core.settings import Settings

# ponytail: in-process TTL cache. Multi-instance rotation can lag up to KEY_CACHE_SECONDS. Upgrade: NOTIFY/LISTEN or shared cache.
_priv: RSAKey | None = None
_priv_at = 0.0
_pub: dict | None = None
_pub_at = 0.0


def _clear_cache() -> None:
    global _priv, _priv_at, _pub, _pub_at
    _priv = None
    _priv_at = 0.0
    _pub = None
    _pub_at = 0.0


async def ensure_active_key(session: AsyncSession, settings: Settings) -> RSAKey:
    row = (
        await session.execute(select(SigningKey).where(SigningKey.status == "active"))
    ).scalar_one_or_none()
    if row is None:
        return await _insert_key(session, settings, "active")
    return _load_private(settings, row)


async def rotate_keys(session: AsyncSession, settings: Settings) -> str:
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    current = (
        await session.execute(select(SigningKey).where(SigningKey.status == "active"))
    ).scalar_one_or_none()
    if current is not None:
        current.status = "retiring"
        current.retire_after = now + timedelta(seconds=settings.key_retire_seconds)
    new = await _insert_key(session, settings, "active")
    _clear_cache()
    return new.kid


async def public_jwks(session: AsyncSession, settings: Settings) -> dict:
    global _pub, _pub_at
    now = time.monotonic()
    if _pub is not None and now - _pub_at < settings.key_cache_seconds:
        return _pub
    from datetime import UTC, datetime

    cutoff = datetime.now(UTC)
    rows = (
        await session.execute(
            select(SigningKey).where(
                SigningKey.status.in_(("active", "next", "retiring")),
            )
        )
    ).scalars()
    keys = []
    for row in rows:
        if row.status == "retiring" and row.retire_after is not None and row.retire_after < cutoff:
            continue
        keys.append(row.public_jwk)
    if not keys:
        active_key = await ensure_active_key(session, settings)
        keys = [active_key.as_dict(private=False)]
    _pub = {"keys": keys}
    _pub_at = now
    return _pub


async def signing_key(session: AsyncSession, settings: Settings) -> RSAKey:
    global _priv, _priv_at
    now = time.monotonic()
    if _priv is not None and now - _priv_at < settings.key_cache_seconds:
        return _priv
    key = await ensure_active_key(session, settings)
    _priv = key
    _priv_at = now
    return key


def verify_key_set(jwks: dict) -> KeySet:
    return KeySet.import_key_set(jwks)


async def _insert_key(session: AsyncSession, settings: Settings, status: str) -> RSAKey:
    kid = secrets.token_hex(8)
    key = RSAKey.generate_key(2048, private=True, parameters={"use": "sig", "alg": "RS256", "kid": kid})
    session.add(
        SigningKey(
            kid=kid,
            private_jwk_enc=encrypt_secret(settings.key_encryption_key, json.dumps(key.as_dict(private=True))),
            public_jwk=key.as_dict(private=False),
            status=status,
        )
    )
    await session.flush()
    _clear_cache()
    return key


def _load_private(settings: Settings, row: SigningKey) -> RSAKey:
    data = json.loads(decrypt_secret(settings.key_encryption_key, row.private_jwk_enc))
    return RSAKey.import_key(data)
