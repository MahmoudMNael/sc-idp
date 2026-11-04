import base64
import binascii
import hmac
from urllib.parse import unquote_plus

from fastapi import APIRouter, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit import audit
from src.crypto import hash_token
from src.deps import db_dep, ip_of, s_dep
from src.models import OAuthClient
from src.oauth_errors import token_error
from src.ratelimit import allow
from src.settings import Settings
from src.tokens import TokenError, exchange_code, rotate_refresh

router = APIRouter()


async def _client_auth(
    request: Request, form: dict, session: AsyncSession, settings: Settings
) -> OAuthClient | None:
    client_id = None
    secret = None
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
            client_id, secret = decoded.split(":", 1)
            client_id, secret = unquote_plus(client_id), unquote_plus(secret)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return None
    if client_id is None:
        client_id = form.get("client_id")
        secret = form.get("client_secret")
    if not client_id or secret is None:
        return None
    client = await session.get(OAuthClient, client_id)
    if client is None or not client.is_active:
        hmac.compare_digest(hash_token(settings.token_hash_pepper, secret), hash_token(settings.token_hash_pepper, "x"))
        return None
    if not hmac.compare_digest(client.client_secret_hash, hash_token(settings.token_hash_pepper, secret)):
        return None
    return client


@router.post("/token")
async def token(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    form = {k: v for k, v in (await request.form()).items()}
    if not await allow(session, f"token:{ip_of(request) or 'unknown'}", settings.rate_limit_token, settings.rate_limit_window):
        return token_error("temporarily_unavailable", "rate limited", 429)
    client = await _client_auth(request, form, session, settings)
    if client is None:
        return token_error("invalid_client", status=401)
    grant = form.get("grant_type")
    try:
        if grant == "authorization_code":
            tokens = await exchange_code(
                session,
                settings,
                client=client,
                code=form.get("code") or "",
                redirect_uri=form.get("redirect_uri") or "",
                code_verifier=form.get("code_verifier") or "",
            )
            await audit(session, "token_code", user_id=None, client_id=client.client_id, ip=ip_of(request))
            return tokens
        if grant == "refresh_token":
            tokens = await rotate_refresh(
                session,
                settings,
                client=client,
                refresh_token=form.get("refresh_token") or "",
            )
            await audit(session, "token_refresh", client_id=client.client_id, ip=ip_of(request))
            return tokens
        return token_error("unsupported_grant_type")
    except TokenError as exc:
        if exc.description and "reuse" in exc.description:
            await audit(session, "refresh_reuse", client_id=client.client_id, ip=ip_of(request))
        if exc.description and "already used" in exc.description:
            await audit(session, "code_replay", client_id=client.client_id, ip=ip_of(request))
        return token_error(exc.error, exc.description)
