from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from joserfc import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.deps import db_dep, ip_of, s_dep
from src.core.keys import public_jwks, verify_key_set
from src.core.oauth_errors import append_query
from src.core.settings import Settings
from src.html import page
from src.models import OAuthClient
from src.services.audit import audit
from src.services.sessions import clear_session_cookie, load_session

router = APIRouter()


@router.get("/logout")
async def logout(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    id_token_hint: str | None = None,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
):
    sess = await load_session(session, settings, request.cookies.get(settings.cookie_name))
    if sess is not None:
        from datetime import UTC, datetime

        sess.revoked_at = datetime.now(UTC)
        await audit(session, "logout", user_id=sess.user_id, ip=ip_of(request))

    dest = None
    if post_logout_redirect_uri and id_token_hint:
        try:
            claims = jwt.decode(id_token_hint, verify_key_set(await public_jwks(session, settings))).claims
            aud = claims.get("aud")
            client_id = aud if isinstance(aud, str) else (aud[0] if aud else None)
        except Exception:
            client_id = None
        if client_id:
            client = await session.get(OAuthClient, client_id)
            if client and post_logout_redirect_uri in (client.post_logout_redirect_uris or []):
                dest = append_query(post_logout_redirect_uri, state=state) if state else post_logout_redirect_uri

    if dest:
        response = RedirectResponse(dest, status_code=302)
    else:
        response = page(request, settings, "logged_out.html")
    clear_session_cookie(response, settings)
    return response
