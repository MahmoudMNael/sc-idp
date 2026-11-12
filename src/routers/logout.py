import logging
from urllib.parse import urlsplit, urlunsplit

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

logger = logging.getLogger(__name__)

router = APIRouter()


def _normalize_uri(uri: str) -> str:
    parts = urlsplit(uri.strip())
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    # Normalize path: strip trailing slash so '/' and '' match, as well as '/path' and '/path/'
    path = parts.path.rstrip("/")
    return urlunsplit((scheme, netloc, path, parts.query, parts.fragment))


def _is_post_logout_redirect_allowed(candidate: str | None, allowed_list: list[str] | None) -> bool:
    if not candidate or not allowed_list:
        return False
    if candidate in allowed_list:
        return True
    try:
        norm_candidate = _normalize_uri(candidate)
        for allowed in allowed_list:
            if not allowed:
                continue
            if norm_candidate == _normalize_uri(allowed):
                return True
    except Exception:
        return False
    return False


@router.get("/logout")
@router.post("/logout")
async def logout(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    id_token_hint: str | None = None,
    post_logout_redirect_uri: str | None = None,
    redirect_uri: str | None = None,
    state: str | None = None,
    client_id: str | None = None,
):
    if request.method == "POST":
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            try:
                form = await request.form()
                id_token_hint = id_token_hint or (str(form["id_token_hint"]) if "id_token_hint" in form else None)
                post_logout_redirect_uri = post_logout_redirect_uri or (
                    str(form["post_logout_redirect_uri"]) if "post_logout_redirect_uri" in form else None
                )
                redirect_uri = redirect_uri or (str(form["redirect_uri"]) if "redirect_uri" in form else None)
                state = state or (str(form["state"]) if "state" in form else None)
                client_id = client_id or (str(form["client_id"]) if "client_id" in form else None)
            except Exception:
                pass

    target_uri = post_logout_redirect_uri or redirect_uri

    sess = await load_session(session, settings, request.cookies.get(settings.cookie_name))
    if sess is not None:
        from datetime import UTC, datetime

        sess.revoked_at = datetime.now(UTC)
        await audit(session, "logout", user_id=sess.user_id, ip=ip_of(request))

    target_client_id: str | None = None
    if id_token_hint:
        try:
            jwks = await public_jwks(session, settings)
            claims = jwt.decode(id_token_hint, verify_key_set(jwks)).claims
            aud = claims.get("aud")
            token_client_id = aud if isinstance(aud, str) else (aud[0] if aud else None)
            if client_id and token_client_id and client_id != token_client_id:
                logger.warning(
                    "client_id %r does not match id_token_hint aud %r in logout request",
                    client_id,
                    token_client_id,
                )
                token_client_id = None
            target_client_id = token_client_id
        except Exception as exc:
            logger.warning("Failed to decode id_token_hint in logout: %s", exc)
            target_client_id = None
    elif client_id:
        target_client_id = client_id

    dest = None
    if target_uri and target_client_id:
        client = await session.get(OAuthClient, target_client_id)
        if client and _is_post_logout_redirect_allowed(target_uri, client.post_logout_redirect_uris or []):
            dest = append_query(target_uri, state=state) if state else target_uri
        elif client:
            logger.warning(
                "post_logout_redirect_uri %r is not allowed for client %s (registered: %r)",
                target_uri,
                target_client_id,
                client.post_logout_redirect_uris,
            )

    if dest:
        response = RedirectResponse(dest, status_code=302)
    else:
        response = page(request, settings, "logged_out.html")
    clear_session_cookie(response, settings)
    return response
