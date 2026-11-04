from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.crypto import csrf_ok
from src.core.deps import db_dep, s_dep
from src.core.oauth_errors import oauth_redirect
from src.core.settings import Settings
from src.html import page
from src.models import OAuthClient, User
from src.routers.accounts import load_next, sign_next
from src.services.sessions import load_session
from src.services.tokens import issue_code

router = APIRouter()


async def _client(session: AsyncSession, client_id: str | None) -> OAuthClient | None:
    if not client_id:
        return None
    row = await session.get(OAuthClient, client_id)
    if row is None or not row.is_active:
        return None
    return row


def _redirect_ok(client: OAuthClient, uri: str | None) -> bool:
    return bool(uri) and uri in client.redirect_uris


def _scopes_ok(requested: list[str], allowed: list[str]) -> bool:
    return "openid" in requested and set(requested) <= set(allowed)


async def _issue(session, settings, client, user, sess, params: dict) -> RedirectResponse:
    code = await issue_code(
        session,
        settings,
        client=client,
        user=user,
        redirect_uri=params["redirect_uri"],
        scope=params["scope"],
        nonce=params.get("nonce") or None,
        code_challenge=params["code_challenge"],
        auth_time=sess.auth_time,
        amr=list(sess.amr),
    )
    return oauth_redirect(params["redirect_uri"], code=code, state=params.get("state") or None)


@router.get("/authorize")
async def authorize(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    q = request.query_params
    client_id = q.get("client_id")
    redirect_uri = q.get("redirect_uri")
    client = await _client(session, client_id)
    if client is None:
        return page(request, settings, "error.html", status=400, error="Unknown or inactive client.")
    if not _redirect_ok(client, redirect_uri):
        return page(request, settings, "error.html", status=400, error="redirect_uri is not registered for this client.")

    def fail(error: str, description: str | None = None):
        return oauth_redirect(redirect_uri, error=error, error_description=description, state=q.get("state"))

    if q.get("response_type") != "code":
        return fail("unsupported_response_type")
    if not q.get("code_challenge") or q.get("code_challenge_method") != "S256":
        return fail("invalid_request", "PKCE S256 is required")
    scope = q.get("scope") or ""
    scopes = scope.split()
    if not _scopes_ok(scopes, list(client.allowed_scopes)):
        return fail("invalid_scope")

    params = {
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "nonce": q.get("nonce") or "",
        "code_challenge": q.get("code_challenge"),
        "state": q.get("state") or "",
        "client_id": client.client_id,
    }
    nxt = sign_next(settings, request.url.query)
    prompt = q.get("prompt") or ""
    max_age = q.get("max_age")
    sess = await load_session(session, settings, request.cookies.get(settings.cookie_name))
    needs_login = sess is None or "login" in prompt.split()
    if not needs_login and max_age is not None:
        try:
            if int((sess.auth_time.timestamp())) + int(max_age) < int(__import__("time").time()):
                needs_login = True
        except ValueError:
            return fail("invalid_request", "max_age must be an integer")

    if needs_login:
        if "none" in prompt.split():
            return fail("login_required")
        return RedirectResponse(f"/login?next={nxt}", status_code=302)

    user = await session.get(User, sess.user_id)
    if user is None or not user.is_active:
        if "none" in prompt.split():
            return fail("login_required")
        return RedirectResponse(f"/login?next={nxt}", status_code=302)

    if user.totp_enabled and "otp" not in sess.amr:
        if "none" in prompt.split():
            return fail("login_required")
        return RedirectResponse(f"/login/mfa?next={nxt}", status_code=302)

    needs_consent = (not client.is_first_party) or "consent" in prompt.split()
    if needs_consent:
        if "none" in prompt.split():
            return fail("consent_required")
        return page(
            request,
            settings,
            "consent.html",
            client_name=client.name,
            scopes=params["scope"],
            next=nxt,
            cancel_url=f"/cancel?next={nxt}",
        )
    return await _issue(session, settings, client, user, sess, params)


@router.post("/consent")
async def consent(
    request: Request,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    csrf_token: str = Form(""),
    next: str = Form(""),
    decision: str = Form(""),
):
    if not csrf_ok(settings.secret_key, request.cookies.get("csrf"), csrf_token):
        return page(request, settings, "error.html", status=400, error="Invalid or expired form token.")
    query = load_next(settings, next)
    if not query:
        return page(request, settings, "error.html", status=400, error="Authorization request expired. Start again from the application.")
    from urllib.parse import parse_qs

    parsed = {k: v[0] if v else "" for k, v in parse_qs(query, keep_blank_values=True).items()}
    client = await _client(session, parsed.get("client_id"))
    redirect_uri = parsed.get("redirect_uri")
    if client is None or not _redirect_ok(client, redirect_uri):
        return page(request, settings, "error.html", status=400, error="Unknown client.")
    if decision != "allow":
        return oauth_redirect(redirect_uri, error="access_denied", state=parsed.get("state") or None)
    sess = await load_session(session, settings, request.cookies.get(settings.cookie_name))
    if sess is None:
        return RedirectResponse(f"/login?next={next}", status_code=302)
    user = await session.get(User, sess.user_id)
    params = {
        "redirect_uri": redirect_uri,
        "scope": parsed.get("scope") or "",
        "nonce": parsed.get("nonce") or "",
        "code_challenge": parsed.get("code_challenge") or "",
        "state": parsed.get("state") or "",
        "client_id": client.client_id,
    }
    return await _issue(session, settings, client, user, sess, params)


@router.get("/cancel")
async def cancel(
    next: str = "",
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
):
    query = load_next(settings, next)
    if query:
        from urllib.parse import parse_qs

        parsed = {k: v[0] if v else "" for k, v in parse_qs(query, keep_blank_values=True).items()}
        client = await _client(session, parsed.get("client_id"))
        redirect_uri = parsed.get("redirect_uri")
        if client and _redirect_ok(client, redirect_uri):
            return oauth_redirect(redirect_uri, error="access_denied", state=parsed.get("state") or None)
    return RedirectResponse("/", status_code=302)

