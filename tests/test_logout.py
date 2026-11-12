import uuid
from datetime import UTC, datetime, timedelta
from joserfc import jwt
from joserfc.jwk import RSAKey, KeySet
from fastapi.testclient import TestClient
from sqlalchemy import select

from src.main import app
from src.core.oauth_errors import append_query
from src.core.keys import signing_key
from src.core.settings import get_settings
from src.core.crypto import hash_token
from src.models import OAuthClient, RefreshToken, User
from src.routers.logout import _is_post_logout_redirect_allowed, _normalize_uri
from src.services.tokens import mint_idp_jwt


def test_normalize_uri():
    assert _normalize_uri("http://localhost:4200") == "http://localhost:4200"
    assert _normalize_uri("http://localhost:4200/") == "http://localhost:4200"
    assert _normalize_uri("https://example.com/app/callback/") == "https://example.com/app/callback"
    assert _normalize_uri("https://example.com/app/callback") == "https://example.com/app/callback"
    assert _normalize_uri("HTTP://LOCALHOST:4200/") == "http://localhost:4200"


def test_is_post_logout_redirect_allowed():
    allowed = ["http://localhost:4200/"]
    assert _is_post_logout_redirect_allowed("http://localhost:4200", allowed) is True
    assert _is_post_logout_redirect_allowed("http://localhost:4200/", allowed) is True

    allowed_no_slash = ["http://localhost:4200"]
    assert _is_post_logout_redirect_allowed("http://localhost:4200", allowed_no_slash) is True
    assert _is_post_logout_redirect_allowed("http://localhost:4200/", allowed_no_slash) is True

    assert _is_post_logout_redirect_allowed("http://localhost:4200/other", allowed) is False
    assert _is_post_logout_redirect_allowed("http://attacker.com", allowed) is False
    assert _is_post_logout_redirect_allowed("", allowed) is False
    assert _is_post_logout_redirect_allowed(None, allowed) is False
    assert _is_post_logout_redirect_allowed("http://localhost:4200", []) is False


def test_direct_idp_logout():
    with TestClient(app) as client:
        # Direct IdP logout with no params displays signed out page and clears cookie
        res = client.get("/logout", follow_redirects=False)
        assert res.status_code == 200
        assert "Signed Out" in res.text
        assert 'idp_session=""' in res.headers.get("set-cookie", "")


def test_client_logout_invalid_redirect_uri():
    with TestClient(app) as client:
        # Client logout with unknown post_logout_redirect_uri returns 400 error page without clearing session cookie
        res = client.get(
            "/logout",
            params={"post_logout_redirect_uri": "http://evil.com", "client_id": "nonexistent"},
            follow_redirects=False,
        )
        assert res.status_code == 400
        assert "Invalid post-logout redirect URI." in res.text
        # Cookie is NOT cleared
        assert 'idp_session=""' not in res.headers.get("set-cookie", "")


def test_client_logout_decoupled_from_idp_session():
    with TestClient(app) as client:
        async def setup_data():
            import src.core.db as db_mod
            async with db_mod.SessionLocal() as s:
                cl = (await s.execute(select(OAuthClient).where(OAuthClient.post_logout_redirect_uris.is_not(None)))).scalars().first()
                if not cl or not cl.post_logout_redirect_uris:
                    return None, None, None, None

                # Find or create a user and refresh token
                u = (await s.execute(select(User))).scalars().first()
                if not u:
                    return None, None, None, None

                test_user_id = u.id
                now = datetime.now(UTC)
                rt = RefreshToken(
                    token_hash=hash_token(get_settings().token_hash_pepper, f"test_rt_{now.timestamp()}"),
                    family_id=uuid.uuid4(),
                    user_id=test_user_id,
                    client_id=cl.client_id,
                    scope="openid",
                    auth_time=now,
                    amr=["pwd"],
                    expires_at=now + timedelta(days=1),
                    family_expires_at=now + timedelta(days=7),
                )
                s.add(rt)
                await s.commit()

                key = await signing_key(s, get_settings())
                return cl.client_id, cl.post_logout_redirect_uris[0], key, test_user_id

        cid, reg_uri, key, uid = client.portal.call(setup_data)
        if not cid:
            return

        req_uri = reg_uri.rstrip("/") if reg_uri.endswith("/") else reg_uri + "/"

        id_token = mint_idp_jwt({
            "iss": get_settings().public_base,
            "sub": str(uid),
            "aud": cid,
            "exp": 9999999999,
            "iat": 1000000000,
            "auth_time": 1000000000,
            "amr": ["pwd"],
            "at_hash": "dummy",
        }, key)

        # Perform client logout
        res = client.get(
            "/logout",
            params={"id_token_hint": id_token, "post_logout_redirect_uri": req_uri, "state": "state123"},
            follow_redirects=False,
        )
        # 1. Must redirect 302
        assert res.status_code == 302
        assert res.headers["location"].startswith(req_uri)
        assert "state=state123" in res.headers["location"]

        # 2. Must NOT clear idp_session cookie
        assert 'idp_session=""' not in res.headers.get("set-cookie", "")

        # 3. Must have revoked the user's refresh token for this client
        async def verify_rt_revoked():
            import src.core.db as db_mod
            async with db_mod.SessionLocal() as s:
                rts = (await s.execute(
                    select(RefreshToken).where(
                        RefreshToken.client_id == cid,
                        RefreshToken.user_id == uid,
                    )
                )).scalars().all()
                for r in rts:
                    assert r.revoked_at is not None
                    assert r.revoked_reason == "client_logout"

        client.portal.call(verify_rt_revoked)
