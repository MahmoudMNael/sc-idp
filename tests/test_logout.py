from datetime import UTC, datetime
from joserfc import jwt
from joserfc.jwk import RSAKey, KeySet
from fastapi.testclient import TestClient
from sqlalchemy import select

from src.main import app
from src.core.oauth_errors import append_query
from src.core.keys import signing_key
from src.core.settings import get_settings
from src.models import OAuthClient
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


def test_logout_endpoint_fallback():
    with TestClient(app) as client:
        # Visiting logout with no params displays signed out page
        res = client.get("/logout", follow_redirects=False)
        assert res.status_code == 200
        assert "Signed Out" in res.text

        # Visiting logout with unknown post_logout_redirect_uri falls back to signed out page
        res2 = client.get(
            "/logout",
            params={"post_logout_redirect_uri": "http://evil.com", "client_id": "nonexistent"},
            follow_redirects=False,
        )
        assert res2.status_code == 200
        assert "Signed Out" in res2.text


def test_logout_redirect_with_trailing_slash_mismatch():
    with TestClient(app) as client:
        # Find any client in db
        async def get_test_client():
            import src.core.db as db_mod
            async with db_mod.SessionLocal() as s:
                cl = (await s.execute(select(OAuthClient).where(OAuthClient.post_logout_redirect_uris.is_not(None)))).scalars().first()
                if cl and cl.post_logout_redirect_uris:
                    key = await signing_key(s, get_settings())
                    return cl.client_id, cl.post_logout_redirect_uris[0], key
                return None, None, None

        cid, reg_uri, key = client.portal.call(get_test_client)
        if not cid:
            return

        # If registered has slash, request without slash (or vice versa)
        if reg_uri.endswith("/"):
            req_uri = reg_uri.rstrip("/")
        else:
            req_uri = reg_uri + "/"

        # 1. Test redirect using client_id
        res = client.get(
            "/logout",
            params={"client_id": cid, "post_logout_redirect_uri": req_uri, "state": "xyz123"},
            follow_redirects=False,
        )
        assert res.status_code == 302
        assert res.headers["location"].startswith(req_uri)
        assert "state=xyz123" in res.headers["location"]

        # 2. Test redirect using id_token_hint
        id_token = mint_idp_jwt({
            "iss": get_settings().public_base,
            "sub": "test-user",
            "aud": cid,
            "exp": 9999999999,
            "iat": 1000000000,
            "auth_time": 1000000000,
            "amr": ["pwd"],
            "at_hash": "dummy",
        }, key)
        res_hint = client.get(
            "/logout",
            params={"id_token_hint": id_token, "post_logout_redirect_uri": req_uri},
            follow_redirects=False,
        )
        assert res_hint.status_code == 302
        assert res_hint.headers["location"] == req_uri

        # 3. Test POST /logout
        res_post = client.post(
            "/logout",
            data={"id_token_hint": id_token, "post_logout_redirect_uri": req_uri},
            follow_redirects=False,
        )
        assert res_post.status_code == 302
        assert res_post.headers["location"] == req_uri
