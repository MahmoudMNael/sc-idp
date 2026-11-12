import re
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select

from src.core.crypto import hash_password, hash_token, pkce_s256, random_token
from src.core.keys import signing_key
from src.core.settings import get_settings
from src.main import app
from src.models import AuthSession, OAuthClient, User
from src.services.sessions import create_session, set_session_cookie
from src.services.tokens import mint_idp_jwt


def _csrf(text: str) -> str:
    m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', text)
    if not m:
        m = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']', text)
    return m.group(1) if m else ""


def test_account_confirm_and_switching_flow():
    with TestClient(app) as client:
        settings = get_settings()

        async def setup():
            import src.core.db as db_mod
            async with db_mod.SessionLocal() as s:
                # 1. Create client
                cid = f"test-client-{uuid.uuid4().hex[:8]}"
                cl = OAuthClient(
                    client_id=cid,
                    client_secret_hash=hash_token(settings.token_hash_pepper, "secret"),
                    name="Test App",
                    redirect_uris=["http://testapp.test/cb"],
                    allowed_scopes=["openid", "profile", "email"],
                    is_first_party=True,
                    is_active=True,
                )
                s.add(cl)

                # 2. Create User 1
                u1_id = uuid.uuid4()
                u1 = User(
                    id=u1_id,
                    email=f"user1-{uuid.uuid4().hex[:8]}@example.test",
                    password_hash=hash_password(settings, "Password123!"),
                    first_name="Alice",
                    last_name="Wonderland",
                    email_verified=True,
                    is_active=True,
                )
                s.add(u1)

                # 3. Create User 2
                u2_id = uuid.uuid4()
                u2 = User(
                    id=u2_id,
                    email=f"user2-{uuid.uuid4().hex[:8]}@example.test",
                    password_hash=hash_password(settings, "Password123!"),
                    first_name="Bob",
                    last_name="Builder",
                    email_verified=True,
                    is_active=True,
                )
                s.add(u2)

                await s.commit()

                # Create session for User 1
                raw1 = await create_session(s, settings, u1, ["pwd"], ip="127.0.0.1", user_agent="test")
                await s.commit()

                return cl.client_id, u1.email, u2.email, raw1, str(u1_id), str(u2_id)

        client_id, email1, email2, raw_session1, u1_id_str, u2_id_str = client.portal.call(setup)

        verifier = random_token(32)
        challenge = pkce_s256(verifier)
        auth_params = {
            "client_id": client_id,
            "redirect_uri": "http://testapp.test/cb",
            "response_type": "code",
            "scope": "openid email",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "state_abc",
        }

        # ------------------------------------------------------------------
        # Step 1: Active session for User 1 initiates /authorize
        # Should render account_confirm.html with clickable row card and buttons
        # ------------------------------------------------------------------
        client.cookies.set(settings.cookie_name, raw_session1)
        res = client.get("/authorize", params=auth_params, follow_redirects=False)
        assert res.status_code == 200, res.text
        assert "Choose an Account" in res.text
        assert "Alice Wonderland" in res.text
        assert email1 in res.text
        assert "account-card-btn" in res.text
        assert "Use a different account" in res.text
        assert "Cancel" in res.text

        csrf_val = _csrf(res.text)
        assert csrf_val != ""

        # Extract next param from form
        m_next = re.search(r'name=["\']next["\']\s+value=["\']([^"\']+)["\']', res.text)
        assert m_next
        nxt = m_next.group(1)

        # ------------------------------------------------------------------
        # Step 2: Cancel button works
        # ------------------------------------------------------------------
        cancel_res = client.get(f"/cancel?next={nxt}", follow_redirects=False)
        assert cancel_res.status_code == 302
        assert cancel_res.headers["location"].startswith("http://testapp.test/cb")
        assert "error=access_denied" in cancel_res.headers["location"]
        assert "state=state_abc" in cancel_res.headers["location"]

        # ------------------------------------------------------------------
        # Step 3: Clicking the User 1 card submits POST /authorize/confirm
        # Since client is first-party, it immediately issues code for User 1
        # ------------------------------------------------------------------
        confirm_res = client.post(
            "/authorize/confirm",
            data={"csrf_token": csrf_val, "next": nxt},
            follow_redirects=False,
        )
        assert confirm_res.status_code == 302
        loc = confirm_res.headers["location"]
        assert loc.startswith("http://testapp.test/cb")
        assert "code=" in loc
        assert "state=state_abc" in loc

        # ------------------------------------------------------------------
        # Step 4: Click "Use a different account" -> GET /login?switch_account=1
        # Should display switch account login page without redirecting
        # ------------------------------------------------------------------
        switch_page = client.get(f"/login?next={nxt}&switch_account=1", follow_redirects=False)
        assert switch_page.status_code == 200
        assert "Switch Account" in switch_page.text
        assert "Sign in with a different account" in switch_page.text

        login_csrf = _csrf(switch_page.text)
        assert login_csrf != ""

        # ------------------------------------------------------------------
        # Step 5: Sign in as User 2 (Bob)
        # Should create session for User 2 WITHOUT revoking User 1's session
        # ------------------------------------------------------------------
        login_res = client.post(
            "/login",
            data={
                "email": email2,
                "password": "Password123!",
                "csrf_token": login_csrf,
                "next": nxt,
            },
            follow_redirects=False,
        )
        assert login_res.status_code == 303
        redirect_after_login = login_res.headers["location"]
        assert "/authorize?" in redirect_after_login
        assert "confirmed=" in redirect_after_login

        # Verify User 1's session in DB was NOT revoked!
        async def verify_user1_session_alive():
            import src.core.db as db_mod
            async with db_mod.SessionLocal() as s:
                sess1 = (await s.execute(
                    select(AuthSession).where(
                        AuthSession.session_token_hash == hash_token(settings.token_hash_pepper, raw_session1)
                    )
                )).scalar_one_or_none()
                assert sess1 is not None
                assert sess1.revoked_at is None, f"User 1 session was revoked: {sess1.revoked_at}"

        client.portal.call(verify_user1_session_alive)

        # ------------------------------------------------------------------
        # Step 6: Follow the redirect back to /authorize
        # Because confirmed ticket is present, it skips account chooser and issues code for User 2!
        # ------------------------------------------------------------------
        final_az = client.get(redirect_after_login, follow_redirects=False)
        assert final_az.status_code == 302, final_az.text
        cb_loc = final_az.headers["location"]
        assert cb_loc.startswith("http://testapp.test/cb")
        assert "code=" in cb_loc
        code_user2 = parse_qs(urlparse(cb_loc).query)["code"][0]

        # Verify issued authorization code belongs to User 2
        async def verify_code_owner():
            import src.core.db as db_mod
            from src.models import AuthorizationCode
            async with db_mod.SessionLocal() as s:
                auth_code_row = (await s.execute(
                    select(AuthorizationCode).where(
                        AuthorizationCode.code_hash == hash_token(settings.token_hash_pepper, code_user2)
                    )
                )).scalar_one_or_none()
                assert auth_code_row is not None
                assert str(auth_code_row.user_id) == u2_id_str

        client.portal.call(verify_code_owner)

        # ------------------------------------------------------------------
        # Step 7: prompt=none bypasses account chooser (Silent SSO)
        # ------------------------------------------------------------------
        none_verifier = random_token(32)
        none_challenge = pkce_s256(none_verifier)
        none_res = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": "http://testapp.test/cb",
                "response_type": "code",
                "scope": "openid",
                "code_challenge": none_challenge,
                "code_challenge_method": "S256",
                "prompt": "none",
            },
            follow_redirects=False,
        )
        assert none_res.status_code == 302
        assert "code=" in none_res.headers["location"]


def test_third_party_client_shows_consent_after_account_confirm():
    with TestClient(app) as client:
        settings = get_settings()

        async def setup():
            import src.core.db as db_mod
            async with db_mod.SessionLocal() as s:
                cid = f"test-3p-client-{uuid.uuid4().hex[:8]}"
                cl = OAuthClient(
                    client_id=cid,
                    client_secret_hash=hash_token(settings.token_hash_pepper, "secret"),
                    name="External Service",
                    redirect_uris=["http://external.test/cb"],
                    allowed_scopes=["openid", "profile", "email"],
                    is_first_party=False,
                    is_active=True,
                )
                s.add(cl)
                u = User(
                    id=uuid.uuid4(),
                    email=f"user3p-{uuid.uuid4().hex[:8]}@example.test",
                    password_hash=hash_password(settings, "Password123!"),
                    first_name="Charlie",
                    last_name="Brown",
                    email_verified=True,
                    is_active=True,
                )
                s.add(u)
                await s.commit()

                raw = await create_session(s, settings, u, ["pwd"], ip="127.0.0.1", user_agent="test")
                await s.commit()
                return cl.client_id, u.email, raw

        client_id, email, raw_sess = client.portal.call(setup)
        client.cookies.set(settings.cookie_name, raw_sess)

        verifier = random_token(32)
        challenge = pkce_s256(verifier)

        # 1. Authorize shows account chooser
        res = client.get(
            "/authorize",
            params={
                "client_id": client_id,
                "redirect_uri": "http://external.test/cb",
                "response_type": "code",
                "scope": "openid email",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "state3p",
            },
            follow_redirects=False,
        )
        assert res.status_code == 200
        assert "Choose an Account" in res.text
        assert "Charlie Brown" in res.text

        csrf_val = _csrf(res.text)
        m_next = re.search(r'name=["\']next["\']\s+value=["\']([^"\']+)["\']', res.text)
        assert m_next
        nxt = m_next.group(1)

        # 2. Confirm account -> since 3rd party, leads to consent screen
        confirm_res = client.post(
            "/authorize/confirm",
            data={"csrf_token": csrf_val, "next": nxt},
            follow_redirects=False,
        )
        assert confirm_res.status_code == 200
        assert "Authorize Access" in confirm_res.text
        assert "External Service" in confirm_res.text
        assert "openid" in confirm_res.text

        consent_csrf = _csrf(confirm_res.text)
        # 3. Allow consent -> redirects to callback with code
        allow_res = client.post(
            "/consent",
            data={"csrf_token": consent_csrf, "next": nxt, "decision": "allow"},
            follow_redirects=False,
        )
        assert allow_res.status_code == 302
        assert allow_res.headers["location"].startswith("http://external.test/cb")
        assert "code=" in allow_res.headers["location"]
        assert "state=state3p" in allow_res.headers["location"]

