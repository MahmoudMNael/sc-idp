import re
import uuid
from datetime import UTC, datetime, timedelta
import pytest
from fastapi.testclient import TestClient
from joserfc import jwt
from sqlalchemy import select

from src.core.crypto import hash_password, hash_token, random_token
from src.core.keys import public_jwks, verify_key_set
from src.core.settings import get_settings
from src.main import app
from src.models import AuthSession, OAuthClient, RefreshToken, User
from src.services.tokens import TokenError, _mint_pair, rotate_refresh


def test_offline_access_controls_refresh_token_issuance():
    settings = get_settings()

    with TestClient(app) as http_client:
        async def run_test():
            import src.core.db as db_mod

            async with db_mod.SessionLocal() as session:
                user = User(
                    email=f"test-offline-{uuid.uuid4().hex[:8]}@example.com",
                    password_hash=hash_password(settings, "password123"),
                    first_name="Offline",
                    last_name="Tester",
                    email_verified=True,
                )
                session.add(user)

                client = OAuthClient(
                    client_id=f"client-{uuid.uuid4().hex[:8]}",
                    name="Offline Test Client",
                    client_secret_hash=hash_token(settings.token_hash_pepper, "secret"),
                    redirect_uris=["http://localhost:3000/callback"],
                    post_logout_redirect_uris=["http://localhost:3000/"],
                    allowed_scopes=["openid", "email", "profile"],
                    is_first_party=True,
                    is_active=True,
                )
                session.add(client)
                await session.flush()

                now = datetime.now(UTC)
                family_id = uuid.uuid4()
                family_expires = now + timedelta(days=30)

                # 1. Without offline_access: NO refresh token should be minted
                tokens_no_refresh = await _mint_pair(
                    session,
                    settings,
                    user=user,
                    client=client,
                    scope="openid email profile",
                    nonce="nonce-1",
                    auth_time=now,
                    amr=["pwd"],
                    family_id=family_id,
                    family_expires_at=family_expires,
                    parent_id=None,
                )
                assert "refresh_token" not in tokens_no_refresh
                assert "access_token" in tokens_no_refresh
                assert "id_token" in tokens_no_refresh

                # Check DB: no refresh token row created for family_id
                rt_count = (
                    await session.execute(
                        select(RefreshToken).where(RefreshToken.family_id == family_id)
                    )
                ).scalars().all()
                assert len(rt_count) == 0

                # 2. With offline_access: refresh token MUST be minted and saved
                family_id_2 = uuid.uuid4()
                tokens_with_refresh = await _mint_pair(
                    session,
                    settings,
                    user=user,
                    client=client,
                    scope="openid email profile offline_access",
                    nonce="nonce-2",
                    auth_time=now,
                    amr=["pwd"],
                    family_id=family_id_2,
                    family_expires_at=family_expires,
                    parent_id=None,
                )
                assert "refresh_token" in tokens_with_refresh
                rt_raw = tokens_with_refresh["refresh_token"]

                # Check DB: exactly one refresh token row created
                rt_row = (
                    await session.execute(
                        select(RefreshToken).where(RefreshToken.family_id == family_id_2)
                    )
                ).scalar_one_or_none()
                assert rt_row is not None
                assert rt_row.token_hash == hash_token(settings.token_hash_pepper, rt_raw)

                # 3. Downscoping on refresh: omit profile
                jwks = await public_jwks(session, settings)
                rotated = await rotate_refresh(
                    session,
                    settings,
                    client=client,
                    refresh_token=rt_raw,
                    requested_scope="openid email",
                )
                assert "refresh_token" in rotated
                assert "id_token" in rotated
                id_claims = jwt.decode(rotated["id_token"], verify_key_set(jwks)).claims
                assert "email" in id_claims
                assert "given_name" not in id_claims
                assert "family_name" not in id_claims
                assert "name" not in id_claims

                # 4. Scope exceeding granted: should fail
                with pytest.raises(TokenError) as exc_info:
                    await rotate_refresh(
                        session,
                        settings,
                        client=client,
                        refresh_token=rotated["refresh_token"],
                        requested_scope="openid email ungranted_scope",
                    )
                assert exc_info.value.error == "invalid_scope"

        http_client.portal.call(run_test)


def test_connected_apps_and_user_revocation():
    settings = get_settings()

    with TestClient(app) as http_client:
        async def setup_data():
            import src.core.db as db_mod

            async with db_mod.SessionLocal() as session:
                user = User(
                    email=f"test-revoke-{uuid.uuid4().hex[:8]}@example.com",
                    password_hash=hash_password(settings, "password123"),
                    first_name="Revoke",
                    last_name="Tester",
                    email_verified=True,
                )
                session.add(user)

                client1 = OAuthClient(
                    client_id=f"client1-{uuid.uuid4().hex[:8]}",
                    name="App One",
                    client_secret_hash=hash_token(settings.token_hash_pepper, "secret"),
                    redirect_uris=["http://localhost:3001/callback"],
                    post_logout_redirect_uris=["http://localhost:3001/"],
                    allowed_scopes=["openid", "email"],
                    is_first_party=True,
                    is_active=True,
                )
                client2 = OAuthClient(
                    client_id=f"client2-{uuid.uuid4().hex[:8]}",
                    name="App Two",
                    client_secret_hash=hash_token(settings.token_hash_pepper, "secret"),
                    redirect_uris=["http://localhost:3002/callback"],
                    post_logout_redirect_uris=["http://localhost:3002/"],
                    allowed_scopes=["openid", "email"],
                    is_first_party=False,
                    is_active=True,
                )
                session.add_all([client1, client2])
                await session.flush()

                now = datetime.now(UTC)
                # Create active refresh tokens for both clients
                t1 = await _mint_pair(
                    session,
                    settings,
                    user=user,
                    client=client1,
                    scope="openid email offline_access",
                    nonce=None,
                    auth_time=now,
                    amr=["pwd"],
                    family_id=uuid.uuid4(),
                    family_expires_at=now + timedelta(days=30),
                    parent_id=None,
                )
                t2 = await _mint_pair(
                    session,
                    settings,
                    user=user,
                    client=client2,
                    scope="openid email offline_access",
                    nonce=None,
                    auth_time=now,
                    amr=["pwd"],
                    family_id=uuid.uuid4(),
                    family_expires_at=now + timedelta(days=30),
                    parent_id=None,
                )

                # Create session cookie for user
                raw_sess = random_token(32)
                sess_row = AuthSession(
                    session_token_hash=hash_token(settings.token_hash_pepper, raw_sess),
                    user_id=user.id,
                    auth_time=now,
                    amr=["pwd"],
                    idle_expires_at=now + timedelta(hours=12),
                    absolute_expires_at=now + timedelta(days=7),
                )
                session.add(sess_row)
                await session.commit()
                return user, client1, client2, t1, t2, raw_sess

        user, client1, client2, t1, t2, raw_sess = http_client.portal.call(setup_data)

        http_client.cookies.set(settings.cookie_name, raw_sess)

        # 1. View /account?tab=apps
        resp = http_client.get("/account?tab=apps")
        assert resp.status_code == 200
        assert "CONNECTED APPLICATIONS" in resp.text
        assert "App One" in resp.text
        assert "App Two" in resp.text

        # Extract CSRF token from page
        csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
        assert csrf_match, "CSRF token not found"
        csrf = csrf_match.group(1)

        # 2. Revoke App One
        revoke_resp = http_client.post(
            "/account/clients/revoke",
            data={"client_id": client1.client_id, "csrf_token": csrf},
            follow_redirects=False,
        )
        assert revoke_resp.status_code == 303
        assert "tab=apps" in revoke_resp.headers["location"]

        async def verify_revocation():
            import src.core.db as db_mod
            async with db_mod.SessionLocal() as s:
                with pytest.raises(TokenError) as exc_info:
                    await rotate_refresh(
                        s,
                        settings,
                        client=client1,
                        refresh_token=t1["refresh_token"],
                    )
                assert exc_info.value.error == "invalid_grant"

                # App Two should still be active
                rot2 = await rotate_refresh(
                    s,
                    settings,
                    client=client2,
                    refresh_token=t2["refresh_token"],
                )
                assert "refresh_token" in rot2
                return rot2

        rot2 = http_client.portal.call(verify_revocation)

        # 3. Revoke All Applications
        revoke_all_resp = http_client.post(
            "/account/clients/revoke",
            data={"revoke_all": "1", "csrf_token": csrf},
            follow_redirects=False,
        )
        assert revoke_all_resp.status_code == 303

        async def verify_all_revocation():
            import src.core.db as db_mod
            async with db_mod.SessionLocal() as s:
                with pytest.raises(TokenError) as exc_info:
                    await rotate_refresh(
                        s,
                        settings,
                        client=client2,
                        refresh_token=rot2["refresh_token"],
                    )
                assert exc_info.value.error == "invalid_grant"

        http_client.portal.call(verify_all_revocation)
