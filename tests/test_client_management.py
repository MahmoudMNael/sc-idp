import html
import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from src.core.crypto import hash_password, hash_token, pkce_s256, random_token
from src.core.settings import get_settings
from src.main import app
from src.models import AuthSession, IdpRole, OAuthClient, User, UserIdpRole
from src.services.roles import RoleName, assign_role_to_user, ensure_role_exists
from src.services.sessions import create_session


def _extract_csrf(html_text: str) -> str:
    m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html_text)
    if not m:
        m = re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']', html_text)
    return m.group(1) if m else ""


@pytest.fixture
def admin_setup():
    settings = get_settings()

    async def _setup():
        import src.core.db as db_mod

        async with db_mod.SessionLocal() as session:
            await ensure_role_exists(session, RoleName.ADMIN)

            # Create admin user
            admin_user = User(
                email=f"admin-{uuid.uuid4().hex[:8]}@example.com",
                password_hash=hash_password(settings, "AdminPassword123!"),
                first_name="Admin",
                last_name="Super",
                email_verified=True,
                is_active=True,
            )
            session.add(admin_user)
            await session.flush()

            await assign_role_to_user(session, admin_user.id, RoleName.ADMIN)

            # Create session for admin
            raw_session = await create_session(
                session, settings, admin_user, ["pwd"], ip="127.0.0.1", user_agent="test-agent"
            )
            await session.commit()
            return admin_user, raw_session

    return _setup


def test_dashboard_register_client_with_offline_access(admin_setup):
    settings = get_settings()

    with TestClient(app) as client:
        admin_user, raw_sess = client.portal.call(admin_setup)
        client.cookies.set(settings.cookie_name, raw_sess)

        # 1. GET Dashboard - verify offline_access checkbox and edit modal warning exist
        dashboard_resp = client.get("/admin/dashboard")
        assert dashboard_resp.status_code == 200
        assert 'value="offline_access"' in dashboard_resp.text
        assert "This edit may break your implementation" in dashboard_resp.text
        csrf = _extract_csrf(dashboard_resp.text)
        assert csrf

        # 2. Register client WITH offline_access
        client_name = f"Offline App {uuid.uuid4().hex[:6]}"
        reg_resp = client.post(
            "/admin/dashboard/clients",
            data={
                "name": client_name,
                "redirect_uris": "http://app.test/callback\nhttp://localhost:4000/callback",
                "post_logout_redirect_uris": "http://app.test/\nhttp://localhost:4000/",
                "scopes": ["openid", "email", "profile", "offline_access"],
                "is_first_party": "true",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert reg_resp.status_code == 200
        assert f"Client '{client_name}' registered successfully." in html.unescape(reg_resp.text)

        # Verify DB
        async def verify_db():
            import src.core.db as db_mod

            async with db_mod.SessionLocal() as session:
                row = (
                    await session.execute(
                        select(OAuthClient).where(OAuthClient.name == client_name)
                    )
                ).scalar_one_or_none()
                assert row is not None
                assert "offline_access" in row.allowed_scopes
                assert "openid" in row.allowed_scopes
                assert "email" in row.allowed_scopes
                assert "profile" in row.allowed_scopes
                assert "http://app.test/callback" in row.redirect_uris
                assert "http://localhost:4000/callback" in row.redirect_uris
                assert row.is_first_party is True
                return row.client_id

        cid = client.portal.call(verify_db)
        assert cid


def test_dashboard_register_client_without_offline_access(admin_setup):
    settings = get_settings()

    with TestClient(app) as client:
        admin_user, raw_sess = client.portal.call(admin_setup)
        client.cookies.set(settings.cookie_name, raw_sess)

        dashboard_resp = client.get("/admin/dashboard")
        assert dashboard_resp.status_code == 200
        csrf = _extract_csrf(dashboard_resp.text)

        # Register client WITHOUT offline_access
        client_name = f"Standard App {uuid.uuid4().hex[:6]}"
        reg_resp = client.post(
            "/admin/dashboard/clients",
            data={
                "name": client_name,
                "redirect_uris": "http://standard.test/callback",
                "post_logout_redirect_uris": "http://standard.test/logout",
                "scopes": ["openid", "email"],
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert reg_resp.status_code == 200
        assert f"Client '{client_name}' registered successfully." in html.unescape(reg_resp.text)

        async def verify_db():
            import src.core.db as db_mod

            async with db_mod.SessionLocal() as session:
                row = (
                    await session.execute(
                        select(OAuthClient).where(OAuthClient.name == client_name)
                    )
                ).scalar_one_or_none()
                assert row is not None
                assert "offline_access" not in row.allowed_scopes
                assert set(row.allowed_scopes) == {"openid", "email"}
                assert row.is_first_party is False

        client.portal.call(verify_db)


def test_dashboard_edit_client(admin_setup):
    settings = get_settings()

    with TestClient(app) as client:
        admin_user, raw_sess = client.portal.call(admin_setup)
        client.cookies.set(settings.cookie_name, raw_sess)

        # First, create a client in DB directly
        async def create_client():
            import src.core.db as db_mod

            async with db_mod.SessionLocal() as session:
                cid = f"test-edit-{uuid.uuid4().hex[:8]}"
                cl = OAuthClient(
                    client_id=cid,
                    name="Initial Name",
                    client_secret_hash=hash_token(settings.token_hash_pepper, "secret"),
                    redirect_uris=["http://initial.test/callback"],
                    post_logout_redirect_uris=["http://initial.test/"],
                    allowed_scopes=["openid", "email"],
                    is_first_party=True,
                    is_active=True,
                )
                session.add(cl)
                await session.commit()
                return cid

        cid = client.portal.call(create_client)

        # Check dashboard renders edit button with data attributes
        dashboard_resp = client.get("/admin/dashboard")
        assert dashboard_resp.status_code == 200
        assert f'data-client-id="{cid}"' in dashboard_resp.text
        assert 'data-name="Initial Name"' in dashboard_resp.text
        assert "openEditClientModal" in dashboard_resp.text
        csrf = _extract_csrf(dashboard_resp.text)

        # 1. Edit client: change name, redirect_uris, post_logout_uris, add offline_access and profile
        edit_resp = client.post(
            f"/admin/dashboard/clients/{cid}/edit",
            data={
                "name": "Updated Client Name",
                "redirect_uris": "http://updated.test/cb1\nhttp://updated.test/cb2",
                "post_logout_redirect_uris": "http://updated.test/out1\nhttp://updated.test/out2",
                "scopes": ["openid", "email", "profile", "offline_access"],
                "is_first_party": "false",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert edit_resp.status_code == 200
        assert "Client 'Updated Client Name' updated successfully." in html.unescape(edit_resp.text)

        # Verify DB changes
        async def verify_edit():
            import src.core.db as db_mod

            async with db_mod.SessionLocal() as session:
                row = await session.get(OAuthClient, cid)
                assert row is not None
                assert row.name == "Updated Client Name"
                assert row.redirect_uris == ["http://updated.test/cb1", "http://updated.test/cb2"]
                assert row.post_logout_redirect_uris == ["http://updated.test/out1", "http://updated.test/out2"]
                assert set(row.allowed_scopes) == {"openid", "email", "profile", "offline_access"}
                assert row.is_first_party is False

        client.portal.call(verify_edit)

        # 2. Validation: empty redirect_uris should fail
        csrf = _extract_csrf(edit_resp.text)
        fail_resp = client.post(
            f"/admin/dashboard/clients/{cid}/edit",
            data={
                "name": "Another Name",
                "redirect_uris": "   \n  ",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert fail_resp.status_code == 400
        assert "At least one valid redirect URI is required." in fail_resp.text

        # 3. Non-existent client should 404
        csrf = _extract_csrf(fail_resp.text)
        not_found_resp = client.post(
            "/admin/dashboard/clients/non-existent-cid/edit",
            data={
                "name": "Whatever",
                "redirect_uris": "http://valid.test/cb",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        assert not_found_resp.status_code == 404
        assert "Client not found." in not_found_resp.text


def test_api_client_update_and_scope_enforcement():
    settings = get_settings()
    admin_auth = {"Authorization": f"Bearer {settings.idp_admin_api_key}"}

    with TestClient(app) as client:
        # 1. Register a client via API without offline_access
        create_resp = client.post(
            "/admin/clients",
            headers=admin_auth,
            json={
                "name": "API Client",
                "redirect_uris": ["http://api.test/callback"],
                "post_logout_redirect_uris": ["http://api.test/"],
                "allowed_scopes": ["openid", "email"],
                "is_first_party": True,
            },
        )
        assert create_resp.status_code == 200
        created = create_resp.json()
        cid = created["client_id"]

        # 2. GET client via API
        get_resp = client.get(f"/admin/clients/{cid}", headers=admin_auth)
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["name"] == "API Client"
        assert data["allowed_scopes"] == ["openid", "email"]

        # 3. Authorize with scope 'offline_access' should fail (invalid_scope) because not allowed
        verifier = random_token(32)
        challenge = pkce_s256(verifier)
        auth_fail = client.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": "http://api.test/callback",
                "response_type": "code",
                "scope": "openid email offline_access",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "st",
            },
            follow_redirects=False,
        )
        assert auth_fail.status_code == 302
        loc = auth_fail.headers["location"]
        assert "error=invalid_scope" in loc

        # 4. Update client via API to allow offline_access and edit redirect_uris
        update_resp = client.put(
            f"/admin/clients/{cid}",
            headers=admin_auth,
            json={
                "name": "API Client With Offline Access",
                "redirect_uris": ["http://api.test/callback", "http://api.test/new_callback"],
                "post_logout_redirect_uris": ["http://api.test/logout"],
                "allowed_scopes": ["openid", "email", "offline_access"],
            },
        )
        assert update_resp.status_code == 200
        updated = update_resp.json()
        assert updated["name"] == "API Client With Offline Access"
        assert "offline_access" in updated["allowed_scopes"]
        assert len(updated["redirect_uris"]) == 2

        # 5. Now authorize with 'offline_access' should not fail with invalid_scope
        auth_ok = client.get(
            "/authorize",
            params={
                "client_id": cid,
                "redirect_uri": "http://api.test/new_callback",
                "response_type": "code",
                "scope": "openid email offline_access",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "st",
            },
            follow_redirects=False,
        )
        # Should redirect to login (not error=invalid_scope)
        assert auth_ok.status_code in (302, 303)
        assert "error=invalid_scope" not in auth_ok.headers["location"]
        assert "/login" in auth_ok.headers["location"]

        # 6. Discovery check: offline_access is in scopes_supported
        disc = client.get("/.well-known/openid-configuration").json()
        assert "offline_access" in disc["scopes_supported"]
