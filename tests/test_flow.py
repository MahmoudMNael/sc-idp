"""
End-to-end IdP check. No fixture pyramid.

Requires DATABASE_URL (and the other IdP secrets). Copy .env.example to .env and fill it,
or export the variables. This process forces IDP_ISSUER=http://testserver and COOKIE_SECURE=false.

Run: python tests/test_flow.py
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except Exception:
    pass

if not os.environ.get("DATABASE_URL"):
    sys.exit(
        "DATABASE_URL is required. Copy .env.example to .env, fill every variable, then re-run."
    )

for name in ("SECRET_KEY", "TOKEN_HASH_PEPPER", "KEY_ENCRYPTION_KEY", "IDP_ADMIN_API_KEY"):
    os.environ.setdefault(name, secrets.token_urlsafe(32))

os.environ["IDP_ISSUER"] = "http://testserver"
os.environ["COOKIE_SECURE"] = "false"
os.environ["MAIL_BACKEND"] = "console"
os.environ["RATE_LIMIT_REGISTER"] = "30"
os.environ["RATE_LIMIT_LOGIN"] = "60"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def csrf_token(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, html[:500]
    return m.group(1)


def basic(cid: str, secret: str) -> dict[str, str]:
    token = base64.b64encode(f"{cid}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def main() -> None:
    import asyncio

    from fastapi.testclient import TestClient
    from joserfc import jwt
    from joserfc.jwk import KeySet, RSAKey
    from sqlalchemy.ext.asyncio import create_async_engine

    from src.models import Base
    from src.core.settings import get_settings
    from src.services.tokens import mint_idp_jwt

    os.environ["MAIL_BACKEND"] = "console"
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.mail_backend == "console", "Email service must be in console mode for tests"

    from sqlalchemy.pool import NullPool
    from sqlalchemy.ext.asyncio import async_sessionmaker
    import src.core.db as db_mod
    from src.core.deps import get_db

    async def ensure_schema() -> None:
        engine = create_async_engine(settings.sqlalchemy_url, poolclass=NullPool)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(ensure_schema())

    engine = create_async_engine(settings.sqlalchemy_url, poolclass=NullPool)
    from src.main import app

    email = f"user-{secrets.token_hex(4)}@example.test"
    password = "correct-horse-battery"

    from contextlib import contextmanager

    @contextmanager
    def db_transaction_rollback(client, engine, settings):
        async def setup_tx():
            conn = await engine.connect()
            trans = await conn.begin()
            sm = async_sessionmaker(bind=conn, expire_on_commit=False, join_transaction_mode="create_savepoint")

            async def override_get_db():
                async with sm() as s:
                    yield s
                    await s.commit()

            app.dependency_overrides[get_db] = override_get_db
            db_mod.SessionLocal = sm
            async with sm() as s:
                from src.core.keys import ensure_active_key
                from src.services.bootstrap import bootstrap_demo_clients
                await ensure_active_key(s, settings)
                await bootstrap_demo_clients(s, settings)
                await s.commit()
            return conn, trans, sm

        conn, trans, sm = client.portal.call(setup_tx)
        try:
            yield sm
        finally:
            async def teardown_tx():
                await trans.rollback()
                await conn.close()
            client.portal.call(teardown_tx)
            app.dependency_overrides.pop(get_db, None)

    with TestClient(app, base_url="http://testserver") as c, db_transaction_rollback(c, engine, settings) as sm:
        async def age_tokens(user_email: str, seconds: int = 40) -> None:
            from datetime import UTC, datetime, timedelta
            from sqlalchemy import select, update
            from src.models import EmailToken, User
            async with sm() as s:
                await s.execute(
                    update(EmailToken)
                    .where(EmailToken.user_id == (
                        select(User.id).where(User.email == user_email).scalar_subquery()
                    ))
                    .values(created_at=datetime.now(UTC) - timedelta(seconds=seconds))
                )
                await s.commit()

        h = c.get("/healthz")
        assert h.status_code == 200, h.text

        disc_resp = c.get("/.well-known/openid-configuration")
        assert disc_resp.status_code == 200
        assert disc_resp.headers["access-control-allow-origin"] == "*"
        assert "public, max-age=" in disc_resp.headers["cache-control"]
        disc = disc_resp.json()
        assert disc["issuer"] == settings.public_base
        assert disc["jwks_uri"] == f"{settings.public_base}/.well-known/jwks.json"
        assert disc["authorization_endpoint"] == f"{settings.public_base}/authorize"
        assert disc["token_endpoint"] == f"{settings.public_base}/token"
        assert disc["userinfo_endpoint"] == f"{settings.public_base}/userinfo"
        assert disc["end_session_endpoint"] == f"{settings.public_base}/logout"
        assert disc["response_types_supported"] == ["code"]
        assert disc["response_modes_supported"] == ["query"]
        assert disc["code_challenge_methods_supported"] == ["S256"]
        assert disc["id_token_signing_alg_values_supported"] == ["RS256"]
        assert "idp_roles" in disc["scopes_supported"]
        assert "profile" in disc["scopes_supported"]
        assert "idp_roles" in disc["claims_supported"]
        assert "given_name" in disc["claims_supported"]
        assert "family_name" in disc["claims_supported"]
        assert "name" in disc["claims_supported"]
        assert "at_hash" in disc["claims_supported"]

        # RFC 8414 OAuth authorization server metadata alias
        rfc8414_disc = c.get("/.well-known/oauth-authorization-server")
        assert rfc8414_disc.status_code == 200
        assert rfc8414_disc.json() == disc

        # JWKS headers and alias check
        jwks_resp = c.get("/.well-known/jwks.json")
        assert jwks_resp.status_code == 200
        assert jwks_resp.headers["access-control-allow-origin"] == "*"
        assert "public, max-age=" in jwks_resp.headers["cache-control"]
        jwks_data = jwks_resp.json()
        assert "keys" in jwks_data and len(jwks_data["keys"]) >= 1
        k0 = jwks_data["keys"][0]
        assert k0["kty"] == "RSA"
        assert k0["use"] == "sig"
        assert k0["alg"] == "RS256"
        assert "n" in k0 and "e" in k0 and "kid" in k0

        # /.well-known/jwks alias returns same keys
        jwks_alias = c.get("/.well-known/jwks")
        assert jwks_alias.status_code == 200
        assert jwks_alias.json() == jwks_data

        # 1. forbidden claims never mint
        key = RSAKey.generate_key(2048, private=True, parameters={"kid": "t", "alg": "RS256", "use": "sig"})
        try:
            mint_idp_jwt({"iss": settings.public_base, "sub": "u", "role": "admin"}, key)
            raise AssertionError("allowlist did not reject role")
        except ValueError as exc:
            assert "forbidden" in str(exc)

        admin = {"Authorization": f"Bearer {settings.idp_admin_api_key}"}
        a = c.post(
            "/admin/clients",
            headers=admin,
            json={
                "name": "A",
                "redirect_uris": ["http://appa.test/callback"],
                "post_logout_redirect_uris": ["http://appa.test/"],
                "is_first_party": True,
            },
        )
        assert a.status_code == 200, a.text
        client_a = a.json()
        b = c.post(
            "/admin/clients",
            headers=admin,
            json={
                "name": "B",
                "redirect_uris": ["http://appb.test/callback"],
                "is_first_party": True,
            },
        )
        assert b.status_code == 200, b.text
        client_b = b.json()

        evil = c.get(
            "/authorize",
            params={
                "client_id": "missing",
                "redirect_uri": "http://evil.test/cb",
                "response_type": "code",
            },
            follow_redirects=False,
        )
        assert evil.status_code == 400
        assert "evil.test" not in (evil.headers.get("location") or "")

        sent_emails = []
        import src.services.mail as mail_mod
        orig_send_mail = mail_mod.send_mail

        def fake_send_mail(settings, to, subject, body, html=None, *args, **kwargs):
            sent_emails.append({"to": to, "subject": subject, "body": body, "html": html})
            orig_send_mail(settings, to, subject, body, html=html, *args, **kwargs)

        mail_mod.send_mail = fake_send_mail
        import src.routers.accounts as accounts_mod
        accounts_mod.send_mail = fake_send_mail
        import src.routers.authorize as authorize_mod
        authorize_mod.send_mail = fake_send_mail

        reg = c.get("/register")
        assert "password-toggle-btn" in reg.text
        assert 'aria-label="Show password"' in reg.text

        bad_reg = c.post(
            "/register",
            data={"email": email, "password": password, "csrf_token": csrf_token(reg.text)},
            follow_redirects=False,
        )
        assert bad_reg.status_code == 400
        assert "first name and last name are required" in bad_reg.text.lower()

        r = c.post(
            "/register",
            data={
                "first_name": "Test",
                "last_name": "User",
                "email": email,
                "password": password,
                "csrf_token": csrf_token(bad_reg.text),
            },
            follow_redirects=False,
        )
        assert r.status_code == 303, r.text
        assert "/verify-email" in r.headers["location"]

        # unverified user blocked at login; verify login page also has password toggle
        login_get = c.get("/login")
        assert "password-toggle-btn" in login_get.text

        bad_login = c.post(
            "/login",
            data={"email": email, "password": password, "csrf_token": csrf_token(login_get.text)},
            follow_redirects=False,
        )
        assert bad_login.status_code == 403, bad_login.text
        assert "verify your email" in bad_login.text.lower()

        # extract OTP and test verification
        assert sent_emails, "No email sent"
        reg_mail = [m for m in sent_emails if m["subject"] == "Verify your email"][-1]
        otp_m = re.search(r"code is:\s*([0-9]{6})", reg_mail["body"])
        assert otp_m, reg_mail["body"]
        assert "expires in 5 minutes" in reg_mail["body"].lower()
        assert reg_mail.get("html"), "HTML body missing in register OTP"
        assert "/logo-light.png" in reg_mail["html"]
        assert "Verify your email" in reg_mail["html"]
        assert "Expires in 5 minutes" in reg_mail["html"]
        otp = otp_m.group(1)

        # wrong OTP
        verify_page = c.get(r.headers["location"])
        bad_otp = c.post(
            "/verify-email",
            data={"email": email, "code": "000000", "csrf_token": csrf_token(verify_page.text)},
            follow_redirects=False,
        )
        assert bad_otp.status_code == 400
        assert "Invalid or expired" in bad_otp.text

        # valid OTP
        good_otp = c.post(
            "/verify-email",
            data={"email": email, "code": otp, "csrf_token": csrf_token(bad_otp.text)},
            follow_redirects=False,
        )
        assert good_otp.status_code == 303
        welcome_mails = [m for m in sent_emails if m["subject"] == "Welcome to Short Circuit — Account Created"]
        assert welcome_mails, "Account created welcome email not sent"
        assert welcome_mails[-1].get("html"), "HTML body missing in account created email"
        assert "Welcome to Short Circuit" in welcome_mails[-1]["html"]
        assert "/logo-light.png" in welcome_mails[-1]["html"]

        # duplicate registration for already verified user returns 400
        dup_verified = c.post(
            "/register",
            data={
                "first_name": "Test",
                "last_name": "User",
                "email": email,
                "password": password,
                "csrf_token": csrf_token(c.get("/register").text),
            },
            follow_redirects=False,
        )
        assert dup_verified.status_code == 400
        assert "Could not create that account" in dup_verified.text
        c.get("/logout", follow_redirects=False)

        def login_and_code(
            client_id: str,
            redirect: str,
            prompt: str | None = None,
            login_email: str | None = None,
            login_password: str | None = None,
            scope: str = "openid email",
        ) -> tuple[str, str]:
            verifier, challenge = pkce()
            params = {
                "client_id": client_id,
                "redirect_uri": redirect,
                "response_type": "code",
                "scope": scope,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "st",
                "nonce": "n1",
            }
            if prompt:
                params["prompt"] = prompt
            az = c.get("/authorize", params=params, follow_redirects=False)
            while az.status_code in (302, 303) and urlparse(az.headers["location"]).path == "/login":
                loc = az.headers["location"]
                login_page = c.get(loc, follow_redirects=False)
                nxt = parse_qs(urlparse(loc).query).get("next", [""])[0]
                posted = c.post(
                    "/login",
                    data={
                        "email": login_email or email,
                        "password": login_password or password,
                        "csrf_token": csrf_token(login_page.text),
                        "next": nxt,
                    },
                    follow_redirects=False,
                )
                assert posted.status_code == 303, posted.text
                az = c.get(posted.headers["location"], follow_redirects=False)
            assert az.status_code == 302, az.text[:500]
            loc = az.headers["location"]
            assert loc.startswith(redirect), loc
            code = parse_qs(urlparse(loc).query)["code"][0]
            return code, verifier

        code, verifier = login_and_code(client_a["client_id"], "http://appa.test/callback")
        tok = c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://appa.test/callback",
                "code_verifier": verifier,
            },
            headers=basic(client_a["client_id"], client_a["client_secret"]),
        )
        assert tok.status_code == 200, tok.text
        body = tok.json()
        jwks = c.get("/.well-known/jwks.json").json()
        id_claims = jwt.decode(body["id_token"], KeySet.import_key_set(jwks)).claims
        assert id_claims["sub"]
        assert id_claims["email"] == email
        assert "role" not in id_claims
        assert "roles" not in id_claims
        at_claims = jwt.decode(body["access_token"], KeySet.import_key_set(jwks)).claims
        assert at_claims["typ"] == "at+jwt"

        me = c.get("/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"})
        assert me.status_code == 200, me.text
        assert me.json()["email"] == email

        # 2. auth code replay
        replay = c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://appa.test/callback",
                "code_verifier": verifier,
            },
            headers=basic(client_a["client_id"], client_a["client_secret"]),
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"

        family_dead = c.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": body["refresh_token"]},
            headers=basic(client_a["client_id"], client_a["client_secret"]),
        )
        assert family_dead.status_code == 400, family_dead.text

        # fresh tokens for refresh-reuse
        code2, ver2 = login_and_code(client_a["client_id"], "http://appa.test/callback")
        first = c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code2,
                "redirect_uri": "http://appa.test/callback",
                "code_verifier": ver2,
            },
            headers=basic(client_a["client_id"], client_a["client_secret"]),
        ).json()
        rotated = c.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
            headers=basic(client_a["client_id"], client_a["client_secret"]),
        )
        assert rotated.status_code == 200, rotated.text
        new_rt = rotated.json()["refresh_token"]

        # 3. reuse of the parent revokes the family, including the child
        reuse = c.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": first["refresh_token"]},
            headers=basic(client_a["client_id"], client_a["client_secret"]),
        )
        assert reuse.status_code == 400
        child = c.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": new_rt},
            headers=basic(client_a["client_id"], client_a["client_secret"]),
        )
        assert child.status_code == 400, child.text

        # 4. silent SSO: same browser session, second client, no login form
        verifier_b, challenge_b = pkce()
        az_b = c.get(
            "/authorize",
            params={
                "client_id": client_b["client_id"],
                "redirect_uri": "http://appb.test/callback",
                "response_type": "code",
                "scope": "openid email",
                "code_challenge": challenge_b,
                "code_challenge_method": "S256",
                "state": "stb",
            },
            follow_redirects=False,
        )
        assert az_b.status_code == 302, az_b.text[:400]
        loc_b = az_b.headers["location"]
        assert loc_b.startswith("http://appb.test/callback"), loc_b
        assert "code=" in loc_b
        none = c.get(
            "/authorize",
            params={
                "client_id": client_b["client_id"],
                "redirect_uri": "http://appb.test/callback",
                "response_type": "code",
                "scope": "openid",
                "code_challenge": challenge_b,
                "code_challenge_method": "S256",
                "prompt": "none",
            },
            follow_redirects=False,
        )
        assert none.status_code == 302
        assert "code=" in none.headers["location"]

        wrong = c.get("/login")
        bad = c.post(
            "/login",
            data={
                "email": email,
                "password": "wrong-password-not-it",
                "csrf_token": csrf_token(wrong.text),
                "next": "",
            },
            follow_redirects=False,
        )
        unknown = c.post(
            "/login",
            data={
                "email": "nobody@example.test",
                "password": "wrong-password-not-it",
                "csrf_token": csrf_token(c.get("/login").text),
                "next": "",
            },
            follow_redirects=False,
        )
        assert "Invalid email or password" in bad.text
        assert "Invalid email or password" in unknown.text

        acc = c.get("/account/mfa")
        setup = c.post(
            "/account/mfa/setup",
            data={"csrf_token": csrf_token(acc.text)},
            follow_redirects=True,
        )
        secret_m = re.search(r"secret=([A-Z2-7]+)", setup.text)
        assert secret_m, setup.text[:500]
        assert "Short%20Circuit" in setup.text or "Short Circuit" in setup.text
        assert "mfa-qrcode" in setup.text
        import pyotp

        totp_secret = secret_m.group(1)
        enabled = c.post(
            "/account/mfa/enable",
            data={"csrf_token": csrf_token(setup.text), "code": pyotp.TOTP(totp_secret).now()},
            follow_redirects=True,
        )
        assert "Store these recovery codes" in enabled.text

        c.get("/logout", follow_redirects=False)
        verifier_m, challenge_m = pkce()
        params_m = {
            "client_id": client_a["client_id"],
            "redirect_uri": "http://appa.test/callback",
            "response_type": "code",
            "scope": "openid email",
            "code_challenge": challenge_m,
            "code_challenge_method": "S256",
            "state": "mfa",
        }
        az_m = c.get("/authorize", params=params_m, follow_redirects=False)
        assert az_m.status_code == 302
        login_loc = az_m.headers["location"]
        login_page = c.get(login_loc, follow_redirects=False)
        nxt = parse_qs(urlparse(login_loc).query).get("next", [""])[0]
        posted = c.post(
            "/login",
            data={
                "email": email,
                "password": password,
                "csrf_token": csrf_token(login_page.text),
                "next": nxt,
            },
            follow_redirects=False,
        )
        assert posted.status_code == 303
        assert "/login/mfa" in posted.headers["location"]
        step_up = c.get("/authorize", params=params_m, follow_redirects=False)
        assert step_up.status_code == 302
        assert "/login/mfa" in step_up.headers["location"]
        mfa_page = c.get(posted.headers["location"], follow_redirects=False)
        done = c.post(
            "/login/mfa",
            data={
                "code": pyotp.TOTP(totp_secret).now(),
                "csrf_token": csrf_token(mfa_page.text),
                "next": nxt,
            },
            follow_redirects=False,
        )
        assert done.status_code == 303
        az_done = c.get(done.headers["location"], follow_redirects=False)
        assert az_done.status_code == 302
        assert az_done.headers["location"].startswith("http://appa.test/callback")

        c.get("/logout", follow_redirects=False)
        silent = c.get(
            "/authorize",
            params={
                "client_id": client_b["client_id"],
                "redirect_uri": "http://appb.test/callback",
                "response_type": "code",
                "scope": "openid",
                "code_challenge": challenge_b,
                "code_challenge_method": "S256",
                "prompt": "none",
            },
            follow_redirects=False,
        )
        assert silent.status_code == 302
        assert "login_required" in silent.headers["location"]

        # forgot password 2-step OTP flow
        forgot_page = c.get("/forgot-password")
        bad_forgot = c.post(
            "/forgot-password",
            data={"email": "nobody-exists@example.com", "csrf_token": csrf_token(forgot_page.text)},
            follow_redirects=False,
        )
        assert bad_forgot.status_code == 400
        assert "No active account found with this email." in bad_forgot.text

        f = c.post(
            "/forgot-password",
            data={"email": email, "csrf_token": csrf_token(bad_forgot.text)},
            follow_redirects=False,
        )
        assert f.status_code == 303
        assert "/reset-password/verify" in f.headers["location"]

        reset_mail = [m for m in sent_emails if m["subject"] == "Reset your password"][-1]
        reset_m = re.search(r"code is:\s*([0-9]{6})", reset_mail["body"])
        assert reset_m, reset_mail["body"]
        assert "expires in 5 minutes" in reset_mail["body"].lower()
        assert reset_mail.get("html"), "HTML body missing in password reset email"
        assert "Reset your password" in reset_mail["html"]
        assert "Expires in 5 minutes" in reset_mail["html"]
        assert "/logo-light.png" in reset_mail["html"]
        reset_otp = reset_m.group(1)

        reset_verify_page = c.get(f.headers["location"])
        assert "disabled" in reset_verify_page.text
        assert "Resend code in " in reset_verify_page.text

        # early reset resend blocked by 30s cooldown
        early_reset_resend = c.post(
            "/reset-password/resend",
            data={"email": email, "csrf_token": csrf_token(reset_verify_page.text)},
            follow_redirects=False,
        )
        assert early_reset_resend.status_code == 429
        assert "Please wait" in early_reset_resend.text

        # age tokens to simulate cooldown expiring
        c.portal.call(age_tokens, email, 40)

        good_reset_resend = c.post(
            "/reset-password/resend",
            data={"email": email, "csrf_token": csrf_token(early_reset_resend.text)},
            follow_redirects=False,
        )
        assert good_reset_resend.status_code == 200
        assert "A new reset code has been sent." in good_reset_resend.text
        reset_m = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"])
        assert reset_m
        reset_otp = reset_m.group(1)

        # wrong reset OTP
        bad_reset_otp = c.post(
            "/reset-password/verify",
            data={"email": email, "code": "000000", "csrf_token": csrf_token(good_reset_resend.text)},
            follow_redirects=False,
        )
        assert bad_reset_otp.status_code == 400

        # valid reset OTP -> redirects to step 2 with ticket
        good_reset_otp = c.post(
            "/reset-password/verify",
            data={"email": email, "code": reset_otp, "csrf_token": csrf_token(bad_reset_otp.text)},
            follow_redirects=False,
        )
        assert good_reset_otp.status_code == 303
        assert "/reset-password?ticket=" in good_reset_otp.headers["location"]
        ticket = parse_qs(urlparse(good_reset_otp.headers["location"]).query)["ticket"][0]

        # step 2: set new password
        reset_page = c.get(good_reset_otp.headers["location"])
        assert "password-toggle-btn" in reset_page.text
        new_password = "new-correct-horse-battery"
        reset_done = c.post(
            "/reset-password",
            data={"ticket": ticket, "password": new_password, "csrf_token": csrf_token(reset_page.text)},
            follow_redirects=False,
        )
        assert reset_done.status_code == 303
        assert "/login" in reset_done.headers["location"]

        # sign in with new password
        new_login = c.post(
            "/login",
            data={"email": email, "password": new_password, "csrf_token": csrf_token(c.get("/login").text)},
            follow_redirects=False,
        )
        assert new_login.status_code == 303

        # OTP edge cases: resend, max attempt limit, and replay
        email2 = f"user2-{secrets.token_hex(4)}@example.test"
        reg2 = c.get("/register")
        r2 = c.post(
            "/register",
            data={
                "first_name": "User",
                "last_name": "Two",
                "email": email2,
                "password": password,
                "csrf_token": csrf_token(reg2.text),
            },
            follow_redirects=False,
        )
        assert r2.status_code == 303
        otp2_first = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"]).group(1)
        v2_page = c.get(r2.headers["location"])
        assert "disabled" in v2_page.text
        assert "Resend code in " in v2_page.text

        # test resend cooldown enforcement (early attempt blocked)
        early_resend = c.post(
            "/verify-email/resend",
            data={"email": email2, "csrf_token": csrf_token(v2_page.text)},
            follow_redirects=False,
        )
        assert early_resend.status_code == 429
        assert "Please wait" in early_resend.text

        # age tokens to simulate cooldown expiring
        c.portal.call(age_tokens, email2, 40)

        # test resend after cooldown expires
        resend_resp = c.post(
            "/verify-email/resend",
            data={"email": email2, "csrf_token": csrf_token(early_resend.text)},
            follow_redirects=False,
        )
        assert resend_resp.status_code == 200
        assert "A new verification code has been sent." in resend_resp.text
        otp2_m = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"])
        assert otp2_m
        otp2 = otp2_m.group(1)

        # previous OTP code for email2 is now invalidated
        bad_prev_otp = c.post(
            "/verify-email",
            data={"email": email2, "code": otp2_first, "csrf_token": csrf_token(resend_resp.text)},
            follow_redirects=False,
        )
        assert bad_prev_otp.status_code == 400
        assert "Invalid or expired" in bad_prev_otp.text

        # test max attempts (settings.otp_max_attempts invalid tries allowed, next triggers 429)
        curr_page = bad_prev_otp
        for _ in range(settings.otp_max_attempts - 1):
            curr_page = c.post(
                "/verify-email",
                data={"email": email2, "code": "000000", "csrf_token": csrf_token(curr_page.text)},
                follow_redirects=False,
            )
            assert curr_page.status_code == 400

        # next attempt is rate-limited
        curr_page = c.post(
            "/verify-email",
            data={"email": email2, "code": "000000", "csrf_token": csrf_token(curr_page.text)},
            follow_redirects=False,
        )
        assert curr_page.status_code == 429
        assert "Too many failed attempts" in curr_page.text

        # test replaying consumed OTP fails
        replay_resp = c.post(
            "/verify-email",
            data={"email": email, "code": otp, "csrf_token": csrf_token(c.get("/verify-email").text)},
            follow_redirects=False,
        )
        assert replay_resp.status_code == 400
        assert "Invalid or expired" in replay_resp.text

        # Test registering again with pending unverified email2 redirects to /verify-email and issues a new code
        r2_rereg = c.post(
            "/register",
            data={
                "first_name": "User",
                "last_name": "Two",
                "email": email2,
                "password": password,
                "csrf_token": csrf_token(c.get("/register").text),
            },
            follow_redirects=False,
        )
        assert r2_rereg.status_code == 303
        assert "/verify-email" in r2_rereg.headers["location"]
        otp2_rereg_m = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"])
        assert otp2_rereg_m
        otp2_rereg = otp2_rereg_m.group(1)
        assert otp2 != otp2_rereg

        # previous otp2 is now invalidated
        bad_rereg_otp = c.post(
            "/verify-email",
            data={"email": email2, "code": otp2, "csrf_token": csrf_token(c.get("/verify-email").text)},
            follow_redirects=False,
        )
        assert bad_rereg_otp.status_code == 400
        assert "Invalid or expired" in bad_rereg_otp.text

        # new otp2_rereg succeeds (and attempt limit was reset on new OTP issuance)
        good_rereg_otp = c.post(
            "/verify-email",
            data={"email": email2, "code": otp2_rereg, "csrf_token": csrf_token(bad_rereg_otp.text)},
            follow_redirects=False,
        )
        assert good_rereg_otp.status_code == 303

        # -------------------------------------------------------------
        # IdP Roles Foundation Tests
        # -------------------------------------------------------------
        # 1. create role
        r_create = c.post(
            "/admin/roles",
            headers=admin,
            json={"name": "admin", "description": "IdP Administrator"},
        )
        assert r_create.status_code == 200, r_create.text
        assert r_create.json()["name"] == "admin"

        # duplicate role returns 409
        dup_role = c.post(
            "/admin/roles",
            headers=admin,
            json={"name": "admin"},
        )
        assert dup_role.status_code == 409

        # list roles
        roles_list = c.get("/admin/roles", headers=admin).json()
        assert any(r["name"] == "admin" for r in roles_list)

        # 2. preassign role to unregistered email
        vip_email = f"vip-{secrets.token_hex(4)}@example.test"
        pre_resp = c.post(
            "/admin/roles/assign",
            headers=admin,
            json={"email": vip_email, "role": "admin"},
        )
        assert pre_resp.status_code == 200
        assert pre_resp.json()["preassigned"] is True

        assigns = c.get(f"/admin/roles/assignments?email={vip_email}", headers=admin).json()
        assert assigns["user_id"] is None
        assert assigns["user_roles"] == []
        assert assigns["preassigned_roles"] == ["admin"]

        # 3. register that email and verify OTP -> roles automatically assigned!
        vip_reg = c.get("/register")
        vip_r = c.post(
            "/register",
            data={
                "first_name": "Vip",
                "last_name": "User",
                "email": vip_email,
                "password": password,
                "csrf_token": csrf_token(vip_reg.text),
            },
            follow_redirects=False,
        )
        assert vip_r.status_code == 303
        vip_otp = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"]).group(1)
        vip_vpage = c.get(vip_r.headers["location"])
        vip_verify = c.post(
            "/verify-email",
            data={"email": vip_email, "code": vip_otp, "csrf_token": csrf_token(vip_vpage.text)},
            follow_redirects=False,
        )
        assert vip_verify.status_code == 303

        # check user now has the role
        vip_assigns = c.get(f"/admin/roles/assignments?email={vip_email}", headers=admin).json()
        assert vip_assigns["user_id"] is not None
        assert "admin" in vip_assigns["user_roles"]

        # 4. assign second role directly
        c.post(
            "/admin/roles",
            headers=admin,
            json={"name": "auditor", "description": "Auditor"},
        )
        c.post(
            "/admin/roles/assign",
            headers=admin,
            json={"email": vip_email, "role": "auditor"},
        )
        vip_assigns2 = c.get(f"/admin/roles/assignments?email={vip_email}", headers=admin).json()
        assert set(vip_assigns2["user_roles"]) == {"admin", "auditor"}

        # 5. unassign auditor
        c.post(
            "/admin/roles/unassign",
            headers=admin,
            json={"email": vip_email, "role": "auditor"},
        )
        vip_assigns3 = c.get(f"/admin/roles/assignments?email={vip_email}", headers=admin).json()
        assert vip_assigns3["user_roles"] == ["admin"]

        # 6. OIDC client requesting idp_roles scope
        client_roles_resp = c.post(
            "/admin/clients",
            headers=admin,
            json={
                "name": "RolesApp",
                "redirect_uris": ["http://rolesapp.test/callback"],
                "allowed_scopes": ["openid", "email", "idp_roles"],
                "is_first_party": True,
            },
        )
        assert client_roles_resp.status_code == 200
        client_roles = client_roles_resp.json()

        # perform code flow with client_roles and vip user
        code_r, verifier_r = login_and_code(
            client_roles["client_id"],
            "http://rolesapp.test/callback",
            login_email=vip_email,
            login_password=password,
            scope="openid email idp_roles",
        )
        tok_r = c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code_r,
                "redirect_uri": "http://rolesapp.test/callback",
                "code_verifier": verifier_r,
            },
            headers=basic(client_roles["client_id"], client_roles["client_secret"]),
        )
        assert tok_r.status_code == 200
        jwks_data = c.get("/.well-known/jwks.json").json()
        ks = KeySet.import_key_set(jwks_data)
        verified_id = jwt.decode(tok_r.json()["id_token"], ks).claims
        assert verified_id.get("idp_roles") == ["admin"]
        assert verified_id.get("roles") == ["admin"]

        verified_at = jwt.decode(tok_r.json()["access_token"], ks).claims
        assert verified_at.get("idp_roles") == ["admin"]
        assert verified_at.get("roles") == ["admin"]

        # userinfo includes idp_roles and roles
        u_info = c.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {tok_r.json()['access_token']}"},
        ).json()
        assert u_info.get("idp_roles") == ["admin"]
        assert u_info.get("roles") == ["admin"]

        # 7. test require_idp_role route guard dependency
        from fastapi import Depends
        from src.services.roles import require_idp_role

        @app.get("/_test_admin_only")
        async def _test_admin_only(user: User = Depends(require_idp_role("admin"))):
            return {"user": user.email}

        # login as vip (has admin role)
        c.get("/logout", follow_redirects=False)
        loc_vip = c.get("/login")
        c.post(
            "/login",
            data={
                "email": vip_email,
                "password": password,
                "csrf_token": csrf_token(loc_vip.text),
            },
            follow_redirects=False,
        )
        ok_route = c.get("/_test_admin_only")
        assert ok_route.status_code == 200
        assert ok_route.json()["user"] == vip_email

        # login as standard user (no admin role)
        c.get("/logout", follow_redirects=False)
        loc_user = c.get("/login")
        c.post(
            "/login",
            data={
                "email": email,
                "password": new_password,
                "csrf_token": csrf_token(loc_user.text),
            },
            follow_redirects=False,
        )
        forbidden_route = c.get("/_test_admin_only")
        assert forbidden_route.status_code == 403
        assert "insufficient idp roles" in forbidden_route.text

        # 8. test @shortcircuitcompany.com automatic sc_member assignment
        sc_email = f"alice-{secrets.token_hex(4)}@shortcircuitcompany.com"
        sc_reg = c.get("/register")
        sc_r = c.post(
            "/register",
            data={
                "first_name": "Alice",
                "last_name": "Smith",
                "email": sc_email,
                "password": password,
                "csrf_token": csrf_token(sc_reg.text),
            },
            follow_redirects=False,
        )
        assert sc_r.status_code == 303
        sc_otp = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"]).group(1)
        sc_vpage = c.get(sc_r.headers["location"])
        sc_verify = c.post(
            "/verify-email",
            data={"email": sc_email, "code": sc_otp, "csrf_token": csrf_token(sc_vpage.text)},
            follow_redirects=False,
        )
        assert sc_verify.status_code == 303

        sc_assigns = c.get(f"/admin/roles/assignments?email={sc_email}", headers=admin).json()
        assert "sc_member" in sc_assigns["user_roles"]

        # 9. test admin client registration dashboard
        # Static assets
        logo_resp = c.get("/assets/logo.png")
        assert logo_resp.status_code == 200
        favicon_resp = c.get("/assets/favicon.svg")
        assert favicon_resp.status_code == 200

        # Currently c is logged in as sc_email (non-admin). Access should return 403
        dash_forbidden = c.get("/admin/dashboard")
        assert dash_forbidden.status_code == 403
        assert "IdP admin role required" in dash_forbidden.text
        dash_users_forbidden = c.get("/admin/dashboard/users")
        assert dash_users_forbidden.status_code == 403
        assert "IdP admin role required" in dash_users_forbidden.text

        # Log out -> unauthenticated access to /admin/dashboard redirects to /login
        c.get("/logout", follow_redirects=False)
        dash_anon = c.get("/admin/dashboard", follow_redirects=False)
        assert dash_anon.status_code == 303
        assert "/login?next=/admin/dashboard" in dash_anon.headers["location"]
        dash_users_anon = c.get("/admin/dashboard/users", follow_redirects=False)
        assert dash_users_anon.status_code == 303
        assert "/login?next=/admin/dashboard" in dash_users_anon.headers["location"]

        # Admin access (vip_email) succeeds
        vip_login = c.post(
            "/login",
            data={"email": vip_email, "password": password, "csrf_token": csrf_token(c.get("/login").text)},
            follow_redirects=False,
        )
        assert vip_login.status_code == 303
        dash_ok = c.get("/admin/dashboard")
        assert dash_ok.status_code == 200
        assert "OAUTH CLIENTS" in dash_ok.text
        assert "REGISTER NEW CLIENT" in dash_ok.text

        # Register a new client
        new_client_name = "Payment Engine"
        reg_resp = c.post(
            "/admin/dashboard/clients",
            data={
                "name": new_client_name,
                "redirect_uris": "https://payments.internal/callback\nhttp://localhost:4000/callback",
                "post_logout_redirect_uris": "https://payments.internal/",
                "scopes": ["openid", "email"],
                "is_first_party": "true",
                "csrf_token": csrf_token(dash_ok.text),
            },
        )
        assert reg_resp.status_code == 200, f"Got {reg_resp.status_code}: {reg_resp.text}"
        assert "registered successfully" in reg_resp.text
        cid_match = re.search(r'id="revealed-cid"\s+readonly\s+value="([^"]+)"', reg_resp.text)
        secret_match = re.search(r'id="revealed-secret"\s+readonly\s+value="([^"]+)"', reg_resp.text)
        assert cid_match is not None and secret_match is not None
        new_cid = cid_match.group(1)
        new_secret = secret_match.group(1)

        # Rotate secret
        rotate_resp = c.post(
            f"/admin/dashboard/clients/{new_cid}/rotate-secret",
            data={"csrf_token": csrf_token(reg_resp.text)},
        )
        assert rotate_resp.status_code == 200
        assert "New secret generated" in rotate_resp.text
        rotated_secret = re.search(r'id="revealed-secret"\s+readonly\s+value="([^"]+)"', rotate_resp.text).group(1)
        assert rotated_secret != new_secret

        # Toggle status to inactive
        toggle_resp = c.post(
            f"/admin/dashboard/clients/{new_cid}/toggle-status",
            data={"csrf_token": csrf_token(rotate_resp.text)},
            follow_redirects=False,
        )
        assert toggle_resp.status_code == 303
        dash_after_toggle = c.get("/admin/dashboard")
        assert "INACTIVE" in dash_after_toggle.text

        # Toggle back to active
        toggle_back = c.post(
            f"/admin/dashboard/clients/{new_cid}/toggle-status",
            data={"csrf_token": csrf_token(dash_after_toggle.text)},
            follow_redirects=False,
        )
        assert toggle_back.status_code == 303

        # Test Admin Users Dashboard
        dash_clients = c.get("/admin/dashboard")
        assert 'href="/admin/dashboard/users"' in dash_clients.text

        users_page = c.get("/admin/dashboard/users")
        assert users_page.status_code == 200
        assert "USER ACCOUNTS" in users_page.text
        assert 'href="/admin/dashboard"' in users_page.text
        assert sc_email in users_page.text
        assert "sc_member" in users_page.text
        assert f"openResetModal('{sc_assigns['user_id']}', '{sc_email}')" in users_page.text

        sc_uid = sc_assigns["user_id"]
        normal_uid = c.get(f"/admin/roles/assignments?email={email}", headers=admin).json()["user_id"]

        # Attempt password reset on non-sc_member user -> 403
        bad_target_resp = c.post(
            f"/admin/dashboard/users/{normal_uid}/reset-password",
            data={
                "new_password": "new-admin-password-123",
                "confirm_password": "new-admin-password-123",
                "csrf_token": csrf_token(users_page.text),
            },
        )
        assert bad_target_resp.status_code == 403
        assert "sc_member" in bad_target_resp.text

        # Attempt password reset with mismatched passwords -> 400
        mismatch_resp = c.post(
            f"/admin/dashboard/users/{sc_uid}/reset-password",
            data={
                "new_password": "new-admin-password-123",
                "confirm_password": "different-password-123",
                "csrf_token": csrf_token(bad_target_resp.text),
            },
        )
        assert mismatch_resp.status_code == 400
        assert "Passwords do not match" in mismatch_resp.text

        # Attempt password reset with short password -> 400
        short_resp = c.post(
            f"/admin/dashboard/users/{sc_uid}/reset-password",
            data={
                "new_password": "short",
                "confirm_password": "short",
                "csrf_token": csrf_token(mismatch_resp.text),
            },
        )
        assert short_resp.status_code == 400
        assert "at least 8 characters" in short_resp.text

        # Valid password reset for sc_member
        new_sc_password = "brand-new-sc-password-999"
        reset_ok = c.post(
            f"/admin/dashboard/users/{sc_uid}/reset-password",
            data={
                "new_password": new_sc_password,
                "confirm_password": new_sc_password,
                "csrf_token": csrf_token(short_resp.text),
            },
        )
        assert reset_ok.status_code == 200, f"Got {reset_ok.status_code}: {reset_ok.text}"
        assert f"Password for {sc_email} was reset successfully" in reset_ok.text

        # Verify old password for sc_email fails and new password succeeds
        c.get("/logout", follow_redirects=False)
        old_login_fail = c.post(
            "/login",
            data={"email": sc_email, "password": password, "csrf_token": csrf_token(c.get("/login").text)},
            follow_redirects=False,
        )
        assert old_login_fail.status_code == 401
        assert "Invalid email or password" in old_login_fail.text

        new_login_ok = c.post(
            "/login",
            data={"email": sc_email, "password": new_sc_password, "csrf_token": csrf_token(c.get("/login").text)},
            follow_redirects=False,
        )
        assert new_login_ok.status_code == 303

        # Re-authenticate as vip_email (admin) to continue the rest of the flow
        c.get("/logout", follow_redirects=False)
        c.post(
            "/login",
            data={"email": vip_email, "password": password, "csrf_token": csrf_token(c.get("/login").text)},
            follow_redirects=False,
        )

        users_page2 = c.get("/admin/dashboard/users")
        vip_uid = c.get(f"/admin/roles/assignments?email={vip_email}", headers=admin).json()["user_id"]

        # Password reset works for admin accounts as well (and revokes their existing session)
        admin_new_pass = "admin-secret-new-pwd-789"
        reset_admin_ok = c.post(
            f"/admin/dashboard/users/{vip_uid}/reset-password",
            data={
                "new_password": admin_new_pass,
                "confirm_password": admin_new_pass,
                "csrf_token": csrf_token(users_page2.text),
            },
        )
        assert reset_admin_ok.status_code == 200
        assert f"Password for {vip_email} was reset successfully" in reset_admin_ok.text

        # Re-login with the new admin password
        admin_relogin = c.post(
            "/login",
            data={"email": vip_email, "password": admin_new_pass, "csrf_token": csrf_token(c.get("/login").text)},
            follow_redirects=False,
        )
        assert admin_relogin.status_code == 303

        # Test Assign Multiple Roles via Dashboard to regular user (normal_uid)
        users_page3 = c.get("/admin/dashboard/users")
        assert 'data-roles=' in users_page3.text
        # Test assign multiple roles at once: ["sc_member", "admin"]
        assign_multi_resp = c.post(
            f"/admin/dashboard/users/{normal_uid}/roles",
            data={"roles": ["sc_member", "admin"], "csrf_token": csrf_token(users_page3.text)},
            follow_redirects=False,
        )
        assert assign_multi_resp.status_code == 303
        norm_assigns = c.get(f"/admin/roles/assignments?email={email}", headers=admin).json()
        assert set(norm_assigns["user_roles"]) == {"admin", "sc_member"}

        # Now normal_uid has sc_member & admin, so password reset is allowed for them
        users_page4 = c.get("/admin/dashboard/users")
        reset_promoted_ok = c.post(
            f"/admin/dashboard/users/{normal_uid}/reset-password",
            data={
                "new_password": "promoted-user-pass-123",
                "confirm_password": "promoted-user-pass-123",
                "csrf_token": csrf_token(users_page4.text),
            },
        )
        assert reset_promoted_ok.status_code == 200

        # Test update roles checklist to remove admin and keep only sc_member
        users_page5 = c.get("/admin/dashboard/users")
        update_resp = c.post(
            f"/admin/dashboard/users/{normal_uid}/roles",
            data={"roles": ["sc_member"], "csrf_token": csrf_token(users_page5.text)},
            follow_redirects=False,
        )
        assert update_resp.status_code == 303
        norm_after_update = c.get(f"/admin/roles/assignments?email={email}", headers=admin).json()
        assert norm_after_update["user_roles"] == ["sc_member"]

        # Test self-lockout protection on own account: even if roles is empty, admin role is retained
        users_page6 = c.get("/admin/dashboard/users")
        self_update_resp = c.post(
            f"/admin/dashboard/users/{vip_uid}/roles",
            data={"roles": [], "csrf_token": csrf_token(users_page6.text)},
            follow_redirects=False,
        )
        assert self_update_resp.status_code == 303
        vip_after_self = c.get(f"/admin/roles/assignments?email={vip_email}", headers=admin).json()
        assert "admin" in vip_after_self["user_roles"]

        # Test Login Redirections:
        # 1. Direct login without next redirects directly to /account (for user without TOTP like sc_email)
        c.get("/logout", follow_redirects=False)
        direct_login = c.post(
            "/login",
            data={"email": sc_email, "password": new_sc_password, "csrf_token": csrf_token(c.get("/login").text)},
            follow_redirects=False,
        )
        assert direct_login.status_code == 303
        assert direct_login.headers["location"] == "/account"

        # 2. Login with relative next path redirects directly to that path
        c.get("/logout", follow_redirects=False)
        next_login = c.post(
            "/login",
            data={"email": vip_email, "password": admin_new_pass, "next": "/admin/dashboard", "csrf_token": csrf_token(c.get("/login?next=/admin/dashboard").text)},
            follow_redirects=False,
        )
        assert next_login.status_code == 303
        assert next_login.headers["location"] == "/admin/dashboard"

        # Keep password variable updated for vip_email for downstream test steps
        password = admin_new_pass

        # Test OAuth PKCE flow with this newly registered client
        new_code, new_verifier = login_and_code(
            new_cid,
            "https://payments.internal/callback",
            login_email=vip_email,
            login_password=password,
        )
        new_tok = c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": new_code,
                "redirect_uri": "https://payments.internal/callback",
                "code_verifier": new_verifier,
                "client_id": new_cid,
                "client_secret": rotated_secret,
            },
        )
        assert new_tok.status_code == 200, new_tok.text
        assert "access_token" in new_tok.json()

        # Test OAuth UI context and /cancel redirect flow
        v, ch = pkce()
        cancel_state = "state-cancel-123"
        az_cancel = c.get(
            "/authorize",
            params={
                "client_id": client_a["client_id"],
                "redirect_uri": "http://appa.test/callback",
                "response_type": "code",
                "scope": "openid email",
                "code_challenge": ch,
                "code_challenge_method": "S256",
                "state": cancel_state,
                "prompt": "login",
            },
            follow_redirects=False,
        )
        assert az_cancel.status_code == 302
        login_target = az_cancel.headers["location"]
        login_view = c.get(login_target)
        assert login_view.status_code == 200
        assert "to continue to" in login_view.text and ">A<" in login_view.text
        nxt_val = parse_qs(urlparse(login_target).query).get("next", [""])[0]
        assert f"/register?next={nxt_val}" in login_view.text
        assert f"/forgot-password?next={nxt_val}" in login_view.text
        assert f"/cancel?next={nxt_val}" in login_view.text

        # Clicking cancel redirects to client callback with access_denied
        cancel_resp = c.get(f"/cancel?next={nxt_val}", follow_redirects=False)
        assert cancel_resp.status_code == 302
        cancel_loc = cancel_resp.headers["location"]
        assert cancel_loc.startswith("http://appa.test/callback")
        cancel_query = parse_qs(urlparse(cancel_loc).query)
        assert cancel_query.get("error") == ["access_denied"]
        assert cancel_query.get("state") == [cancel_state]

        # Test profile editing via /account/profile
        c.get("/logout", follow_redirects=False)
        loc_l = c.get("/login")
        c.post(
            "/login",
            data={
                "email": vip_email,
                "password": password,
                "csrf_token": csrf_token(loc_l.text),
            },
            follow_redirects=False,
        )
        acc_page = c.get("/account/mfa")
        prof_update = c.post(
            "/account/profile",
            data={
                "first_name": "Alexander",
                "last_name": "Graham",
                "csrf_token": csrf_token(acc_page.text),
            },
            follow_redirects=False,
        )
        assert prof_update.status_code == 303
        acc_updated = c.get("/account/mfa")
        assert 'value="Alexander"' in acc_updated.text
        assert 'value="Graham"' in acc_updated.text

        # Test OAuth flow with scope "openid email profile"
        p_client = c.post(
            "/admin/clients",
            headers=admin,
            json={
                "name": "ProfileClient",
                "redirect_uris": ["http://profile.test/callback"],
                "allowed_scopes": ["openid", "email", "profile"],
                "is_first_party": True,
            },
        )
        assert p_client.status_code == 200
        p_cid = p_client.json()["client_id"]
        p_secret = p_client.json()["client_secret"]

        p_code, p_ver = login_and_code(
            p_cid,
            "http://profile.test/callback",
            scope="openid email profile",
            login_email=vip_email,
            login_password=password,
        )
        p_token_resp = c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": p_code,
                "redirect_uri": "http://profile.test/callback",
                "code_verifier": p_ver,
                "client_id": p_cid,
                "client_secret": p_secret,
            },
        )
        assert p_token_resp.status_code == 200
        p_tokens = p_token_resp.json()
        assert "access_token" in p_tokens
        assert "id_token" in p_tokens

        # Check /userinfo returns given_name, family_name, name
        p_userinfo = c.get("/userinfo", headers={"Authorization": f"Bearer {p_tokens['access_token']}"})
        assert p_userinfo.status_code == 200
        uinfo = p_userinfo.json()
        assert uinfo.get("given_name") == "Alexander"
        assert uinfo.get("family_name") == "Graham"
        assert uinfo.get("name") == "Alexander Graham"

        # Check ID token payload contains given_name, family_name, name
        from joserfc.jwk import KeySet
        id_claims_p = jwt.decode(p_tokens["id_token"], KeySet.import_key_set(jwks)).claims
        assert id_claims_p.get("given_name") == "Alexander"
        assert id_claims_p.get("family_name") == "Graham"
        assert id_claims_p.get("name") == "Alexander Graham"

        # Check that when client requests only "openid email", profile claims are NOT included
        no_prof_code, no_prof_ver = login_and_code(
            p_cid,
            "http://profile.test/callback",
            scope="openid email",
            login_email=vip_email,
            login_password=password,
        )
        no_prof_resp = c.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": no_prof_code,
                "redirect_uri": "http://profile.test/callback",
                "code_verifier": no_prof_ver,
                "client_id": p_cid,
                "client_secret": p_secret,
            },
        )
        assert no_prof_resp.status_code == 200
        no_prof_tokens = no_prof_resp.json()
        no_prof_uinfo = c.get("/userinfo", headers={"Authorization": f"Bearer {no_prof_tokens['access_token']}"}).json()
        assert "given_name" not in no_prof_uinfo
        assert "family_name" not in no_prof_uinfo
        assert "name" not in no_prof_uinfo
        no_prof_id_claims = jwt.decode(no_prof_tokens["id_token"], KeySet.import_key_set(jwks)).claims
        assert "given_name" not in no_prof_id_claims
        assert "family_name" not in no_prof_id_claims
        assert "name" not in no_prof_id_claims

        # 11. Test logo endpoints
        logo_light_resp = c.get("/logo-light.png")
        assert logo_light_resp.status_code == 200
        assert logo_light_resp.headers["content-type"] == "image/png"
        assert len(logo_light_resp.content) > 1000

        logo_dark_resp = c.get("/logo-dark.png")
        assert logo_dark_resp.status_code == 200
        assert logo_dark_resp.headers["content-type"] == "image/png"
        assert len(logo_dark_resp.content) > 1000

        # 12. Test third-party client consent triggers account_linked email
        tp_resp = c.post(
            "/admin/clients",
            headers=admin,
            json={
                "name": "Partner Studio",
                "redirect_uris": ["http://partner.test/callback"],
                "allowed_scopes": ["openid", "email"],
                "is_first_party": False,
            },
        )
        assert tp_resp.status_code == 200
        tp_client = tp_resp.json()

        _, tp_challenge = pkce()
        c.post(
            "/login",
            data={"email": vip_email, "password": password, "csrf_token": csrf_token(c.get("/login").text)},
            follow_redirects=False,
        )
        auth_req = c.get(
            "/authorize",
            params={
                "client_id": tp_client["client_id"],
                "redirect_uri": "http://partner.test/callback",
                "response_type": "code",
                "scope": "openid email",
                "code_challenge": tp_challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert auth_req.status_code == 200
        assert "authorize access" in auth_req.text.lower()
        consent_csrf = csrf_token(auth_req.text)
        next_m = re.search(r'name="next" value="([^"]+)"', auth_req.text)
        assert next_m, "next field not found in consent page"
        next_val = next_m.group(1)

        consent_post = c.post(
            "/consent",
            data={
                "csrf_token": consent_csrf,
                "decision": "allow",
                "next": next_val,
            },
            follow_redirects=False,
        )
        assert consent_post.status_code == 302
        assert "http://partner.test/callback" in consent_post.headers["location"]

        linked_mails = [m for m in sent_emails if "Partner Studio" in m["subject"]]
        assert linked_mails, "Application connected email not sent"
        assert linked_mails[-1]["to"] == vip_email
        assert linked_mails[-1].get("html"), "HTML body missing in account_linked email"
        assert "Partner Studio" in linked_mails[-1]["html"]
        assert "openid email" in linked_mails[-1]["html"]
        assert "/logo-light.png" in linked_mails[-1]["html"]
        # Test Register Confirm Password
        mismatch_email = f"mismatch-{secrets.token_hex(4)}@example.test"
        reg_page = c.get("/register")
        assert "confirm_password" in reg_page.text
        bad_confirm = c.post(
            "/register",
            data={
                "first_name": "Mis",
                "last_name": "Match",
                "email": mismatch_email,
                "password": "correct-horse-battery",
                "confirm_password": "wrong-horse-battery",
                "csrf_token": csrf_token(reg_page.text),
            },
            follow_redirects=False,
        )
        assert bad_confirm.status_code == 400
        assert "passwords do not match" in bad_confirm.text.lower()

        # Test Top Navigation user state and home redirection when logged out vs logged in
        c.get("/logout", follow_redirects=False)
        logged_out_red = c.get("/", follow_redirects=False)
        assert logged_out_red.status_code == 303
        assert "/login" in logged_out_red.headers["location"]

        logged_out_home = c.get("/")
        assert "Sign in" in logged_out_home.text
        assert 'id="userDropdown"' not in logged_out_home.text
        assert ">Home<" not in logged_out_home.text

        # Sign in and check home redirects to /account, top nav has user dropdown, no Home link
        login_page = c.get("/login")
        c.post(
            "/login",
            data={
                "email": vip_email,
                "password": password,
                "csrf_token": csrf_token(login_page.text),
            },
            follow_redirects=False,
        )
        logged_in_red = c.get("/", follow_redirects=False)
        assert logged_in_red.status_code == 303
        assert "/account" in logged_in_red.headers["location"]

        logged_in_home = c.get("/")
        assert 'id="userDropdown"' in logged_in_home.text
        assert "Account Settings" in logged_in_home.text
        assert "Sign out" in logged_in_home.text
        assert ">Home<" not in logged_in_home.text

        # Test Profile Patching: editing last name only preserves first name
        acc_page = c.get("/account")
        assert "PROFILE DETAILS" in acc_page.text
        assert "CHANGE PASSWORD" in acc_page.text
        patch_last = c.post(
            "/account/profile",
            data={
                "last_name": "Bell",
                "csrf_token": csrf_token(acc_page.text),
            },
            follow_redirects=False,
        )
        assert patch_last.status_code == 303
        acc_view = c.get("/account")
        assert 'value="Alexander"' in acc_view.text
        assert 'value="Bell"' in acc_view.text

        # Test JSON PATCH /account/profile
        json_patch = c.patch(
            "/account/profile",
            json={"first_name": "Sir Alexander"},
            headers={"x-csrf-token": csrf_token(acc_view.text)},
        )
        assert json_patch.status_code == 200
        assert json_patch.json() == {"first_name": "Sir Alexander", "last_name": "Bell"}
        acc_view2 = c.get("/account")
        assert 'value="Sir Alexander"' in acc_view2.text
        assert 'value="Bell"' in acc_view2.text

        # Test Change Password
        # 1. Invalid current password
        bad_curr = c.post(
            "/account/password",
            data={
                "current_password": "wrong-password",
                "new_password": "brand-new-secure-password",
                "confirm_password": "brand-new-secure-password",
                "csrf_token": csrf_token(acc_view2.text),
            },
            follow_redirects=False,
        )
        assert bad_curr.status_code == 303
        assert "Current+password+is+incorrect" in bad_curr.headers["location"]

        # 2. Mismatched confirm password
        bad_conf = c.post(
            "/account/password",
            data={
                "current_password": password,
                "new_password": "brand-new-secure-password",
                "confirm_password": "different-new-password",
                "csrf_token": csrf_token(acc_view2.text),
            },
            follow_redirects=False,
        )
        assert bad_conf.status_code == 303
        assert "do+not+match" in bad_conf.headers["location"]

        # 3. Test revocation of other sessions:
        # Save first session cookie
        first_cookie = c.cookies.get(settings.cookie_name)
        assert first_cookie is not None

        # Clear cookies and log in again to create a second active session
        c.cookies.clear()
        login_again = c.post(
            "/login",
            data={
                "email": vip_email,
                "password": password,
                "csrf_token": csrf_token(c.get("/login").text),
            },
            follow_redirects=False,
        )
        assert login_again.status_code == 303
        second_cookie = c.cookies.get(settings.cookie_name)
        assert second_cookie is not None and second_cookie != first_cookie

        # Now change password successfully using the second session
        fresh_acc = c.get("/account")
        new_vip_pass = "brand-new-secure-password"
        pwd_success = c.post(
            "/account/password",
            data={
                "current_password": password,
                "new_password": new_vip_pass,
                "confirm_password": new_vip_pass,
                "csrf_token": csrf_token(fresh_acc.text),
            },
            follow_redirects=False,
        )
        assert pwd_success.status_code == 303
        assert "Password+updated+successfully" in pwd_success.headers["location"]

        # Current (second) session still works
        assert c.get("/account").status_code == 200

        # Prior (first) session was revoked by password change, so using it redirects to /login
        c.cookies.clear()
        c.cookies.set(settings.cookie_name, first_cookie, domain="testserver.local")
        first_revoked = c.get("/account", follow_redirects=False)
        assert first_revoked.status_code == 302
        assert "/login" in first_revoked.headers["location"]

        # Old password cannot log in
        c.cookies.clear()
        old_login = c.post(
            "/login",
            data={
                "email": vip_email,
                "password": password,
                "csrf_token": csrf_token(c.get("/login").text),
            },
            follow_redirects=False,
        )
        assert old_login.status_code == 401

        # New password logs in successfully
        c.cookies.clear()
        new_login_resp = c.post(
            "/login",
            data={
                "email": vip_email,
                "password": new_vip_pass,
                "csrf_token": csrf_token(c.get("/login").text),
            },
            follow_redirects=False,
        )
        assert new_login_resp.status_code == 303
        active_sess_cookie = c.cookies.get(settings.cookie_name)
        assert active_sess_cookie is not None
        assert c.get("/account").status_code == 200

        # Test session revocation on password reset
        forgot_req = c.post(
            "/forgot-password",
            data={"email": vip_email, "csrf_token": csrf_token(c.get("/forgot-password").text)},
            follow_redirects=False,
        )
        assert forgot_req.status_code == 303
        reset_otp_m = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"])
        assert reset_otp_m
        reset_code = reset_otp_m.group(1)

        verify_resp = c.post(
            "/reset-password/verify",
            data={"email": vip_email, "code": reset_code, "csrf_token": csrf_token(c.get(forgot_req.headers["location"]).text)},
            follow_redirects=False,
        )
        assert verify_resp.status_code == 303
        tkt = parse_qs(urlparse(verify_resp.headers["location"]).query)["ticket"][0]

        final_pass = "brand-new-final-password"
        reset_post = c.post(
            "/reset-password",
            data={"ticket": tkt, "password": final_pass, "csrf_token": csrf_token(c.get(verify_resp.headers["location"]).text)},
            follow_redirects=False,
        )
        assert reset_post.status_code == 303

        # Active session was revoked by password reset!
        c.cookies.clear()
        c.cookies.set(settings.cookie_name, active_sess_cookie, domain="testserver.local")
        assert c.get("/account", follow_redirects=False).status_code == 302

        # Test active session guard on /login and /register
        c.cookies.clear()
        lp = c.get("/login")
        c.post(
            "/login",
            data={"email": vip_email, "password": final_pass, "csrf_token": csrf_token(lp.text)},
            follow_redirects=False,
        )
        assert c.get("/login", follow_redirects=False).status_code == 303
        assert c.get("/login", follow_redirects=False).headers["location"] == "/account"
        assert c.get("/register", follow_redirects=False).status_code == 303
        assert c.get("/register", follow_redirects=False).headers["location"] == "/account"

    print("ok")


def test_flow() -> None:
    main()


if __name__ == "__main__":
    main()
