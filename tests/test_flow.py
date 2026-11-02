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
sys.path.insert(0, str(ROOT / "src"))

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

    from idp.models import Base
    from idp.settings import get_settings
    from idp.tokens import mint_idp_jwt

    get_settings.cache_clear()
    settings = get_settings()

    async def reset_db() -> None:
        engine = create_async_engine(settings.sqlalchemy_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(reset_db())

    from idp.main import app

    email = f"user-{secrets.token_hex(4)}@example.test"
    password = "correct-horse-battery"

    with TestClient(app, base_url="http://testserver") as c:
        h = c.get("/healthz")
        assert h.status_code == 200, h.text

        disc = c.get("/.well-known/openid-configuration").json()
        assert disc["response_types_supported"] == ["code"]
        assert disc["code_challenge_methods_supported"] == ["S256"]
        assert disc["id_token_signing_alg_values_supported"] == ["RS256"]
        assert "idp_roles" in disc["scopes_supported"]
        assert "idp_roles" in disc["claims_supported"]

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
        import idp.routers.accounts as accounts_mod
        orig_send_mail = accounts_mod.send_mail

        def fake_send_mail(settings, to, subject, body):
            sent_emails.append({"to": to, "subject": subject, "body": body})
            orig_send_mail(settings, to, subject, body)

        accounts_mod.send_mail = fake_send_mail

        reg = c.get("/register")
        r = c.post(
            "/register",
            data={"email": email, "password": password, "csrf_token": csrf_token(reg.text)},
            follow_redirects=False,
        )
        assert r.status_code == 303, r.text
        assert "/verify-email" in r.headers["location"]

        # unverified user blocked at login
        bad_login = c.post(
            "/login",
            data={"email": email, "password": password, "csrf_token": csrf_token(c.get("/login").text)},
            follow_redirects=False,
        )
        assert bad_login.status_code == 403, bad_login.text
        assert "verify your email" in bad_login.text.lower()

        # extract OTP and test verification
        assert sent_emails, "No email sent"
        otp_m = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"])
        assert otp_m, sent_emails[-1]["body"]
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
        f = c.post(
            "/forgot-password",
            data={"email": email, "csrf_token": csrf_token(forgot_page.text)},
            follow_redirects=False,
        )
        assert f.status_code == 303
        assert "/reset-password/verify" in f.headers["location"]

        reset_m = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"])
        assert reset_m, sent_emails[-1]["body"]
        reset_otp = reset_m.group(1)

        reset_verify_page = c.get(f.headers["location"])
        # wrong reset OTP
        bad_reset_otp = c.post(
            "/reset-password/verify",
            data={"email": email, "code": "000000", "csrf_token": csrf_token(reset_verify_page.text)},
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
            data={"email": email2, "password": password, "csrf_token": csrf_token(reg2.text)},
            follow_redirects=False,
        )
        assert r2.status_code == 303
        v2_page = c.get(r2.headers["location"])

        # test resend
        resend_resp = c.post(
            "/verify-email/resend",
            data={"email": email2, "csrf_token": csrf_token(v2_page.text)},
            follow_redirects=False,
        )
        assert resend_resp.status_code == 200
        assert "A new verification code has been sent." in resend_resp.text
        otp2_m = re.search(r"code is:\s*([0-9]{6})", sent_emails[-1]["body"])
        assert otp2_m
        otp2 = otp2_m.group(1)

        # test max attempts (5 invalid tries allowed, 6th triggers 429)
        curr_page = resend_resp
        for _ in range(5):
            curr_page = c.post(
                "/verify-email",
                data={"email": email2, "code": "000000", "csrf_token": csrf_token(curr_page.text)},
                follow_redirects=False,
            )
            assert curr_page.status_code == 400

        # 6th attempt is rate-limited
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
            data={"email": vip_email, "password": password, "csrf_token": csrf_token(vip_reg.text)},
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

        # userinfo includes idp_roles
        u_info = c.get(
            "/userinfo",
            headers={"Authorization": f"Bearer {tok_r.json()['access_token']}"},
        ).json()
        assert u_info.get("idp_roles") == ["admin"]

        # 7. test require_idp_role route guard dependency
        from fastapi import Depends
        from idp.roles import require_idp_role

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
            data={"email": sc_email, "password": password, "csrf_token": csrf_token(sc_reg.text)},
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

    print("ok")


if __name__ == "__main__":
    main()
