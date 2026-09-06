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

        reg = c.get("/register")
        r = c.post(
            "/register",
            data={"email": email, "password": password, "csrf_token": csrf_token(reg.text)},
            follow_redirects=False,
        )
        assert r.status_code == 200, r.text

        def login_and_code(client_id: str, redirect: str, prompt: str | None = None) -> tuple[str, str]:
            verifier, challenge = pkce()
            params = {
                "client_id": client_id,
                "redirect_uri": redirect,
                "response_type": "code",
                "scope": "openid email",
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
                        "email": email,
                        "password": password,
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

    print("ok")


if __name__ == "__main__":
    main()
