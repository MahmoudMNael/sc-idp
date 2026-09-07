"""Demo first-party product. Layer 2: product JWT + rotating refresh. Never ships IdP tokens to the browser."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from joserfc import jwt
from joserfc.jwk import KeySet, OctKey
from joserfc.jwt import JWTClaimsRegistry
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

ACCESS_TTL = 600
REFRESH_TTL = 2_592_000

_refresh: dict[str, dict] = {}


def _env(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        raise RuntimeError(f"{name} is not set")
    return v


def _settings():
    which = os.environ.get("PRODUCT_NAME", "a").lower()
    p = which.upper()
    return {
        "name": which,
        "client_id": _env(f"PRODUCT_{p}_CLIENT_ID"),
        "client_secret": _env(f"PRODUCT_{p}_CLIENT_SECRET"),
        "url": _env(f"PRODUCT_{p}_URL").rstrip("/"),
        "jwt_secret": _env(f"PRODUCT_{p}_JWT_SECRET"),
        "idp": _env("IDP_ISSUER").rstrip("/"),
        "secret_key": os.environ.get("SECRET_KEY") or _env(f"PRODUCT_{p}_JWT_SECRET"),
    }


def _key(secret: str) -> OctKey:
    return OctKey.import_key(hashlib.sha256(secret.encode()).digest())


def _sign_flow(secret: str, payload: dict) -> str:
    return URLSafeTimedSerializer(secret, salt="oidc-flow").dumps(payload)


def _load_flow(secret: str, token: str) -> dict | None:
    try:
        return URLSafeTimedSerializer(secret, salt="oidc-flow").loads(token, max_age=600)
    except (BadSignature, SignatureExpired, Exception):
        return None


def _hash(secret: str, token: str) -> str:
    return hashlib.sha256(f"{secret}:{token}".encode()).hexdigest()


def mint_product(cfg: dict, sub: str, email: str, roles: list[str]) -> tuple[str, str]:
    now = int(time.time())
    access = jwt.encode(
        {"alg": "HS256", "typ": "JWT"},
        {
            "iss": cfg["url"],
            "sub": sub,
            "email": email,
            "roles": roles,
            "exp": now + ACCESS_TTL,
            "iat": now,
        },
        _key(cfg["jwt_secret"]),
    )
    raw = secrets.token_urlsafe(48)
    family = str(uuid.uuid4())
    _refresh[_hash(cfg["jwt_secret"], raw)] = {
        "sub": sub,
        "email": email,
        "roles": roles,
        "family": family,
        "used": False,
        "exp": now + REFRESH_TTL,
    }
    return access, raw


def rotate_product(cfg: dict, refresh_raw: str) -> tuple[str, str] | None:
    now = int(time.time())
    h = _hash(cfg["jwt_secret"], refresh_raw)
    row = _refresh.get(h)
    if row is None:
        return None
    if row["used"] or row["exp"] < now:
        fam = row["family"]
        for rec in _refresh.values():
            if rec["family"] == fam:
                rec["used"] = True
        return None
    row["used"] = True
    access, new_raw = mint_product(cfg, row["sub"], row["email"], row["roles"])
    _refresh[_hash(cfg["jwt_secret"], new_raw)]["family"] = row["family"]
    return access, new_raw


def read_product_jwt(cfg: dict, token: str) -> dict:
    obj = jwt.decode(token, _key(cfg["jwt_secret"]))
    JWTClaimsRegistry(iss={"essential": True, "value": cfg["url"]}, exp={"essential": True}).validate(obj.claims)
    return obj.claims


def create_product_app() -> FastAPI:
    app = FastAPI(title="demo-product")

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        cfg = _settings()
        token = request.cookies.get("product_access")
        if not token:
            return HTMLResponse(
                f"<p>Not signed into product {cfg['name']}.</p><p><a href='/login'>Sign in with IdP</a></p>"
            )
        try:
            claims = read_product_jwt(cfg, token)
        except Exception:
            return HTMLResponse("<p>Product session expired.</p><p><a href='/login'>Sign in</a></p>")
        return HTMLResponse(
            f"<p>Product {cfg['name']} sees sub={claims['sub']} email={claims.get('email')} "
            f"roles={claims.get('roles')}</p><p><a href='/logout'>Product logout</a></p>"
        )

    @app.get("/login")
    async def login():
        cfg = _settings()
        async with httpx.AsyncClient() as http:
            meta = (await http.get(f"{cfg['idp']}/.well-known/openid-configuration")).json()
        nonce = secrets.token_urlsafe(16)
        code_verifier = secrets.token_urlsafe(64)
        client = AsyncOAuth2Client(
            cfg["client_id"],
            cfg["client_secret"],
            scope="openid email",
            redirect_uri=f"{cfg['url']}/callback",
            code_challenge_method="S256",
        )
        url, state = client.create_authorization_url(
            meta["authorization_endpoint"], nonce=nonce, code_verifier=code_verifier
        )
        response = RedirectResponse(url, status_code=302)
        response.set_cookie(
            "oidc_flow",
            _sign_flow(
                cfg["secret_key"],
                {"state": state, "nonce": nonce, "verifier": code_verifier, "authz": meta["authorization_endpoint"], "token": meta["token_endpoint"], "jwks": meta["jwks_uri"]},
            ),
            httponly=True,
            max_age=600,
            samesite="lax",
        )
        return response

    @app.get("/callback")
    async def callback(request: Request, code: str = "", state: str = ""):
        cfg = _settings()
        flow = _load_flow(cfg["secret_key"], request.cookies.get("oidc_flow") or "")
        if not flow or flow.get("state") != state or not code:
            return HTMLResponse("invalid oauth state", status_code=400)
        client = AsyncOAuth2Client(
            cfg["client_id"],
            cfg["client_secret"],
            redirect_uri=f"{cfg['url']}/callback",
        )
        token = await client.fetch_token(
            flow["token"],
            grant_type="authorization_code",
            code=code,
            redirect_uri=f"{cfg['url']}/callback",
            code_verifier=flow["verifier"],
        )
        async with httpx.AsyncClient() as http:
            jwks = (await http.get(flow["jwks"])).json()
        id_claims = jwt.decode(token["id_token"], KeySet.import_key_set(jwks)).claims
        JWTClaimsRegistry(
            iss={"essential": True, "value": cfg["idp"]},
            aud={"essential": True, "value": cfg["client_id"]},
        ).validate(id_claims)
        if flow["nonce"] != id_claims.get("nonce"):
            return HTMLResponse("nonce mismatch", status_code=400)
        access, refresh = mint_product(cfg, id_claims["sub"], id_claims.get("email") or "", ["user"])
        response = RedirectResponse("/", status_code=302)
        response.delete_cookie("oidc_flow")
        response.set_cookie("product_access", access, httponly=True, samesite="lax", max_age=ACCESS_TTL)
        response.set_cookie("product_refresh", refresh, httponly=True, samesite="lax", max_age=REFRESH_TTL)
        return response

    @app.post("/refresh")
    async def refresh(request: Request):
        cfg = _settings()
        raw = request.cookies.get("product_refresh")
        if not raw:
            return JSONResponse({"error": "invalid_grant"}, status_code=401)
        rotated = rotate_product(cfg, raw)
        if rotated is None:
            response = JSONResponse({"error": "invalid_grant"}, status_code=401)
            response.delete_cookie("product_access")
            response.delete_cookie("product_refresh")
            return response
        access, new_raw = rotated
        body = {"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_TTL}
        response = JSONResponse(body)
        response.set_cookie("product_access", access, httponly=True, samesite="lax", max_age=ACCESS_TTL)
        response.set_cookie("product_refresh", new_raw, httponly=True, samesite="lax", max_age=REFRESH_TTL)
        return response

    @app.get("/api/me")
    async def me(request: Request):
        cfg = _settings()
        header = request.headers.get("authorization") or ""
        token = header.split(" ", 1)[1] if header.lower().startswith("bearer ") else request.cookies.get("product_access")
        if not token:
            return JSONResponse({"error": "missing token"}, status_code=401)
        try:
            return read_product_jwt(cfg, token)
        except Exception:
            return JSONResponse({"error": "invalid token"}, status_code=401)

    @app.get("/logout")
    async def logout():
        cfg = _settings()
        dest = f"{cfg['idp']}/logout?post_logout_redirect_uri={cfg['url']}/"
        response = RedirectResponse(dest, status_code=302)
        response.delete_cookie("product_access")
        response.delete_cookie("product_refresh")
        return response

    return app


app = create_product_app()
