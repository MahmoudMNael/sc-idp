from fastapi import APIRouter, Response
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.deps import db_dep, s_dep
from src.core.keys import public_jwks
from src.core.settings import Settings

router = APIRouter()


@router.get("/.well-known/openid-configuration")
@router.get("/.well-known/oauth-authorization-server")
async def discovery(response: Response, settings: Settings = s_dep):
    response.headers["Cache-Control"] = "public, max-age=3600, stale-while-revalidate=300"
    response.headers["Access-Control-Allow-Origin"] = "*"
    base = settings.public_base
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "userinfo_endpoint": f"{base}/userinfo",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "end_session_endpoint": f"{base}/logout",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": ["openid", "email", "idp_roles"],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "amr",
            "at_hash",
            "email",
            "email_verified",
            "idp_roles",
        ],
        "claims_parameter_supported": False,
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
        "require_request_uri_registration": False,
    }


@router.get("/.well-known/jwks.json")
@router.get("/.well-known/jwks")
async def jwks(response: Response, session: AsyncSession = db_dep, settings: Settings = s_dep):
    response.headers["Cache-Control"] = (
        f"public, max-age={settings.key_cache_seconds}, stale-while-revalidate=60"
    )
    response.headers["Access-Control-Allow-Origin"] = "*"
    return await public_jwks(session, settings)

