from fastapi import APIRouter, Request
from sqlalchemy.ext.asyncio import AsyncSession

from idp.deps import db_dep, s_dep
from idp.keys import public_jwks
from idp.settings import Settings

router = APIRouter()


@router.get("/.well-known/openid-configuration")
async def discovery(settings: Settings = s_dep):
    base = settings.public_base
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "userinfo_endpoint": f"{base}/userinfo",
        "jwks_uri": f"{base}/.well-known/jwks.json",
        "end_session_endpoint": f"{base}/logout",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": ["openid", "email"],
        "claims_supported": ["sub", "email", "email_verified"],
    }


@router.get("/.well-known/jwks.json")
async def jwks(session: AsyncSession = db_dep, settings: Settings = s_dep):
    return await public_jwks(session, settings)
