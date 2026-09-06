import hmac
import secrets

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from idp.audit import audit
from idp.crypto import hash_token
from idp.deps import db_dep, s_dep
from idp.keys import rotate_keys
from idp.models import OAuthClient
from idp.settings import Settings

router = APIRouter(prefix="/admin")


class ClientIn(BaseModel):
    name: str
    redirect_uris: list[str] = Field(min_length=1)
    post_logout_redirect_uris: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(default_factory=lambda: ["openid", "email"])
    is_first_party: bool = True
    client_id: str | None = None


def _admin(settings: Settings, authorization: str | None) -> None:
    if not settings.idp_admin_api_key:
        raise HTTPException(503, "IDP_ADMIN_API_KEY is not set")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing admin bearer token")
    got = authorization.split(" ", 1)[1]
    if not hmac.compare_digest(got, settings.idp_admin_api_key):
        raise HTTPException(401, "invalid admin bearer token")


@router.post("/clients")
async def create_client(
    body: ClientIn,
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    authorization: str | None = Header(default=None),
):
    _admin(settings, authorization)
    cid = body.client_id or secrets.token_urlsafe(16)
    if await session.get(OAuthClient, cid):
        raise HTTPException(409, "client_id already exists")
    secret = secrets.token_urlsafe(32)
    session.add(
        OAuthClient(
            client_id=cid,
            name=body.name,
            client_secret_hash=hash_token(settings.token_hash_pepper, secret),
            redirect_uris=body.redirect_uris,
            post_logout_redirect_uris=body.post_logout_redirect_uris,
            allowed_scopes=body.allowed_scopes,
            is_first_party=body.is_first_party,
        )
    )
    await audit(session, "admin_create_client", client_id=cid, detail={"name": body.name})
    return {"client_id": cid, "client_secret": secret}


@router.post("/keys/rotate")
async def rotate(
    session: AsyncSession = db_dep,
    settings: Settings = s_dep,
    authorization: str | None = Header(default=None),
):
    _admin(settings, authorization)
    kid = await rotate_keys(session, settings)
    await audit(session, "admin_rotate_keys", detail={"kid": kid})
    return {"kid": kid, "status": "active"}
