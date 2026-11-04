from sqlalchemy.ext.asyncio import AsyncSession

from src.crypto import hash_token
from src.models import OAuthClient
from src.settings import Settings


async def bootstrap_demo_clients(session: AsyncSession, settings: Settings) -> None:
    specs = [
        ("a", settings.product_a_client_id, settings.product_a_client_secret, settings.product_a_url),
        ("b", settings.product_b_client_id, settings.product_b_client_secret, settings.product_b_url),
    ]
    for name, cid, secret, url in specs:
        if not cid or not secret or not url:
            continue
        base = url.rstrip("/")
        redirect = f"{base}/callback"
        logout = f"{base}/"
        hashed = hash_token(settings.token_hash_pepper, secret)
        row = await session.get(OAuthClient, cid)
        if row is None:
            session.add(
                OAuthClient(
                    client_id=cid,
                    name=f"Product {name.upper()}",
                    client_secret_hash=hashed,
                    redirect_uris=[redirect],
                    post_logout_redirect_uris=[logout],
                    allowed_scopes=["openid", "email"],
                    is_first_party=True,
                    is_active=True,
                )
            )
        else:
            row.client_secret_hash = hashed
            row.redirect_uris = [redirect]
            row.post_logout_redirect_uris = [logout]
            row.is_active = True
