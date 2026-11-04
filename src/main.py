from contextlib import asynccontextmanager

from pathlib import Path
from starlette.staticfiles import StaticFiles
from fastapi import FastAPI
from sqlalchemy import text

from src.core import db
from src.services.bootstrap import bootstrap_demo_clients
from src.core.keys import ensure_active_key
from src.routers import accounts, admin, authorize, discovery, logout, mfa, token, userinfo
from src.core.settings import get_settings


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_engine()
    async with db.SessionLocal() as session:
        await ensure_active_key(session, get_settings())
        await bootstrap_demo_clients(session, get_settings())
        await session.commit()
    yield
    await db.engine.dispose()


app = FastAPI(
    title="sc-idp",
    description=(
        "Central OpenID Connect identity provider. Tokens are identity only "
        "(`sub`, email). Product roles, permissions, and billing never appear here. "
        "See docs/integrating-a-product.md."
    ),
    lifespan=lifespan,
)
app.include_router(discovery.router, tags=["oidc"])
app.include_router(authorize.router, tags=["oidc"])
app.include_router(token.router, tags=["oidc"])
app.include_router(userinfo.router, tags=["oidc"])
app.include_router(accounts.router, tags=["account"])
app.include_router(mfa.router, tags=["account"])
app.include_router(logout.router, tags=["oidc"])
app.include_router(admin.router, tags=["admin"])

from fastapi.responses import FileResponse

ASSETS_DIR = Path(__file__).resolve().parents[1] / "assets"
if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")


@app.get("/logo-light.png", include_in_schema=False)
async def logo_light():
    return FileResponse(ASSETS_DIR / "logo-light.png", media_type="image/png")


@app.get("/logo-dark.png", include_in_schema=False)
async def logo_dark():
    return FileResponse(ASSETS_DIR / "logo-dark.png", media_type="image/png")


@app.get("/healthz", tags=["ops"])
async def healthz():
    async with db.SessionLocal() as session:
        await session.execute(text("SELECT 1"))
    return {"ok": True}
