from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.settings import get_settings

engine = None
SessionLocal = None


def init_engine() -> None:
    global engine, SessionLocal
    settings = get_settings()
    engine = create_async_engine(settings.sqlalchemy_url, pool_pre_ping=True)
    SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session
        await session.commit()
