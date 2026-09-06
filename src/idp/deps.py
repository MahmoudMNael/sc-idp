from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from idp.db import get_db
from idp.settings import Settings, get_settings


def settings_dep() -> Settings:
    return get_settings()


Db = AsyncSession
db_dep = Depends(get_db)
s_dep = Depends(settings_dep)


def ip_of(request: Request) -> str | None:
    return request.client.host if request.client else None
