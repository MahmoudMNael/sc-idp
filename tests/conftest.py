from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

import src.core.db as db_mod
from src.core.deps import get_db
from src.core.settings import get_settings
from src.main import app
from src.models import Base


@pytest.fixture(autouse=True)
def force_console_mail() -> Iterator[None]:
    """Force console mail backend for all tests so no SMTP calls are made."""
    prev_backend = os.environ.get("MAIL_BACKEND")
    os.environ["MAIL_BACKEND"] = "console"
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.mail_backend == "console"
    yield
    if prev_backend is not None:
        os.environ["MAIL_BACKEND"] = prev_backend
    else:
        os.environ.pop("MAIL_BACKEND", None)
    get_settings.cache_clear()


@pytest.fixture
def mail_capture() -> Iterator[list[dict]]:
    """Capture all emails dispatched during a test in memory while keeping console output."""
    sent = []
    import src.services.mail as mail_mod

    orig_send_mail = mail_mod.send_mail

    def fake_send(settings, to, subject, body, html=None, *args, **kwargs):
        sent.append({"to": to, "subject": subject, "body": body, "html": html})
        orig_send_mail(settings, to, subject, body, html=html, *args, **kwargs)

    mail_mod.send_mail = fake_send
    import src.routers.accounts as acc
    import src.routers.authorize as auth

    acc.send_mail = fake_send
    auth.send_mail = fake_send

    yield sent

    mail_mod.send_mail = orig_send_mail
    acc.send_mail = orig_send_mail
    auth.send_mail = orig_send_mail


@pytest.fixture
def db_transaction_client() -> Iterator[TestClient]:
    """TestClient wrapped in an outer transaction that is always rolled back on teardown."""
    settings = get_settings()
    engine = create_async_engine(settings.sqlalchemy_url, poolclass=NullPool)

    with TestClient(app, base_url="http://testserver") as client:

        async def setup_tx():
            conn = await engine.connect()
            trans = await conn.begin()
            sm = async_sessionmaker(
                bind=conn,
                expire_on_commit=False,
                join_transaction_mode="create_savepoint",
            )

            async def override_get_db():
                async with sm() as s:
                    yield s
                    await s.commit()

            app.dependency_overrides[get_db] = override_get_db
            db_mod.SessionLocal = sm
            return conn, trans, sm

        conn, trans, sm = client.portal.call(setup_tx)
        client.db_sessionmaker = sm

        try:
            yield client
        finally:

            async def teardown_tx():
                await trans.rollback()
                await conn.close()
                await engine.dispose()

            client.portal.call(teardown_tx)
            app.dependency_overrides.pop(get_db, None)
