from __future__ import annotations

import uuid
from typing import Callable

from fastapi import Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from idp.deps import db_dep, s_dep
from idp.models import EmailIdpRolePreassignment, IdpRole, User, UserIdpRole
from idp.sessions import load_session
from idp.settings import Settings


class RoleName:
    ADMIN = "admin"
    SC_MEMBER = "sc_member"


async def ensure_role_exists(session: AsyncSession, role_name: str, description: str | None = None) -> IdpRole:
    role = await session.get(IdpRole, role_name)
    if not role:
        role = IdpRole(name=role_name, description=description)
        session.add(role)
        await session.flush()
    return role


async def get_user_roles(session: AsyncSession, user_id: uuid.UUID) -> list[str]:
    # ponytail: simple index scan on composite PK (user_id, role_name).
    rows = await session.execute(
        select(UserIdpRole.role_name).where(UserIdpRole.user_id == user_id).order_by(UserIdpRole.role_name)
    )
    return list(rows.scalars().all())


async def assign_role_to_user(session: AsyncSession, user_id: uuid.UUID, role_name: str) -> bool:
    await ensure_role_exists(session, role_name)
    existing = await session.get(UserIdpRole, (user_id, role_name))
    if not existing:
        session.add(UserIdpRole(user_id=user_id, role_name=role_name))
        await session.flush()
        return True
    return False


async def remove_role_from_user(session: AsyncSession, user_id: uuid.UUID, role_name: str) -> bool:
    res = await session.execute(
        delete(UserIdpRole).where(UserIdpRole.user_id == user_id, UserIdpRole.role_name == role_name)
    )
    return (res.rowcount or 0) > 0


async def get_email_preassigned_roles(session: AsyncSession, email: str) -> list[str]:
    email_n = email.strip().lower()
    rows = await session.execute(
        select(EmailIdpRolePreassignment.role_name)
        .where(EmailIdpRolePreassignment.email == email_n)
        .order_by(EmailIdpRolePreassignment.role_name)
    )
    return list(rows.scalars().all())


async def preassign_role_to_email(session: AsyncSession, email: str, role_name: str) -> bool:
    await ensure_role_exists(session, role_name)
    email_n = email.strip().lower()
    existing = await session.get(EmailIdpRolePreassignment, (email_n, role_name))
    if not existing:
        session.add(EmailIdpRolePreassignment(email=email_n, role_name=role_name))
        await session.flush()
        return True
    return False


async def remove_preassigned_role_from_email(session: AsyncSession, email: str, role_name: str) -> bool:
    email_n = email.strip().lower()
    res = await session.execute(
        delete(EmailIdpRolePreassignment).where(
            EmailIdpRolePreassignment.email == email_n,
            EmailIdpRolePreassignment.role_name == role_name,
        )
    )
    return (res.rowcount or 0) > 0


async def apply_preassigned_roles(session: AsyncSession, user_id: uuid.UUID, email: str) -> list[str]:
    email_n = email.strip().lower()
    preassigned = set(await get_email_preassigned_roles(session, email_n))
    # ponytail: hardcoded domain rule; upgrade to domain mapping table or config when more domains need dynamic roles.
    if email_n.endswith("@shortcircuitcompany.com"):
        preassigned.add(RoleName.SC_MEMBER)
    assigned = []
    for role in sorted(preassigned):
        if await assign_role_to_user(session, user_id, role):
            assigned.append(role)
    return assigned


def require_idp_role(*roles: str) -> Callable:
    # ponytail: standard FastAPI dependency inspecting the active browser session or bearer auth.
    async def _dependency(
        request: Request,
        session: AsyncSession = db_dep,
        settings: Settings = s_dep,
    ) -> User:
        cookie = request.cookies.get(settings.cookie_name)
        auth_session = await load_session(session, settings, cookie) if cookie else None
        if not auth_session:
            raise HTTPException(401, "authentication required")
        user = await session.get(User, auth_session.user_id)
        if not user or not user.is_active:
            raise HTTPException(401, "invalid user")
        user_roles = await get_user_roles(session, user.id)
        if roles and not any(r in user_roles for r in roles):
            raise HTTPException(403, "forbidden: insufficient idp roles")
        return user

    return _dependency
