from sqlalchemy.ext.asyncio import AsyncSession

from idp.models import AuditEvent


async def audit(
    session: AsyncSession,
    event_type: str,
    *,
    user_id=None,
    client_id: str | None = None,
    ip: str | None = None,
    detail: dict | None = None,
) -> None:
    session.add(
        AuditEvent(
            event_type=event_type,
            user_id=user_id,
            client_id=client_id,
            ip=ip,
            detail=detail,
        )
    )
