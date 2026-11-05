from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def allow(session: AsyncSession, key: str, limit: int, window: int) -> bool:
    # ponytail: single-DB fixed window; one extra write on the primary per limited request. Ceiling: lock contention under multi-instance burst. Upgrade: Redis INCR with TTL.
    now = datetime.now(UTC)
    window_start = datetime.fromtimestamp((int(now.timestamp()) // window) * window, tz=UTC)
    await session.execute(
        text(
            """
            INSERT INTO rate_limits (`key`, window_start, count)
            VALUES (:key, :window_start, 1)
            ON DUPLICATE KEY UPDATE count = count + 1
            """
        ),
        {"key": key, "window_start": window_start},
    )
    result = await session.execute(
        text("SELECT count FROM rate_limits WHERE `key` = :key AND window_start = :window_start"),
        {"key": key, "window_start": window_start},
    )
    count = result.scalar_one()
    return int(count) <= limit


async def reset_rate_limit(session: AsyncSession, key: str) -> None:
    await session.execute(
        text("DELETE FROM rate_limits WHERE `key` = :key"),
        {"key": key},
    )
