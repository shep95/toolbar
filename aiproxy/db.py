"""Database engine and session factory."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .config import Settings
from .models import Base

# Errors that mean "the database is unavailable". The gateway turns these into
# a 503 and never forwards the request upstream.
DB_UNAVAILABLE_ERRORS: tuple[type[BaseException], ...] = (SQLAlchemyError, OSError, TimeoutError)


class Database:
    def __init__(self, engine: AsyncEngine):
        self.engine = engine
        self.sessionmaker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        url = settings.database_url
        kwargs: dict = {}
        if url.startswith("postgresql+asyncpg"):
            # No pool_pre_ping: it adds a round trip to every checkout. Dead
            # connections are detected on use and replaced (see is_disconnect),
            # and pool_recycle retires connections before servers drop them.
            kwargs["pool_size"] = settings.database_pool_size
            kwargs["max_overflow"] = settings.database_max_overflow
            kwargs["pool_recycle"] = 1800
            kwargs["connect_args"] = {"timeout": settings.database_connect_timeout_seconds}
        return cls(create_async_engine(url, **kwargs))

    def session(self) -> AsyncSession:
        return self.sessionmaker()

    async def create_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def ping(self) -> bool:
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("select 1"))
            return True
        except DB_UNAVAILABLE_ERRORS:
            return False

    @staticmethod
    def is_disconnect(exc: BaseException) -> bool:
        """True when a pooled connection turned out to be dead and was discarded."""
        return bool(getattr(exc, "connection_invalidated", False))

    async def dispose(self) -> None:
        await self.engine.dispose()
