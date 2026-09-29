"""Database engine and session factory."""

from __future__ import annotations

from sqlalchemy import inspect, text
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
        """Create missing tables, then add missing optional columns.

        New tables are created whole. Columns added to an existing model are
        added with ALTER TABLE if they are nullable, which is always safe on a
        live database. Anything else needs a hand-written migration and stops
        startup with a clear error rather than running with a mismatched schema.
        """
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.run_sync(_add_missing_columns)

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


def _add_missing_columns(sync_conn) -> None:
    inspector = inspect(sync_conn)
    dialect = sync_conn.dialect
    for table in Base.metadata.sorted_tables:
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            if not column.nullable or column.primary_key:
                raise RuntimeError(
                    f"column {table.name}.{column.name} is missing and not nullable; add a migration for it"
                )
            column_type = column.type.compile(dialect=dialect)
            sync_conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {column_type}'))
