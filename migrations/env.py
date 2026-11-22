import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

# Importing the model modules has a side effect: their ``class X(SQLModel, table=True)``
# statements register the corresponding tables on ``SQLModel.metadata``.
# Alembic's autogenerate diffs ``target_metadata`` (== ``SQLModel.metadata``)
# against the live DB, so without these imports the users table would be
# invisible to ``alembic revision --autogenerate``. When you add a module with
# new tables, add its import here too.
import queuepass.modules.auth.models  # noqa: F401
import queuepass.modules.events.models  # noqa: F401
from queuepass.core.config import settings
from queuepass.core.db import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = create_async_engine(settings.DATABASE_URL, poolclass=pool.NullPool)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
