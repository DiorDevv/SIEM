import logging
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from config import settings

logger = logging.getLogger(__name__)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_recycle=1800,  # Recycle connections every 30 min
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            logger.error(f"DB session error, rolling back: {e}", exc_info=True)
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    from models.user import User
    from models.agent import Agent
    from models.alert import Alert
    from models.log import Log
    from models.rule import Rule
    from models.active_response import ARPolicy, ARExecution
    from models.vulnerability import PackageScan, Vulnerability
    from models.sca_result import SCAScan
    from models.audit_log import AuditLog

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info(f"Database pool: size={settings.DB_POOL_SIZE}, overflow={settings.DB_MAX_OVERFLOW}")
