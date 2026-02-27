"""
Database Connection and SQLAlchemy Setup

This module provides async SQLAlchemy engine configuration, database session management,
connection pooling, and base model classes for the multi-tenant platform.

Requirements: 1.1, 1.2
"""

from typing import AsyncGenerator, List
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool, QueuePool
from sqlalchemy import text, MetaData
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


# Naming convention for constraints (helps with migrations)
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models"""
    
    metadata = MetaData(naming_convention=convention)


class SharedBase(DeclarativeBase):
    """Base class for shared platform schema models"""
    
    metadata = MetaData(
        naming_convention=convention,
        schema="platform_shared"
    )


class TenantBase(DeclarativeBase):
    """Base class for tenant-specific schema models"""
    
    metadata = MetaData(naming_convention=convention)


class DatabaseManager:
    """
    Manages database connections and session lifecycle.
    
    Provides async SQLAlchemy engine with connection pooling configuration
    optimized for multi-tenant operations.
    """
    
    def __init__(self):
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None
    
    def initialize(self) -> None:
        """
        Initialize the database engine and session factory.
        
        Configures connection pooling based on environment settings:
        - Pool size: Maximum number of connections to maintain
        - Max overflow: Additional connections allowed beyond pool_size
        - Pool pre-ping: Verify connections before use
        - Echo: Log SQL statements (disabled in production)
        """
        if self._engine is not None:
            logger.warning("Database engine already initialized")
            return
        
        # Connection pool configuration
        pool_size = settings.DATABASE_POOL_SIZE
        max_overflow = settings.DATABASE_MAX_OVERFLOW
        
        # Create async engine with connection pooling
        self._engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG,  # Log SQL in debug mode
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=True,  # Verify connections before use
            pool_recycle=3600,  # Recycle connections after 1 hour
            poolclass=QueuePool,  # Use queue-based connection pool
        )
        
        # Create session factory
        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,  # Don't expire objects after commit
            autocommit=False,
            autoflush=False,
        )
        
        logger.info(
            "Database engine initialized",
            pool_size=pool_size,
            max_overflow=max_overflow,
            database_url=settings.DATABASE_URL.split("@")[-1],  # Log without credentials
        )
    
    async def close(self) -> None:
        """
        Close the database engine and dispose of connection pool.
        
        Should be called during application shutdown to cleanly close
        all database connections.
        """
        if self._engine is None:
            logger.warning("Database engine not initialized")
            return
        
        await self._engine.dispose()
        self._engine = None
        self._session_factory = None
        
        logger.info("Database engine closed")
    
    @property
    def engine(self) -> AsyncEngine:
        """Get the database engine instance"""
        if self._engine is None:
            raise RuntimeError("Database engine not initialized. Call initialize() first.")
        return self._engine
    
    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Get the session factory"""
        if self._session_factory is None:
            raise RuntimeError("Database engine not initialized. Call initialize() first.")
        return self._session_factory
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get a database session.
        
        This is a dependency that can be used with FastAPI's dependency injection.
        The session is automatically closed after the request completes.
        
        Usage:
            @app.get("/endpoint")
            async def endpoint(db: AsyncSession = Depends(get_db)):
                # Use db session
                pass
        
        Yields:
            AsyncSession: Database session
        """
        if self._session_factory is None:
            raise RuntimeError("Database engine not initialized. Call initialize() first.")
        
        async with self._session_factory() as session:
            try:
                yield session
            except Exception as e:
                await session.rollback()
                logger.error("Database session error", error=str(e))
                raise
            finally:
                await session.close()
    
    async def health_check(self) -> bool:
        """
        Check database connectivity.
        
        Returns:
            bool: True if database is accessible, False otherwise
        """
        try:
            async with self._session_factory() as session:
                await session.execute(text("SELECT 1"))
                return True
        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            return False
    
    async def get_all_tenant_ids(self) -> List[str]:
        """
        Get list of all tenant IDs from the shared schema.
        
        Used for operations that need to iterate through all tenants,
        such as database migrations.
        
        Returns:
            List[str]: List of tenant IDs
        """
        async with self._session_factory() as session:
            # Set search path to shared schema
            await session.execute(text("SET search_path TO platform_shared, public"))
            
            # Query tenant IDs
            result = await session.execute(
                text("SELECT id FROM tenants WHERE status = 'active'")
            )
            tenant_ids = [row[0] for row in result.fetchall()]
            
            logger.info("Retrieved tenant IDs", count=len(tenant_ids))
            return tenant_ids


# Global database manager instance
db_manager = DatabaseManager()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency for getting database sessions.
    
    Usage:
        @app.get("/endpoint")
        async def endpoint(db: AsyncSession = Depends(get_db)):
            # Use db session
            pass
    """
    async for session in db_manager.get_session():
        yield session


async def init_db() -> None:
    """
    Initialize database connection.
    
    Should be called during application startup.
    """
    db_manager.initialize()
    logger.info("Database initialized")


async def close_db() -> None:
    """
    Close database connection.
    
    Should be called during application shutdown.
    """
    await db_manager.close()
    logger.info("Database closed")
