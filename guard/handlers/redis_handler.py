import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import HTTPException, status
from redis.asyncio import Redis
from redis.exceptions import ConnectionError

from guard.models import SecurityConfig


class RedisManager:
    """
    Robust Redis handler with connection pooling and automatic reconnection.
    """

    _instance = None
    _redis: Redis | None = None
    _connection_lock = asyncio.Lock()
    _closed = False
    config: SecurityConfig
    logger: logging.Logger

    def __new__(cls: type["RedisManager"], config: SecurityConfig) -> "RedisManager":
        cls._instance = super().__new__(cls)
        cls._instance.config = config
        cls._instance.logger = logging.getLogger(__name__)
        cls._instance._closed = False
        return cls._instance

    async def initialize(self) -> None:
        """Initialize Redis connection with retry logic"""
        if self._closed or not self.config.enable_redis:
            self._redis = None
            return

        async with self._connection_lock:
            try:
                if self.config.redis_url is not None:
                    self._redis = Redis.from_url(
                        self.config.redis_url, decode_responses=True
                    )
                    if self._redis is not None:
                        await self._redis.ping()
                        self.logger.info("Redis connection established")
                else:
                    self.logger.warning("Redis URL is None, skipping connection")

            except Exception as e:
                self.logger.error(f"Redis connection failed: {str(e)}")
                self._redis = None
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Redis connection failed",
                ) from e

    async def close(self) -> None:
        """Close Redis connection properly"""
        if self._redis:
            await self._redis.aclose()
            self._redis = None
            self.logger.info("Redis connection closed")
        self._closed = True

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[Redis]:
        """Context manager for safe Redis operations"""
        try:
            if self._closed:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Redis connection closed",
                )

            if not self._redis:
                await self.initialize()

            if self._redis is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Redis connection failed",
                )

            yield self._redis
        except (ConnectionError, AttributeError) as e:
            self.logger.error(f"Redis operation failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Redis connection failed",
            ) from e

    async def safe_operation(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        """Execute Redis operation with error handling"""
        if not self.config.enable_redis:
            return None

        try:
            async with self.get_connection() as conn:
                return await func(conn, *args, **kwargs)
        except Exception as e:
            self.logger.error(f"Redis operation failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Redis operation failed",
            ) from e

    # Atomic operations
    async def get_key(self, namespace: str, key: str) -> Any:
        """Get a value from Redis with proper namespacing"""
        if not self.config.enable_redis:
            return None

        async def _get(conn: Redis) -> Any:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return await conn.get(full_key)

        return await self.safe_operation(_get)

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None:
        """Set a value in Redis with proper namespacing"""
        if not self.config.enable_redis:
            return None

        async def _set(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            if ttl:
                return bool(await conn.setex(full_key, ttl, value))
            return bool(await conn.set(full_key, value))

        result = await self.safe_operation(_set)
        return False if result is None else bool(result)

    async def incr(
        self, namespace: str, key: str, ttl: int | None = None
    ) -> int | None:
        """Atomic increment with namespacing"""
        if not self.config.enable_redis:
            return None

        async def _incr(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            async with conn.pipeline() as pipe:
                await pipe.incr(full_key)
                if ttl:
                    await pipe.expire(full_key, ttl)
                result = await pipe.execute()
                return int(result[0]) if result else 0

        result = await self.safe_operation(_incr)
        return int(result) if result is not None else 0

    async def exists(self, namespace: str, key: str) -> bool | None:
        """Check if a namespaced key exists"""
        if not self.config.enable_redis:
            return None

        async def _exists(conn: Redis) -> bool:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return bool(await conn.exists(full_key))

        result = await self.safe_operation(_exists)
        return False if result is None else bool(result)

    async def delete(self, namespace: str, key: str) -> int | None:
        """Delete a namespaced key"""
        if not self.config.enable_redis:
            return None

        async def _delete(conn: Redis) -> int:
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            delete_result = await conn.delete(full_key)
            return int(delete_result) if delete_result is not None else 0

        result = await self.safe_operation(_delete)
        return int(result) if result is not None else 0

    async def keys(self, pattern: str) -> list[str] | None:
        """Get keys matching a pattern"""
        if not self.config.enable_redis:
            return None

        async def _keys(conn: Redis) -> list[str]:
            full_pattern = f"{self.config.redis_prefix}{pattern}"
            keys = await conn.keys(full_pattern)
            return [str(k) for k in keys] if keys else []

        result = await self.safe_operation(_keys)
        return result if result is not None else []

    async def delete_pattern(self, pattern: str) -> int | None:
        """Delete all keys matching a pattern"""
        if not self.config.enable_redis:
            return None

        async def _delete_pattern(conn: Redis) -> int:
            full_pattern = f"{self.config.redis_prefix}{pattern}"
            keys = await conn.keys(full_pattern)
            if not keys:
                return 0
            result = await conn.delete(*keys)
            return int(result) if result is not None else 0

        result = await self.safe_operation(_delete_pattern)
        return int(result) if result is not None else 0


redis_handler = RedisManager
