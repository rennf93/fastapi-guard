import asyncio
from contextlib import asynccontextmanager
from fastapi import HTTPException, status
from guard.models import SecurityConfig
import logging
from redis.asyncio import Redis
from redis.exceptions import ConnectionError
from typing import Any, Optional


class RedisManager:
    """
    Robust Redis handler with connection pooling and automatic reconnection.
    """

    _instance = None
    _redis: Optional[Redis] = None
    _connection_lock = asyncio.Lock()
    _closed = False

    def __new__(cls, config: SecurityConfig):
        cls._instance = super(RedisManager, cls).__new__(cls)
        cls._instance.config = config
        cls._instance.logger = logging.getLogger(__name__)
        cls._instance._closed = False
        return cls._instance

    async def initialize(self):
        """Initialize Redis connection with retry logic"""
        if self._closed or not self.config.enable_redis:
            self._redis = None
            return

        async with self._connection_lock:
            try:
                self._redis = Redis.from_url(
                    self.config.redis_url,
                    decode_responses=True
                )
                await self._redis.ping()
                self.logger.info("Redis connection established")

            except Exception as e:
                self.logger.error(f"Redis connection failed: {str(e)}")
                self._redis = None
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Redis connection failed"
                )

    async def close(self):
        """Close Redis connection properly"""
        if self._redis:
            await self._redis.aclose()
            self._redis = None
            self.logger.info("Redis connection closed")
        self._closed = True

    @asynccontextmanager
    async def get_connection(self):
        """Context manager for safe Redis operations"""
        try:
            if self._closed:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Redis connection closed"
                )

            if not self._redis:
                await self.initialize()

            yield self._redis
        except (ConnectionError, AttributeError) as e:
            self.logger.error(f"Redis operation failed: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Redis connection failed"
            )

    async def safe_operation(self, func, *args, **kwargs):
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
                detail="Redis operation failed"
            )

    # Atomic operations
    async def get_key(self, namespace: str, key: str) -> Any:
        """Get a value from Redis with proper namespacing"""
        async def _get(conn):
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return await conn.get(full_key)
        return await self.safe_operation(_get)

    async def set_key(
        self,
        namespace: str,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ) -> bool:
        """Set a value in Redis with proper namespacing"""
        async def _set(conn):
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            if ttl:
                return await conn.setex(full_key, ttl, value)
            return await conn.set(full_key, value)
        return await self.safe_operation(_set)

    async def incr(
        self,
        namespace: str,
        key: str,
        ttl: Optional[int] = None
    ) -> int:
        """Atomic increment with namespacing"""
        async def _incr(conn):
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            async with conn.pipeline() as pipe:
                await pipe.incr(full_key)
                if ttl:
                    await pipe.expire(full_key, ttl)
                result = await pipe.execute()
                return result[0]
        return await self.safe_operation(_incr)

    async def exists(self, namespace: str, key: str) -> bool:
        """Check if a namespaced key exists"""
        async def _exists(conn):
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return bool(await conn.exists(full_key))
        return await self.safe_operation(_exists)

    async def delete(self, namespace: str, key: str) -> int:
        """Delete a namespaced key"""
        async def _delete(conn):
            full_key = f"{self.config.redis_prefix}{namespace}:{key}"
            return await conn.delete(full_key)
        return await self.safe_operation(_delete)


redis_handler = RedisManager
