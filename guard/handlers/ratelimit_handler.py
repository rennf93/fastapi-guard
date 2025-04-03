import logging
from collections.abc import Awaitable, Callable
from typing import Any, Optional

from cachetools import TTLCache
from fastapi import Request, Response, status

from guard.models import SecurityConfig
from guard.utils import log_suspicious_activity


class RateLimitManager:
    """
    Handles rate limiting functionality with in-memory and Redis storage options.
    """

    _instance: Optional["RateLimitManager"] = None
    config: SecurityConfig
    request_times: TTLCache
    logger: logging.Logger
    redis_handler: Any = None

    def __new__(
        cls: type["RateLimitManager"], config: SecurityConfig
    ) -> "RateLimitManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = config
            cls._instance.request_times = TTLCache(
                maxsize=10000, ttl=config.rate_limit_window
            )
            cls._instance.logger = logging.getLogger(__name__)
            cls._instance.redis_handler = None

        # Update config always
        cls._instance.config = config
        return cls._instance

    async def initialize_redis(self, redis_handler: Any) -> None:
        """Initialize with Redis handler for distributed rate limiting"""
        self.redis_handler = redis_handler

    async def check_rate_limit(
        self,
        request: Request,
        client_ip: str,
        create_error_response: Callable[[int, str], Awaitable[Response]],
    ) -> Response | None:
        """
        Check if the client IP has exceeded rate limits.

        Args:
            request: The incoming request
            client_ip: The client's IP address
            create_error_response: Function to create error responses

        Returns:
            Response if rate limit is exceeded, otherwise None
        """
        if not self.config.enable_rate_limiting:
            return None

        # Redis rate limiting
        if self.config.enable_redis and self.redis_handler:
            rate_key = f"rate:{client_ip}"
            count = await self.redis_handler.incr(
                "rate_limit", rate_key, ttl=self.config.rate_limit_window
            )

            if count and count > self.config.rate_limit:
                await log_suspicious_activity(
                    request, f"Rate limit exceeded for IP: {client_ip}", self.logger
                )
                return await create_error_response(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Too many requests",
                )
            return None

        # In-memory rate limiting
        current_count = self.request_times.get(client_ip, 0)
        self.request_times[client_ip] = current_count + 1

        # Check if limit exceeded
        if current_count >= self.config.rate_limit:
            await log_suspicious_activity(
                request, f"Rate limit exceeded for IP: {client_ip}", self.logger
            )
            return await create_error_response(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many requests",
            )

        return None

    async def reset(self) -> None:
        """Reset all rate limit data"""
        self.request_times.clear()

        # Reset Redis rate limit
        if self.config.enable_redis and self.redis_handler:
            try:
                keys = await self.redis_handler.keys("rate_limit:rate:*")
                if keys and len(keys) > 0:
                    await self.redis_handler.delete_pattern("rate_limit:rate:*")
            except Exception as e:
                self.logger.error(f"Failed to reset Redis rate limits: {str(e)}")


# Instance
rate_limit_handler = RateLimitManager
