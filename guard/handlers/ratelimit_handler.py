# guard/handlers/ratelimit_handler.py
import logging
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Request, Response, status
from redis.exceptions import RedisError

from guard.models import SecurityConfig
from guard.scripts.rate_lua import RATE_LIMIT_SCRIPT
from guard.utils import log_activity


class RateLimitManager:
    """
    Handles rate limiting functionality with in-memory and Redis storage options.
    Implements a true sliding window algorithm with distributed environment support.
    """

    _instance: Optional["RateLimitManager"] = None
    config: SecurityConfig
    request_timestamps: defaultdict[str, deque[float]]
    logger: logging.Logger
    redis_handler: Any = None
    agent_handler: Any = None
    rate_limit_script_sha: str | None = None

    def __new__(
        cls: type["RateLimitManager"], config: SecurityConfig
    ) -> "RateLimitManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = config
            cls._instance.request_timestamps = defaultdict(
                lambda: deque(maxlen=config.rate_limit * 2)
            )
            cls._instance.logger = logging.getLogger("fastapi_guard.handlers.ratelimit")
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.rate_limit_script_sha = None

        cls._instance.config = config
        return cls._instance

    async def initialize_redis(self, redis_handler: Any) -> None:
        """Initialize Redis connection and load Lua scripts"""
        self.redis_handler = redis_handler

        # Load the Lua script
        if self.redis_handler and self.config.enable_redis:
            try:
                async with self.redis_handler.get_connection() as conn:
                    self.rate_limit_script_sha = await conn.script_load(
                        RATE_LIMIT_SCRIPT
                    )
                    self.logger.info("Rate limiting Lua script loaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to load rate limiting Lua script: {str(e)}")
                # Fallback to non-Lua implementation

    async def initialize_agent(self, agent_handler: Any) -> None:
        """Initialize agent integration."""
        self.agent_handler = agent_handler

    async def check_rate_limit(
        self,
        request: Request,
        client_ip: str,
        create_error_response: Callable[[int, str], Awaitable[Response]],
    ) -> Response | None:
        """
        Check if the client IP has exceeded rate limits using a sliding window.
        Optimized for distributed environments with atomic operations.

        Args:
            request: The incoming request
            client_ip: The client's IP address
            create_error_response: Function to create error responses

        Returns:
            Response if rate limit is exceeded, otherwise None
        """
        if not self.config.enable_rate_limiting:
            return None

        current_time = time.time()
        window_start = current_time - self.config.rate_limit_window

        # Redis implementation
        if self.config.enable_redis and self.redis_handler:
            rate_key = f"rate:{client_ip}"
            key_name = f"{self.redis_handler.config.redis_prefix}rate_limit:{rate_key}"

            try:
                # Atomic Lua Script
                if self.rate_limit_script_sha:
                    async with self.redis_handler.get_connection() as conn:
                        count = await conn.evalsha(
                            self.rate_limit_script_sha,
                            1,  # NOTE: Number of keys
                            key_name,  # NOTE: The key
                            current_time,  # NOTE: Current timestamp
                            self.config.rate_limit_window,  # NOTE: Window size
                            self.config.rate_limit,  # NOTE: Rate limit
                        )
                else:
                    # Fallback to pipeline
                    async with self.redis_handler.get_connection() as conn:
                        pipeline = conn.pipeline()
                        pipeline.zadd(key_name, {str(current_time): current_time})
                        pipeline.zremrangebyscore(key_name, 0, window_start)
                        pipeline.zcard(key_name)
                        pipeline.expire(key_name, self.config.rate_limit_window * 2)
                        results = await pipeline.execute()
                        count = results[2]  # NOTE: ZCARD operation count

                # Check exceeded limit
                if count and count > self.config.rate_limit:
                    message = "Rate limit exceeded for IP:"
                    detail = f"requests in {self.config.rate_limit_window}s window)"
                    await log_activity(
                        request,
                        self.logger,
                        log_type="suspicious",
                        reason=f"{message} {client_ip} ({count} {detail})",
                        level=self.config.log_suspicious_level,
                        passive_mode=self.config.passive_mode,
                    )

                    # Send event to agent
                    if self.agent_handler:
                        await self._send_rate_limit_event(request, client_ip, count)

                    return await create_error_response(
                        status.HTTP_429_TOO_MANY_REQUESTS,
                        "Too many requests",
                    )
            except RedisError as e:
                self.logger.error(f"Redis rate limiting error: {str(e)}")
                self.logger.info("Falling back to in-memory rate limiting")
                # In-memory fallback
            except Exception as e:
                self.logger.error(f"Unexpected error in rate limiting: {str(e)}")
                # In-memory fallback

            return None

        # In-memory Fallback
        # Cleanup old requests
        while (
            self.request_timestamps[client_ip]
            and self.request_timestamps[client_ip][0] <= window_start
        ):
            self.request_timestamps[client_ip].popleft()

        # Count requests within the window
        request_count = len(self.request_timestamps[client_ip])

        # Current TS to deque
        self.request_timestamps[client_ip].append(current_time)

        # Check exceeded limit
        if request_count >= self.config.rate_limit:
            message = "Rate limit exceeded for IP:"
            detail = f"requests in {self.config.rate_limit_window}s window)"
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"{message} {client_ip} ({request_count + 1} {detail})",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )

            # Send event to agent
            if self.agent_handler:
                await self._send_rate_limit_event(request, client_ip, request_count + 1)

            return await create_error_response(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Too many requests",
            )

        return None

    async def _send_rate_limit_event(
        self, request: Request, client_ip: str, request_count: int
    ) -> None:
        """Send rate limit event to agent."""
        try:
            message = "Rate limit exceeded"
            details = (
                f"{request_count} requests in {self.config.rate_limit_window}s window"
            )

            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="rate_limited",
                ip_address=client_ip,
                action_taken="request_blocked",
                reason=f"{message}: {details}",
                endpoint=str(request.url.path),
                method=request.method,
                metadata={
                    "request_count": request_count,
                    "rate_limit": self.config.rate_limit,
                    "window": self.config.rate_limit_window,
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            # Don't let agent errors break rate limiting
            self.logger.error(f"Failed to send rate limit event to agent: {e}")

    async def reset(self) -> None:
        """Reset all rate limit data"""
        self.request_timestamps.clear()

        if self.config.enable_redis and self.redis_handler:
            try:
                keys = await self.redis_handler.keys("rate_limit:rate:*")
                if keys and len(keys) > 0:
                    await self.redis_handler.delete_pattern("rate_limit:rate:*")
            except Exception as e:
                self.logger.error(f"Failed to reset Redis rate limits: {str(e)}")


# Instance
rate_limit_handler = RateLimitManager
