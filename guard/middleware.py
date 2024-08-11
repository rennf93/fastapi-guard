# fastapi_guard/middleware.py
import asyncio
from cachetools import TTLCache
from config.ip2.ip2location_config import download_ip2location_database, start_periodic_update_check
from fastapi import Request, Response, status
from guard.models import SecurityConfig
from guard.utils import (
    detect_penetration_attempt,
    ip_ban_manager,
    is_ip_allowed,
    is_user_agent_allowed,
    log_request,
    log_suspicious_activity,
    setup_custom_logging
)
from starlette.middleware.base import BaseHTTPMiddleware
import time
from typing import Callable, Awaitable



class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware for implementing various
    security measures in a FastAPI application.

    This middleware handles rate limiting,
    IP filtering, user agent filtering,
    and detection of potential
    penetration attempts.
    """

    def __init__(
        self,
        app: Callable[
            [Request],
            Awaitable[Response]
        ],
        config: SecurityConfig,
        rate_limit: int = 100,
        rate_limit_window: int = 60
    ):
        """
        Initialize the SecurityMiddleware.

        Args:
            app (Callable[[Request], Awaitable[Response]]):
                The FastAPI application.
            config (SecurityConfig):
                Configuration object for security settings.
            rate_limit (int, optional):
                Maximum number of requests
                allowed per IP in the rate
                limit window. Defaults to 100.
            rate_limit_window (int, optional):
                Time window in
                seconds for rate limiting.
                Defaults to 60.
        """
        super().__init__(app)
        self.config = config
        self.rate_limit = rate_limit
        self.rate_limit_window = rate_limit_window
        self.request_counts = TTLCache(
            maxsize=10000,
            ttl=rate_limit_window
        )
        self.logger = None
        self.ip_request_counts = TTLCache(
            maxsize=10000,
            ttl=3600
        )

        if self.config.use_ip2location:
            download_ip2location_database(self.config)
            asyncio.create_task(start_periodic_update_check(self.config))

    async def setup_logger(self):
        if self.logger is None:
            self.logger = await setup_custom_logging(
                "security.log"
            )

    async def dispatch(
        self, request: Request,
        call_next: Callable[
            [Request],
            Awaitable[Response]
        ]
    ) -> Response:
        """
        Dispatch method to handle incoming
        requests and apply security measures.

        This method implements rate limiting,
        IP filtering, user agent filtering,
        and detection of potential
        penetration attempts.

        Args:
            request (Request):
                The incoming request object.
            call_next (Callable[[Request], Awaitable[Response]]):
                The next middleware or route handler in the chain.

        Returns:
            Response: The response object, either
            from the next handler or a security-related response.
        """
        if self.logger is None:
            await self.setup_logger()
        client_ip = request.headers.get(
            "X-Forwarded-For",
            request.client.host
        ).split(',')[0].strip()

        await log_request(request, self.logger)

        # IP Ban CHECK
        if await ip_ban_manager.is_ip_banned(client_ip):
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="IP address banned"
            )

        # User agent filtering
        user_agent = request.headers.get(
            "User-Agent",
            ""
        )
        if not await is_user_agent_allowed(
            user_agent,
            self.config
        ):
            await log_suspicious_activity(
                request,
                "User-Agent not allowed",
                self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="User-Agent not allowed"
            )

        # Rate limiting
        if self.rate_limit:
            current_time = time.time()
            if client_ip not in self.request_counts:
                self.request_counts[client_ip] = 1
            else:
                self.request_counts[client_ip] += 1
                if self.request_counts[
                    client_ip
                ] > self.rate_limit:
                    await log_suspicious_activity(
                        request,
                        "Rate limit exceeded",
                        self.logger
                    )
                    return await self.create_error_response(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        default_message="Rate limit exceeded"
                    )

        # IP whitelist/blacklist
        # (only if whitelist or blacklist is not empty)
        if (
            self.config.whitelist or self.config.blacklist
        ) and not await is_ip_allowed(
            client_ip, self.config
        ):
            await log_suspicious_activity(
                request,
                "IP not allowed",
                self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Forbidden"
            )

        # Penetration attempts
        if await detect_penetration_attempt(request):
            await log_suspicious_activity(
                request,
                "Potential attack detected",
                self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                default_message="Potential attack detected"
            )

        # Automatic IP ban check
        if client_ip not in self.ip_request_counts:
            self.ip_request_counts[client_ip] = 1
        else:
            self.ip_request_counts[client_ip] += 1
            if self.ip_request_counts[
                client_ip
            ] > self.config.auto_ban_threshold:
                await ip_ban_manager.ban_ip(
                    client_ip,
                    self.config.auto_ban_duration
                )
                await log_suspicious_activity(
                    request,
                    f"IP automatically banned: {client_ip}",
                    self.logger
                )
                return await self.create_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    default_message="IP address banned"
                )

        response = await call_next(request)
        return response

    async def create_error_response(
        self,
        status_code: int,
        default_message: str
    ) -> Response:
        custom_message = self.config.custom_error_responses.get(
            status_code,
            default_message
        )
        return Response(
            custom_message,
            status_code=status_code
        )

    async def reset(self):
        self.request_counts.clear()
        self.ip_request_counts.clear()
