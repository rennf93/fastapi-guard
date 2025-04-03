# fastapi_guard/middleware.py
import logging
import time
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ipban_handler import ip_ban_manager
from guard.handlers.ipinfo_handler import IPInfoManager
from guard.handlers.ratelimit_handler import RateLimitManager
from guard.handlers.suspatterns_handler import sus_patterns_handler
from guard.models import SecurityConfig
from guard.utils import (
    detect_penetration_attempt,
    is_ip_allowed,
    is_user_agent_allowed,
    log_request,
    log_suspicious_activity,
    setup_custom_logging,
)


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware for implementing various
    security measures in a FastAPI application.

    This middleware handles rate limiting,
    IP filtering, user agent filtering,
    and detection of potential
    penetration attempts.
    """

    def __init__(self, app: FastAPI, config: SecurityConfig):
        """
        Initialize the SecurityMiddleware.

        Args:
            app (FastAPI):
                The FastAPI application.
            config (SecurityConfig):
                Configuration object for security settings.
        """
        super().__init__(app)
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, int] = {}
        self.last_cleanup = time.time()
        self.ipinfo_db = IPInfoManager(
            token=config.ipinfo_token, db_path=config.ipinfo_db_path
        )
        self.rate_limit_handler = RateLimitManager(config)

        # Initialize Redis handler if enabled
        self.redis_handler = None
        if config.enable_redis:
            from guard.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(config)

    async def setup_logger(self) -> None:
        self.logger = await setup_custom_logging("security.log")

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
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
        if self.config.enforce_https and request.url.scheme == "http":
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(
                https_url, status_code=status.HTTP_301_MOVED_PERMANENTLY
            )

        if not request.client:
            return await call_next(request)

        client_ip = (
            request.headers.get("X-Forwarded-For", request.client.host)
            .split(",")[0]
            .strip()
        )

        # Excluded paths
        if any(request.url.path.startswith(path) for path in self.config.exclude_paths):
            return await call_next(request)

        # Log request
        await log_request(request, self.logger)

        # Refresh cloud IP ranges
        if (
            self.config.block_cloud_providers
            and time.time() - self.last_cloud_ip_refresh > 3600
        ):
            await self.refresh_cloud_ip_ranges()

        # IP banning
        if await ip_ban_manager.is_ip_banned(client_ip):
            await log_suspicious_activity(
                request, f"Banned IP attempted access: {client_ip}", self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="IP address banned",
            )

        # Whitelist/blacklist
        if not await is_ip_allowed(client_ip, self.config):
            await log_suspicious_activity(
                request, f"IP not allowed: {client_ip}", self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN, default_message="Forbidden"
            )

        # Cloud providers
        if self.config.block_cloud_providers and cloud_handler.is_cloud_ip(
            client_ip, self.config.block_cloud_providers
        ):
            await log_suspicious_activity(
                request, f"Blocked cloud provider IP: {client_ip}", self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Cloud provider IP not allowed",
            )

        # User agent
        user_agent = request.headers.get("User-Agent", "")
        if not await is_user_agent_allowed(user_agent, self.config):
            await log_suspicious_activity(
                request, f"Blocked user agent: {user_agent}", self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="User-Agent not allowed",
            )

        # Rate limit
        rate_limit_response = await self.rate_limit_handler.check_rate_limit(
            request, client_ip, self.create_error_response
        )
        if rate_limit_response:
            return rate_limit_response

        # Sus Activity
        if self.config.enable_penetration_detection:
            if await detect_penetration_attempt(request):
                self.suspicious_request_counts[client_ip] = (
                    self.suspicious_request_counts.get(client_ip, 0) + 1
                )

                # Check banning
                if (
                    self.config.enable_ip_banning
                    and self.suspicious_request_counts[client_ip]
                    >= self.config.auto_ban_threshold
                ):
                    await ip_ban_manager.ban_ip(
                        client_ip, self.config.auto_ban_duration
                    )
                    await log_suspicious_activity(
                        request,
                        f"IP banned due to suspicious activity: {client_ip}",
                        self.logger,
                    )
                    return await self.create_error_response(
                        status_code=status.HTTP_403_FORBIDDEN,
                        default_message="IP has been banned",
                    )

                await log_suspicious_activity(
                    request,
                    f"Suspicious activity detected for IP: {client_ip}",
                    self.logger,
                )
                return await self.create_error_response(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    default_message="Suspicious activity detected",
                )

        # Custom request
        if self.config.custom_request_check:
            custom_response = await self.config.custom_request_check(request)
            if custom_response:
                return custom_response

        return await call_next(request)

    async def refresh_cloud_ip_ranges(self) -> None:
        """Refresh cloud IP ranges asynchronously."""
        if self.config.enable_redis and self.redis_handler:
            await cloud_handler.refresh_async()
        else:
            cloud_handler.refresh()
        self.last_cloud_ip_refresh = int(time.time())

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> Response:
        custom_message = self.config.custom_error_responses.get(
            status_code, default_message
        )
        return Response(custom_message, status_code=status_code)

    async def reset(self) -> None:
        await self.rate_limit_handler.reset()

    @staticmethod
    def configure_cors(app: FastAPI, config: SecurityConfig) -> bool:
        """
        Configure FastAPI's CORS middleware
        based on SecurityConfig.
        """
        if config.enable_cors:
            cors_params = {
                "allow_origins": config.cors_allow_origins,
                "allow_methods": config.cors_allow_methods,
                "allow_headers": config.cors_allow_headers,
                "allow_credentials": config.cors_allow_credentials,
                "max_age": config.cors_max_age,
            }

            if config.cors_expose_headers:
                cors_params["expose_headers"] = config.cors_expose_headers

            app.add_middleware(CORSMiddleware, **cors_params)
            return True
        return False

    async def initialize(self) -> None:
        """Initialize all components asynchronously"""
        if self.config.enable_redis and self.redis_handler:
            await self.redis_handler.initialize()
            await cloud_handler.initialize_redis(self.redis_handler)
            await ip_ban_manager.initialize_redis(self.redis_handler)
            await self.ipinfo_db.initialize_redis(self.redis_handler)
            await self.rate_limit_handler.initialize_redis(self.redis_handler)
            await sus_patterns_handler.initialize_redis(self.redis_handler)
            await cloud_handler.refresh_async()
