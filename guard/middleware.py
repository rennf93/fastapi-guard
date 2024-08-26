# fastapi_guard/middleware.py
import asyncio
from cachetools import TTLCache
from config.ip2.ip2location_config import (
    download_ip2location_database,
    start_periodic_update_check,
)
from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from guard.cloud_ips import cloud_ip_ranges
from guard.models import SecurityConfig
from guard.utils import (
    detect_penetration_attempt,
    ip_ban_manager,
    is_ip_allowed,
    is_user_agent_allowed,
    log_request,
    log_suspicious_activity,
    setup_custom_logging,
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
        app: Callable[[Request], Awaitable[Response]],
        config: SecurityConfig,
        rate_limit: int = 100,
        rate_limit_window: int = 60,
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
        self.request_counts = TTLCache(maxsize=10000, ttl=rate_limit_window)
        self.logger = None
        self.ip_request_counts = TTLCache(maxsize=10000, ttl=3600)
        self.last_cloud_ip_refresh = 0

        if self.config.use_ip2location:
            download_ip2location_database(self.config)
            asyncio.create_task(start_periodic_update_check(self.config))

    async def setup_logger(self):
        if self.logger is None:
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
        client_ip = request.client.host

        if self.config.enforce_https and request.url.scheme == "http":
            https_url = request.url.replace(scheme="https")
            return RedirectResponse(https_url, status_code=301)

        if self.logger is None:
            await self.setup_logger()
        client_ip = (
            request.headers.get("X-Forwarded-For", request.client.host)
            .split(",")[0]
            .strip()
        )

        await log_request(request, self.logger)

        # IP Ban CHECK
        if await ip_ban_manager.is_ip_banned(client_ip):
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="IP address banned",
            )

        # User agent filtering
        user_agent = request.headers.get("User-Agent", "")
        if not await is_user_agent_allowed(user_agent, self.config):
            await log_suspicious_activity(
                request, "User-Agent not allowed", self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="User-Agent not allowed",
            )

        # Rate limiting
        if self.rate_limit:
            current_time = time.time()
            if client_ip not in self.request_counts:
                self.request_counts[client_ip] = 1
            else:
                self.request_counts[client_ip] += 1
                if self.request_counts[client_ip] > self.rate_limit:
                    await log_suspicious_activity(
                        request, f"Rate limit exceeded: {client_ip}", self.logger
                    )
                    return await self.create_error_response(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        default_message="Rate limit exceeded",
                    )

        # IP whitelist/blacklist
        # (only if whitelist or blacklist is not empty)
        if (self.config.whitelist or self.config.blacklist) and not await is_ip_allowed(
            client_ip, self.config
        ):
            await log_suspicious_activity(request, "IP not allowed", self.logger)
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN, default_message="Forbidden"
            )

        # Penetration attempts
        if await detect_penetration_attempt(request):
            await log_suspicious_activity(
                request, "Potential attack detected", self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_400_BAD_REQUEST,
                default_message="Potential attack detected",
            )

        # Custom request check
        if self.config.custom_request_check:
            custom_response = await self.config.custom_request_check(request)
            if custom_response:
                return custom_response

        # Automatic IP ban check
        if client_ip not in self.ip_request_counts:
            self.ip_request_counts[client_ip] = 1
        else:
            self.ip_request_counts[client_ip] += 1
            if self.ip_request_counts[client_ip] > self.config.auto_ban_threshold:
                await ip_ban_manager.ban_ip(client_ip, self.config.auto_ban_duration)
                await log_suspicious_activity(
                    request, f"IP automatically banned: {client_ip}", self.logger
                )
                return await self.create_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    default_message="IP address banned",
                )

        # Refresh cloud IP ranges periodically
        if self.config.block_cloud_providers:
            current_time = time.time()
            if current_time - self.last_cloud_ip_refresh > 86400:
                await self.refresh_cloud_ip_ranges()

            if cloud_ip_ranges.is_cloud_ip(
                client_ip, self.config.block_cloud_providers
            ):
                await log_suspicious_activity(request, "Cloud IP blocked", self.logger)
                return await self.create_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    default_message="Access from cloud IPs is not allowed",
                )

        response = await call_next(request)

        # Custom response modifier
        if self.config.custom_response_modifier:
            response = await self.config.custom_response_modifier(response)

        return response

    async def refresh_cloud_ip_ranges(self):
        await asyncio.to_thread(cloud_ip_ranges.refresh)
        self.last_cloud_ip_refresh = time.time()

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> Response:
        custom_message = self.config.custom_error_responses.get(
            status_code, default_message
        )
        return Response(custom_message, status_code=status_code)

    async def reset(self):
        self.request_counts.clear()
        self.ip_request_counts.clear()

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