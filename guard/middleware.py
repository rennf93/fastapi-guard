# fastapi_guard/middleware.py
from collections import defaultdict
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
from typing import Dict, List, Callable, Awaitable

class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware for implementing various security measures in a FastAPI application.

    This middleware handles rate limiting, IP filtering, user agent filtering,
    and detection of potential penetration attempts.
    """

    def __init__(
        self,
        app: Callable[[Request], Awaitable[Response]],
        config: SecurityConfig,
        rate_limit: int = 100,
        rate_limit_window: int = 60
    ):
        """
        Initialize the SecurityMiddleware.

        Args:
            app (Callable[[Request], Awaitable[Response]]): The FastAPI application.
            config (SecurityConfig): Configuration object for security settings.
            rate_limit (int, optional): Maximum number of requests allowed per IP in the rate limit window. Defaults to 100.
            rate_limit_window (int, optional): Time window in seconds for rate limiting. Defaults to 60.
        """
        super().__init__(app)
        self.config = config
        self.rate_limit = rate_limit
        self.rate_limit_window = rate_limit_window
        self.ip_requests: Dict[str, List[float]] = defaultdict(list)
        self.suspicious_activities: Dict[str, int] = defaultdict(int)
        self.logger = setup_custom_logging(config.custom_log_file or 'requests_digest.log')

    async def dispatch(
        self, request: Request,
        call_next: Callable[
            [Request],
            Awaitable[Response]
        ]
    ) -> Response:
        """
        Dispatch method to handle incoming requests and apply security measures.

        This method implements rate limiting, IP filtering, user agent filtering,
        and detection of potential penetration attempts.

        Args:
            request (Request): The incoming request object.
            call_next (Callable[[Request], Awaitable[Response]]): The next middleware or route handler in the chain.

        Returns:
            Response: The response object, either from the next handler or a security-related response.
        """
        client_ip = request.headers.get(
            "X-Forwarded-For",
            request.client.host
        ).split(',')[0].strip()

        # IP Ban CHECK
        if await ip_ban_manager.is_ip_banned(client_ip):
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="IP address banned"
            )

        await log_request(request, self.logger)

        # Rate limiting
        current_time = time.time()
        self.ip_requests[client_ip] = [t for t in self.ip_requests[client_ip] if current_time - t < self.rate_limit_window]
        self.ip_requests[client_ip].append(current_time)

        if len(self.ip_requests[client_ip]) > self.rate_limit:
            await log_suspicious_activity(
                request,
                "Rate limit exceeded",
                self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                default_message="Too many requests"
            )

        # Increment suspicious activities counter
        self.suspicious_activities[client_ip] += 1

        # Auto IP Ban
        if self.suspicious_activities[client_ip] > self.config.auto_ban_threshold:
            await ip_ban_manager.ban_ip(
                client_ip,
                self.config.auto_ban_duration
            )
            self.logger.warning(
                f"IP {client_ip} automatically banned for {self.config.auto_ban_duration} seconds"
            )
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="IP address banned"
            )

        # IP whitelist/blacklist
        if not await is_ip_allowed(client_ip, self.config):
            await log_suspicious_activity(
                request,
                "IP not allowed",
                self.logger
            )
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Forbidden"
            )

        # User-Agent
        user_agent = request.headers.get('user-agent', '')
        if not await is_user_agent_allowed(user_agent, self.config):
            await log_suspicious_activity(
                request,
                "User-Agent not allowed",
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