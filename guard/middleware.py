# fastapi_guard/middleware.py
from collections import defaultdict
from fastapi import Request, Response, status
from guard.models import SecurityConfig
from guard.utils import is_ip_allowed, is_user_agent_allowed, log_request, detect_penetration_attempt, log_suspicious_activity
from starlette.middleware.base import BaseHTTPMiddleware
import time



class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        config: SecurityConfig,
        rate_limit: int = 100,
        rate_limit_window: int = 60
    ):
        super().__init__(app)
        self.config = config
        self.rate_limit = rate_limit
        self.rate_limit_window = rate_limit_window
        self.ip_requests = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        client_ip = request.headers.get("X-Forwarded-For", request.client.host)

        log_request(request)

        # Rate limiting
        current_time = time.time()
        self.ip_requests[client_ip] = [timestamp for timestamp in self.ip_requests[client_ip] if current_time - timestamp < self.rate_limit_window]
        if len(self.ip_requests[client_ip]) >= self.rate_limit:
            log_suspicious_activity(request, "Rate limit exceeded")
            return Response("Too Many Requests", status_code=status.HTTP_429_TOO_MANY_REQUESTS)
        self.ip_requests[client_ip].append(current_time)

        # IP whitelist/blacklist
        if not is_ip_allowed(client_ip, self.config):
            log_suspicious_activity(request, "IP not allowed")
            return Response("Forbidden", status_code=status.HTTP_403_FORBIDDEN)

        # User-Agent filtering
        user_agent = request.headers.get('user-agent', '')
        if not is_user_agent_allowed(user_agent, self.config):
            log_suspicious_activity(request, "User-Agent not allowed")
            return Response("Forbidden", status_code=status.HTTP_403_FORBIDDEN)

        # Penetration attempts
        if await detect_penetration_attempt(request):
            log_suspicious_activity(request, "Potential attack detected")
            return Response("Potential attack detected", status_code=status.HTTP_400_BAD_REQUEST)

        response = await call_next(request)
        return response