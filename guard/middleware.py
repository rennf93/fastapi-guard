# fastapi_guard/middleware.py
from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from guard.models import SecurityConfig
from guard.utils import is_ip_allowed, log_request, detect_penetration_attempt



class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        config: SecurityConfig
    ):
        super().__init__(app)
        self.config = config

    async def dispatch(
        self,
        request: Request,
        call_next
    ):
        client_ip = request.client.host

        # IP whitelist/blacklist
        if not is_ip_allowed(client_ip, self.config):
            return Response(
                "Forbidden",
                status_code=status.HTTP_403_FORBIDDEN
            )

        log_request(request)

        # Penetration attempts
        if await detect_penetration_attempt(request):
            return Response(
                "Potential attack detected",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        response = await call_next(request)
        return response
    