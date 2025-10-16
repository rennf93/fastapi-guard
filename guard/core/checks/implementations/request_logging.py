# guard/core/checks/implementations/request_logging.py
from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck
from guard.utils import log_activity


class RequestLoggingCheck(SecurityCheck):
    """Log incoming requests."""

    @property
    def check_name(self) -> str:
        return "request_logging"

    async def check(self, request: Request) -> Response | None:
        """Log the request."""
        await log_activity(request, self.logger, level=self.config.log_request_level)
        return None
