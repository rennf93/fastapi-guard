# guard/middleware/checks/base.py
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from fastapi import Request, Response

if TYPE_CHECKING:
    from guard.middleware import SecurityMiddleware


class SecurityCheck(ABC):
    """
    Base class for security checks in the middleware pipeline.

    Each security check implements a single security concern and can
    independently block or allow a request to proceed.
    """

    def __init__(self, middleware: "SecurityMiddleware") -> None:
        """
        Initialize the security check.

        Args:
            middleware: Reference to the parent SecurityMiddleware instance
                       for accessing config, handlers, and utilities.
        """
        self.middleware = middleware
        self.config = middleware.config
        self.logger = middleware.logger

    @abstractmethod
    async def check(self, request: Request) -> Response | None:
        """
        Perform the security check on the request.

        Args:
            request: The incoming FastAPI request.

        Returns:
            Response if the check fails and request should be blocked.
            None if the check passes and request should continue.
        """
        pass  # pragma: no cover

    @property
    @abstractmethod
    def check_name(self) -> str:
        """
        Name of this security check for logging and debugging.

        Returns:
            Human-readable name of the check (e.g., "https_enforcement").
        """
        pass  # pragma: no cover

    async def send_event(
        self,
        event_type: str,
        request: Request,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """
        Send a security event to the agent handler if enabled.

        This is a helper method to simplify event sending from checks.

        Args:
            event_type: Type of security event.
            request: The request that triggered the event.
            action_taken: Action taken by the check.
            reason: Reason for the action.
            **kwargs: Additional metadata for the event.
        """
        await self.middleware.event_bus.send_middleware_event(
            event_type=event_type,
            request=request,
            action_taken=action_taken,
            reason=reason,
            **kwargs,
        )

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> Response:
        """
        Create an error response with custom message and security headers.

        Args:
            status_code: HTTP status code for the error.
            default_message: Default error message if no custom message configured.

        Returns:
            Response object with appropriate status and headers.
        """
        return await self.middleware.create_error_response(status_code, default_message)

    def is_passive_mode(self) -> bool:
        """
        Check if middleware is in passive mode (log only, don't block).

        Returns:
            True if passive mode is enabled, False otherwise.
        """
        return self.config.passive_mode
