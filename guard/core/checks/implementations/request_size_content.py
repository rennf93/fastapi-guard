# guard/core/checks/implementations/request_size_content.py
from fastapi import Request, Response, status

from guard.core.checks.base import SecurityCheck
from guard.decorators.base import RouteConfig
from guard.utils import log_activity


class RequestSizeContentCheck(SecurityCheck):
    """Check request size and content type restrictions."""

    @property
    def check_name(self) -> str:
        return "request_size_content"

    async def _check_request_size_limit(
        self, request: Request, route_config: RouteConfig
    ) -> Response | None:
        """Check if request size exceeds configured limit."""
        if not route_config.max_request_size:
            return None

        content_length = request.headers.get("content-length")
        if not content_length or int(content_length) <= route_config.max_request_size:
            return None

        # Request size exceeds limit
        message = f"Request size {content_length} exceeds limit"

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"{message}: {route_config.max_request_size}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        await self.middleware.event_bus.send_middleware_event(
            event_type="content_filtered",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"{message}: {route_config.max_request_size}",
            decorator_type="content_filtering",
            violation_type="max_request_size",
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                default_message="Request too large",
            )

        return None

    async def _check_content_type_allowed(
        self, request: Request, route_config: RouteConfig
    ) -> Response | None:
        """Check if content type is in allowed list."""
        if not route_config.allowed_content_types:
            return None

        content_type = request.headers.get("content-type", "").split(";")[0]
        if content_type in route_config.allowed_content_types:
            return None

        # Content type not allowed
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Invalid content type: {content_type}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        message = f"Content type {content_type} not in allowed types"

        await self.middleware.event_bus.send_middleware_event(
            event_type="content_filtered",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"{message}: {route_config.allowed_content_types}",
            decorator_type="content_filtering",
            violation_type="content_type",
        )

        if not self.config.passive_mode:
            return await self.middleware.create_error_response(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                default_message="Unsupported content type",
            )

        return None

    async def check(self, request: Request) -> Response | None:
        """Check request size and content type restrictions."""
        route_config = getattr(request.state, "route_config", None)

        if not route_config:
            return None

        # Check request size limit
        size_response = await self._check_request_size_limit(request, route_config)
        if size_response:
            return size_response

        # Check content type allowed
        return await self._check_content_type_allowed(request, route_config)
