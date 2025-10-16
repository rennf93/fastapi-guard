# guard/core/checks/implementations/route_config.py
from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck
from guard.utils import extract_client_ip


class RouteConfigCheck(SecurityCheck):
    """
    Extracts and attaches route configuration to request state.

    This is not a blocking check, but prepares context for other checks.
    """

    @property
    def check_name(self) -> str:
        return "route_config"

    async def check(self, request: Request) -> Response | None:
        """Extract route config and attach to request state."""
        route_config = self.middleware.route_resolver.get_route_config(request)
        # Store in request state for other checks to access
        request.state.route_config = route_config
        request.state.client_ip = await extract_client_ip(
            request, self.config, self.middleware.agent_handler
        )
        return None
