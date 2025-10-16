# guard/core/checks/implementations/cloud_ip_refresh.py
import time

from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck


class CloudIpRefreshCheck(SecurityCheck):
    """Refresh cloud IP ranges periodically."""

    @property
    def check_name(self) -> str:
        return "cloud_ip_refresh"

    async def check(self, request: Request) -> Response | None:
        """Refresh cloud IP ranges if needed."""
        if (
            self.config.block_cloud_providers
            and time.time() - self.middleware.last_cloud_ip_refresh > 3600
        ):
            await self.middleware.refresh_cloud_ip_ranges()
        return None
