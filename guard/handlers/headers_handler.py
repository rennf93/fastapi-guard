from datetime import datetime, timezone
from typing import Any

from guard.models import SecurityConfig


class SecurityHeadersManager:
    """
    Singleton manager that builds security headers based on `SecurityConfig`.
    """

    _instance: "SecurityHeadersManager | None" = None
    redis_handler: Any = None
    agent_handler: Any = None

    def __new__(cls: type["SecurityHeadersManager"]) -> "SecurityHeadersManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
        return cls._instance

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    async def initialize_agent(self, agent_handler: Any) -> None:
        self.agent_handler = agent_handler

    def get_headers(self, config: SecurityConfig) -> dict[str, str]:
        """
        Build the security headers dictionary from SecurityConfig.
        """
        headers: dict[str, str] = {}

        # Content Security Policy
        if config.csp_directives:
            headers["content-security-policy"] = self._build_csp(config.csp_directives)

        # HTTP Strict Transport Security
        headers["strict-transport-security"] = (
            f"max-age={config.hsts_max_age}; includeSubDomains"
        )

        # X-Frame-Options
        headers["x-frame-options"] = config.frame_options

        # X-Content-Type-Options
        headers["x-content-type-options"] = config.content_type_options

        # X-XSS-Protection
        headers["x-xss-protection"] = config.xss_protection

        # Referrer-Policy
        headers["referrer-policy"] = config.referrer_policy

        # Permissions Policy
        if config.permissions_policy:
            headers["permissions-policy"] = self._build_permissions_policy(
                config.permissions_policy
            )

        # Cross-Origin Policies
        headers["cross-origin-opener-policy"] = config.cross_origin_opener_policy
        headers["cross-origin-resource-policy"] = config.cross_origin_resource_policy
        headers["cross-origin-embedder-policy"] = config.cross_origin_embedder_policy

        return headers

    def _build_csp(self, csp: dict[str, list[str]]) -> str:
        return "; ".join(
            f"{directive} {' '.join(sources)}" for directive, sources in csp.items()
        )

    def _build_permissions_policy(self, policy: dict[str, list[str]]) -> str:
        def format_values(values: list[str]) -> str:
            if not values or (len(values) == 1 and values[0].strip("'\" ").lower() == "none"):
                return "()"
            return f"({' '.join(values)})"

        return ", ".join(
            f"{feature}={format_values(values)}" for feature, values in policy.items()
        )

    async def send_header_event(
        self, event_type: str, action_taken: str, reason: str, **kwargs: Any
    ) -> None:
        """
        Optional: send header-related telemetry to the agent.
        """
        if not self.agent_handler:
            return
        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address="system",
                action_taken=action_taken,
                reason=reason,
                metadata=kwargs,
            )
            await self.agent_handler.send_event(event)
        except Exception:
            # Best-effort, never break response path
            pass


# Instance
headers_handler = SecurityHeadersManager()


