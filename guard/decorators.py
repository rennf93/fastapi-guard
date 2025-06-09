from collections.abc import Callable

from fastapi import Request, Response

from guard.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard.models import SecurityConfig


class RouteConfig:
    """Per-route security configuration that can override global settings."""

    def __init__(self):
        self.rate_limit: int | None = None
        self.rate_limit_window: int | None = None
        self.ip_whitelist: list[str] | None = None
        self.ip_blacklist: list[str] | None = None
        self.blocked_countries: list[str] | None = None
        self.allowed_countries: list[str] | None = None
        self.bypassed_checks: set[str] = set()
        self.require_https: bool = False
        self.auth_required: str | None = None
        self.custom_validators: list[Callable] = []
        self.blocked_user_agents: list[str] = []
        self.required_headers: dict[str, str] = {}
        # New behavioral analysis fields
        self.behavior_rules: list[BehaviorRule] = []
        # Additional security fields
        self.block_cloud_providers: set[str] = set()
        self.max_request_size: int | None = None
        self.allowed_content_types: list[str] | None = None
        self.time_restrictions: dict[str, str] | None = None
        self.enable_suspicious_detection: bool = True
        self.require_referrer: list[str] | None = None
        self.api_key_required: bool = False
        self.session_limits: dict[str, int] | None = None


class SecurityDecorator:
    """Main decorator class for FastAPI Guard route-level security."""

    def __init__(self, config: SecurityConfig):
        self.config = config
        self._route_configs: dict[str, RouteConfig] = {}
        self.behavior_tracker = BehaviorTracker(config)

    def get_route_config(self, route_id: str) -> RouteConfig | None:
        """Get security config for a specific route."""
        return self._route_configs.get(route_id)

    def _get_route_id(self, func: Callable) -> str:
        """Generate a unique route identifier."""
        return f"{func.__module__}.{func.__qualname__}"

    def _ensure_route_config(self, func: Callable) -> RouteConfig:
        """Ensure a route config exists for the function."""
        route_id = self._get_route_id(func)
        if route_id not in self._route_configs:
            self._route_configs[route_id] = RouteConfig()
        return self._route_configs[route_id]

    def rate_limit(self, requests: int, window: int = 60):
        """Apply custom rate limiting to a specific route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.rate_limit = requests
            route_config.rate_limit_window = window

            # Store route config reference on the function
            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def require_ip(
        self,
        whitelist: list[str] | None = None,
        blacklist: list[str] | None = None,
    ):
        """Require specific IP addresses or ranges."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            if whitelist:
                route_config.ip_whitelist = whitelist
            if blacklist:
                route_config.ip_blacklist = blacklist

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def block_countries(self, countries: list[str]):
        """Block access from specific countries."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.blocked_countries = countries

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def allow_countries(self, countries: list[str]):
        """Only allow access from specific countries."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.allowed_countries = countries

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def bypass(self, checks: list[str]):
        """Bypass specific security checks for this route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.bypassed_checks.update(checks)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def require_https(self):
        """Force HTTPS for this specific route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.require_https = True

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def require_auth(self, type: str = "bearer"):
        """Require authentication for this route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.auth_required = type

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def custom_validation(
        self,
        validator: Callable[[Request], Response | None],
    ):
        """Add custom validation logic to this route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(validator)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def block_user_agents(self, patterns: list[str]):
        """Block specific user agent patterns for this route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.blocked_user_agents.extend(patterns)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def require_headers(self, headers: dict[str, str]):
        """Require specific headers to be present."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.required_headers.update(headers)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    # NEW BEHAVIORAL ANALYSIS DECORATORS

    def usage_monitor(
        self,
        max_calls: int,
        window: int = 3600,  # 1 hour default
        action: str = "ban",
    ):
        """
        Monitor endpoint usage per IP and take action if threshold exceeded.

        Args:
            max_calls: Maximum number of calls allowed from same IP
            window: Time window in seconds (default: 1 hour)
            action: Action to take ("ban", "log", "throttle", "alert")

        Example:
            @guard_decorator.usage_monitor(
                max_calls=8,
                window=3600,
                action="ban",
            )
            def sensitive_endpoint():
                return {"data": "sensitive"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)

            rule = BehaviorRule(
                rule_type="usage", threshold=max_calls, window=window, action=action
            )
            route_config.behavior_rules.append(rule)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def return_monitor(
        self,
        pattern: str,
        max_occurrences: int,
        window: int = 86400,  # 24 hours default
        action: str = "ban",
    ):
        """
        Monitor return values and detect if same IP gets specific results too often.

        Args:
            pattern: Pattern to match in response (supports various formats)
            max_occurrences: Maximum times pattern can occur for same IP
            window: Time window in seconds (default: 24 hours)
            action: Action to take when threshold exceeded

        Pattern formats:
            - Simple string: "win", "success", "rare_item"
            - JSON path: "json:result.status==win"
            - Regex: "regex:win|victory|success"
            - Status code: "status:200"

        Example:
            @guard_decorator.return_monitor(
                "win",
                max_occurrences=3,
                window=86400,
                action="ban",
            )
            def lootbox_endpoint():
                return {"result": {"status": "win", "item": "rare_sword"}}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)

            rule = BehaviorRule(
                rule_type="return_pattern",
                threshold=max_occurrences,
                window=window,
                pattern=pattern,
                action=action,
            )
            route_config.behavior_rules.append(rule)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def behavior_analysis(self, rules: list[BehaviorRule]):
        """
        Apply multiple behavioral analysis rules to an endpoint.

        Args:
            rules: List of BehaviorRule objects defining analysis rules

        Example:
            rules = [
                BehaviorRule("usage", threshold=10, window=3600),
                BehaviorRule(
                    "return_pattern",
                    threshold=3,
                    pattern="win",
                    window=86400,
                )
            ]
            @guard_decorator.behavior_analysis(rules)
            def complex_endpoint():
                return {"result": "data"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.behavior_rules.extend(rules)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def suspicious_frequency(
        self,
        max_frequency: float,  # requests per second
        window: int = 300,  # 5 minutes
        action: str = "ban",
    ):
        """
        Detect suspiciously high frequency of requests to specific endpoint.

        Args:
            max_frequency: Maximum requests per second allowed
            window: Time window to analyze
            action: Action to take when exceeded

        Example:
            @guard_decorator.suspicious_frequency(
                max_frequency=0.1,
                window=300,
            )  # Max 1 request per 10 seconds
            def expensive_operation():
                return {"result": "computed"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)

            # Convert frequency to call count within window
            max_calls = int(max_frequency * window)

            rule = BehaviorRule(
                rule_type="frequency",
                threshold=max_calls,
                window=window,
                action=action,
            )
            route_config.behavior_rules.append(rule)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    # NEW COMMON USE CASE DECORATORS

    def block_clouds(self, providers: list[str] | None = None):
        """
        Block requests from cloud providers (leverages existing cloud_handler).

        Args:
            providers: List of cloud providers to block ["AWS", "GCP", "Azure"]
                      If None, blocks all supported providers

        Example:
            @guard_decorator.block_clouds(["AWS", "GCP"])  # Block AWS and GCP
            def sensitive_api():
                return {"data": "no clouds allowed"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            if providers is None:
                route_config.block_cloud_providers = {"AWS", "GCP", "Azure"}
            else:
                route_config.block_cloud_providers = set(providers)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def max_request_size(self, size_bytes: int):
        """
        Limit request body size for this endpoint.

        Args:
            size_bytes: Maximum request size in bytes

        Example:
            @guard_decorator.max_request_size(1024 * 1024)  # 1MB limit
            def upload_endpoint():
                return {"status": "uploaded"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.max_request_size = size_bytes

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def time_window(self, start_time: str, end_time: str, timezone: str = "UTC"):
        """
        Restrict access to specific time windows.

        Args:
            start_time: Start time in HH:MM format
            end_time: End time in HH:MM format
            timezone: Timezone (default: UTC)

        Example:
            # NOTE: Business hours only
            @guard_decorator.time_window("09:00", "17:00", "UTC")
            def business_api():
                return {"message": "business hours only"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.time_restrictions = {
                "start": start_time,
                "end": end_time,
                "timezone": timezone,
            }

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def suspicious_detection(self, enabled: bool = True):
        """
        Enable/disable suspicious pattern detection (leverages sus_patterns_handler).

        Args:
            enabled: Whether to enable suspicious pattern detection

        Example:
            # NOTE: Disable for this endpoint
            @guard_decorator.suspicious_detection(enabled=False)
            def upload_endpoint():
                return {"status": "upload safe"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.enable_suspicious_detection = enabled

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def content_type_filter(self, allowed_types: list[str]):
        """
        Restrict allowed content types for this endpoint.

        Args:
            allowed_types: List of allowed MIME types

        Example:
            @guard_decorator.content_type_filter(["application/json", "text/plain"])
            def api_endpoint():
                return {"message": "json or text only"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.allowed_content_types = allowed_types

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def require_referrer(self, allowed_domains: list[str]):
        """
        Require requests to come from specific referrer domains.

        Args:
            allowed_domains: List of allowed referrer domains

        Example:
            @guard_decorator.require_referrer(["example.com", "app.example.com"])
            def api_endpoint():
                return {"message": "referrer validated"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.require_referrer = allowed_domains

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def api_key_auth(self, header_name: str = "X-API-Key"):
        """
        Require API key authentication for this endpoint.

        Args:
            header_name: Name of the header containing the API key

        Example:
            @guard_decorator.api_key_auth("X-API-Key")
            def protected_endpoint():
                return {"data": "api key required"}
        """

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.api_key_required = True
            route_config.required_headers[header_name] = "required"

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def honeypot_detection(self, trap_fields: list[str]):
        """
        Detect bots using honeypot fields that humans shouldn't fill.

        Args:
            trap_fields: List of field names that should remain empty

        Example:
            @guard_decorator.honeypot_detection(["bot_trap", "hidden_field"])
            def form_endpoint():
                return {"message": "human verified"}
        """

        def decorator(func: Callable) -> Callable:
            async def honeypot_validator(request: Request) -> Response | None:
                try:
                    if request.method in ["POST", "PUT", "PATCH"]:
                        # Check form data
                        if "application/x-www-form-urlencoded" in request.headers.get(
                            "content-type", ""
                        ):
                            form = await request.form()
                            for field in trap_fields:
                                if field in form and form[field]:
                                    return Response("Forbidden", status_code=403)

                        # Check JSON data
                        elif "application/json" in request.headers.get(
                            "content-type", ""
                        ):
                            try:
                                json_data = await request.json()
                                for field in trap_fields:
                                    if field in json_data and json_data[field]:
                                        return Response("Forbidden", status_code=403)
                            except Exception:
                                pass
                except Exception:
                    pass
                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(honeypot_validator)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    def geo_rate_limit(self, limits: dict[str, tuple[int, int]]):
        """
        Apply different rate limits based on country.

        Args:
            limits: Dict mapping country codes to (requests, window) tuples

        Example:
            @guard_decorator.geo_rate_limit({
                "US": (100, 3600),  # 100 requests/hour for US
                "CN": (10, 3600),   # 10 requests/hour for China
                "*": (50, 3600)     # 50 requests/hour for others
            })
            def api_endpoint():
                return {"data": "geo-limited"}
        """

        def decorator(func: Callable) -> Callable:
            # TODO: This would need integration with existing geo IP handler
            # For now, store the configuration
            route_config = self._ensure_route_config(func)
            route_config.required_headers["geo_rate_limits"] = str(limits)

            func._guard_route_id = self._get_route_id(func)
            return func

        return decorator

    async def initialize_behavior_tracking(self, redis_handler=None):
        """Initialize behavioral tracking with optional Redis backend."""
        if redis_handler:
            await self.behavior_tracker.initialize_redis(redis_handler)


# Helper function to extract route config from FastAPI route
def get_route_decorator_config(
    request: Request, decorator_handler: SecurityDecorator
) -> RouteConfig | None:
    """Extract route security configuration from the current request."""
    if hasattr(request, "scope") and "route" in request.scope:
        route = request.scope["route"]
        if hasattr(route, "endpoint") and hasattr(route.endpoint, "_guard_route_id"):
            route_id = route.endpoint._guard_route_id
            return decorator_handler.get_route_config(route_id)
    return None
