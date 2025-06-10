from collections.abc import Callable


class RateLimitingMixin:
    """Mixin for rate limiting decorators."""

    def rate_limit(self, requests: int, window: int = 60):
        """Apply custom rate limiting to a specific route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.rate_limit = requests
            route_config.rate_limit_window = window
            return self._apply_route_config(func)

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
            return self._apply_route_config(func)

        return decorator
