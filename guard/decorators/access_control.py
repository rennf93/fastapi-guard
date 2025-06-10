from collections.abc import Callable


class AccessControlMixin:
    """Mixin for access control decorators."""

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
            return self._apply_route_config(func)

        return decorator

    def block_countries(self, countries: list[str]):
        """Block access from specific countries."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.blocked_countries = countries
            return self._apply_route_config(func)

        return decorator

    def allow_countries(self, countries: list[str]):
        """Only allow access from specific countries."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.allowed_countries = countries
            return self._apply_route_config(func)

        return decorator

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
            return self._apply_route_config(func)

        return decorator

    def bypass(self, checks: list[str]):
        """Bypass specific security checks for this route."""

        def decorator(func: Callable) -> Callable:
            route_config = self._ensure_route_config(func)
            route_config.bypassed_checks.update(checks)
            return self._apply_route_config(func)

        return decorator
