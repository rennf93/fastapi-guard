# guard/decorators/access_control.py
from collections.abc import Callable
from typing import Any

from guard.decorators.base import BaseSecurityMixin


class AccessControlMixin(BaseSecurityMixin):
    """Mixin for access control decorators."""

    def require_ip(
        self,
        whitelist: list[str] | None = None,
        blacklist: list[str] | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Require specific IP addresses or ranges."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            if whitelist:
                route_config.ip_whitelist = whitelist
            if blacklist:
                route_config.ip_blacklist = blacklist
            return self._apply_route_config(func)

        return decorator

    def block_countries(
        self, countries: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Block access from specific countries."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.blocked_countries = countries
            return self._apply_route_config(func)

        return decorator

    def allow_countries(
        self, countries: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Only allow access from specific countries."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.whitelist_countries = countries
            return self._apply_route_config(func)

        return decorator

    def block_clouds(
        self, providers: list[str] | None = None
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
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

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            if providers is None:
                route_config.block_cloud_providers = {"AWS", "GCP", "Azure"}
            else:
                route_config.block_cloud_providers = set(providers)
            return self._apply_route_config(func)

        return decorator

    def bypass(
        self, checks: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Bypass specific security checks for this route."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.bypassed_checks.update(checks)
            return self._apply_route_config(func)

        return decorator
