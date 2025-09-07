# guard/decorators/__init__.py
from guard.decorators.access_control import AccessControlMixin
from guard.decorators.advanced import AdvancedMixin
from guard.decorators.authentication import AuthenticationMixin
from guard.decorators.base import (
    BaseSecurityDecorator,
    BaseSecurityMixin,
    RouteConfig,
    get_route_decorator_config,
)
from guard.decorators.behavioral import BehavioralMixin
from guard.decorators.content_filtering import ContentFilteringMixin
from guard.decorators.rate_limiting import RateLimitingMixin


class SecurityDecorator(
    BaseSecurityDecorator,
    AccessControlMixin,
    RateLimitingMixin,
    BehavioralMixin,
    AuthenticationMixin,
    ContentFilteringMixin,
    AdvancedMixin,
):
    """
    Main security decorator class that combines
    all security decorator capabilities.

    This class uses multiple inheritance to
    combine all decorator mixins,
    providing a single interface for all
    route-level security features.

    Example:
        config = SecurityConfig()
        guard = SecurityDecorator(config)

        @app.get("/api/sensitive")
        @guard.rate_limit(requests=5, window=300)
        @guard.require_ip(whitelist=["10.0.0.0/8"])
        @guard.block_countries(["CN", "RU"])
        def sensitive_endpoint():
            return {"data": "sensitive"}
    """

    pass


__all__ = [
    "SecurityDecorator",
    "RouteConfig",
    "get_route_decorator_config",
    # Base classes for extending
    "BaseSecurityDecorator",
    "BaseSecurityMixin",
    # Mixins (to create custom decorator classes)
    "AccessControlMixin",
    "RateLimitingMixin",
    "BehavioralMixin",
    "AuthenticationMixin",
    "ContentFilteringMixin",
    "AdvancedMixin",
]
