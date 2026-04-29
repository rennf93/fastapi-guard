from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from guard_core import (
    BehaviorRule,
    BehaviorTracker,
    CloudManager,
    GeoIPHandler,
    GuardRequest,
    GuardResponse,
    GuardResponseFactory,
    IPBanManager,
    IPInfoManager,
    RateLimitManager,
    RedisHandlerProtocol,
    RedisManager,
    RouteConfig,
    SecurityConfig,
    SecurityDecorator,
    SecurityHeadersManager,
    cloud_handler,
    ip_ban_manager,
    rate_limit_handler,
    redis_handler,
    security_headers_manager,
    sus_patterns_handler,
)

from guard.middleware import SecurityMiddleware

try:
    __version__ = _pkg_version("fastapi-guard")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = [
    "__version__",
    "SecurityMiddleware",
    "SecurityConfig",
    "SecurityDecorator",
    "RouteConfig",
    "BehaviorTracker",
    "BehaviorRule",
    "ip_ban_manager",
    "IPBanManager",
    "cloud_handler",
    "CloudManager",
    "IPInfoManager",
    "rate_limit_handler",
    "RateLimitManager",
    "redis_handler",
    "RedisManager",
    "security_headers_manager",
    "SecurityHeadersManager",
    "sus_patterns_handler",
    "GeoIPHandler",
    "RedisHandlerProtocol",
    "GuardRequest",
    "GuardResponse",
    "GuardResponseFactory",
]
