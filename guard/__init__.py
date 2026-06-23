from importlib.metadata import PackageNotFoundError, version as _pkg_version

import guard_core
from guard_core import (
    BehaviorRule as BehaviorRule,
    BehaviorTracker as BehaviorTracker,
    CloudManager as CloudManager,
    GeoIPHandler as GeoIPHandler,
    GuardRequest as GuardRequest,
    GuardResponse as GuardResponse,
    GuardResponseFactory as GuardResponseFactory,
    IPBanManager as IPBanManager,
    IPInfoManager as IPInfoManager,
    RateLimitManager as RateLimitManager,
    RedisHandlerProtocol as RedisHandlerProtocol,
    RedisManager as RedisManager,
    RouteConfig as RouteConfig,
    SecurityConfig as SecurityConfig,
    SecurityDecorator as SecurityDecorator,
    SecurityHeadersManager as SecurityHeadersManager,
    cloud_handler as cloud_handler,
    ip_ban_manager as ip_ban_manager,
    rate_limit_handler as rate_limit_handler,
    redis_handler as redis_handler,
    security_headers_manager as security_headers_manager,
    sus_patterns_handler as sus_patterns_handler,
)

from guard.middleware import SecurityMiddleware as SecurityMiddleware

try:
    __version__ = _pkg_version("fastapi-guard")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__", "SecurityMiddleware", *guard_core.__all__]
