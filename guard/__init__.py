# fastapi_guard/__init__.py
from guard.decorators import RouteConfig, SecurityDecorator
from guard.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard.handlers.cloud_handler import CloudManager, cloud_handler
from guard.handlers.ipban_handler import IPBanManager, ip_ban_manager
from guard.handlers.ipinfo_handler import IPInfoManager
from guard.handlers.ratelimit_handler import RateLimitManager, rate_limit_handler
from guard.handlers.redis_handler import RedisManager, redis_handler
from guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from guard.handlers.suspatterns_handler import sus_patterns_handler
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.protocols.geo_ip_protocol import GeoIPHandler
from guard.protocols.redis_protocol import RedisHandlerProtocol

__all__ = [
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
]
