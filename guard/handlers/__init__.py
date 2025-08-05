"""
FastAPI Guard handlers package.

This package contains all security handlers for FastAPI Guard,
including IP management, rate limiting, cloud provider detection,
and dynamic rule management.
"""

from .behavior_handler import BehaviorTracker
from .cloud_handler import CloudManager
from .dynamic_rule_handler import DynamicRuleManager
from .ipban_handler import IPBanManager
from .ipinfo_handler import IPInfoManager
from .ratelimit_handler import RateLimitManager
from .redis_handler import RedisManager
from .suspatterns_handler import SusPatternsManager

__all__ = [
    "BehaviorTracker",
    "CloudManager",
    "DynamicRuleManager",
    "IPBanManager",
    "IPInfoManager",
    "RateLimitManager",
    "RedisManager",
    "SusPatternsManager",
]
