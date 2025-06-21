---

title: API Reference - FastAPI Guard
description: Complete API documentation for FastAPI Guard security middleware and its components
keywords: fastapi guard api, security middleware api, python api reference
---

API Reference Overview
======================

___

Core Components
---------------

Middleware & Configuration
----------------------------

- **SecurityMiddleware**: The main middleware that handles all security features
- **SecurityConfig**: Configuration class for all security settings
- **SecurityDecorator**: Route-level security decorator system

Handler Components
------------------

- **IPBanManager**: Manages IP banning functionality
- **IPInfoManager**: Handles IP geolocation using IPInfo's database
- **SusPatternsManager**: Manages suspicious patterns for threat detection
- **CloudManager**: Handles cloud provider IP range detection
- **RateLimitManager**: Handles rate limiting functionality
- **RedisManager**: Handles Redis connections and atomic operations
- **BehaviorTracker**: Handles behavioral analysis and monitoring

Utilities
---------

- **Utilities**: Helper functions for logging and request analysis

___

Key Classes and Instances
-------------------------

```python
# Core middleware and configuration
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

# Security decorators
from guard.decorators import SecurityDecorator, RouteConfig
from guard.decorators.base import get_route_decorator_config

# Handler classes and their pre-initialized instances
from guard.handlers.cloud_handler import CloudManager, cloud_handler
from guard.handlers.ipban_handler import IPBanManager, ip_ban_manager
from guard.handlers.ratelimit_handler import RateLimitManager, rate_limit_handler
from guard.handlers.redis_handler import RedisManager, redis_handler
from guard.handlers.suspatterns_handler import SusPatternsManager, sus_patterns_handler
from guard.handlers.behavior_handler import BehaviorTracker, BehaviorRule

# Special case - requires parameters
from guard.handlers.ipinfo_handler import IPInfoManager
```

___

Singleton Pattern
-----------------

Most handler classes use a singleton pattern with `__new__` to ensure only one instance:

```python
class ExampleHandler:
    _instance = None

    def __new__(cls, *args, **kwargs) -> "ExampleHandler":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # Initialize instance attributes
        return cls._instance
```

___

Configuration Model
-------------------

The `SecurityConfig` class is the central configuration point:

```python
class SecurityConfig:
    def __init__(
        self,
        geo_ip_handler: GeoIPHandler | None = None,
        whitelist: list[str] | None = None,
        blacklist: list[str] = [],
        blocked_countries: list[str] = [],
        whitelist_countries: list[str] = [],
        blocked_user_agents: list[str] = [],
        auto_ban_threshold: int = 5,
        auto_ban_duration: int = 3600,
        rate_limit: int = 100,
        rate_limit_window: int = 60,
        enable_cors: bool = False,
        # ... other parameters
    ):
        # ... initialization
```

___

Optimized Loading
-----------------

FastAPI Guard uses a smart loading strategy to improve performance:

- **IPInfoManager**: Only downloaded and initialized when country filtering is configured
- **CloudManager**: Only fetches cloud provider IP ranges when cloud blocking is enabled
- **Handlers Initialization**: Middleware conditionally initializes components based on configuration

This approach reduces startup time and memory usage when not all security features are needed.

```python
# Conditional loading example from middleware
async def initialize(self) -> None:
    if self.config.enable_redis and self.redis_handler:
        await self.redis_handler.initialize()
        # Only initialize when needed
        if self.config.block_cloud_providers:
            await cloud_handler.initialize_redis(
                self.redis_handler, self.config.block_cloud_providers
            )
        await ip_ban_manager.initialize_redis(self.redis_handler)
        # Only initialize if country filtering is enabled
        if self.geo_ip_handler is not None:
            await self.geo_ip_handler.initialize_redis(self.redis_handler)
```

___

Security Decorators
-------------------

FastAPI Guard provides a comprehensive decorator system for route-level security controls:

SecurityDecorator Class
----------------------------

The main decorator class combines all security capabilities:

```python
from guard.decorators import SecurityDecorator

config = SecurityConfig()
guard_deco = SecurityDecorator(config)

# Apply to routes
@app.get("/api/sensitive")
@guard_deco.rate_limit(requests=5, window=300)
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
@guard_deco.block_countries(["CN", "RU"])
def sensitive_endpoint():
    return {"data": "sensitive"}
```

___

Decorator Categories
-------------------

- **AccessControlMixin**: IP filtering, geographic restrictions, cloud provider blocking
- **AuthenticationMixin**: HTTPS enforcement, auth requirements, API key validation
- **RateLimitingMixin**: Custom rate limits, geographic rate limiting
- **BehavioralMixin**: Usage monitoring, return pattern analysis, frequency detection
- **ContentFilteringMixin**: Content type filtering, size limits, user agent blocking
- **AdvancedMixin**: Time windows, suspicious detection, honeypot detection

___

Integration with Middleware
----------------------------

Decorators work seamlessly with SecurityMiddleware:

```python
# Set up middleware and decorators
app.add_middleware(SecurityMiddleware, config=config)
app.state.guard_decorator = guard_deco  # Required for integration
```

___

Route Configuration Priority
----------------------------

Configuration is applied in the following order of precedence:

1. Decorator Settings (highest priority)
2. Global Middleware Settings
3. Default Settings (lowest priority)

This allows route-specific overrides while maintaining global defaults.
