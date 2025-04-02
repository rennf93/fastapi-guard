---
title: API Reference - FastAPI Guard
description: Complete API documentation for FastAPI Guard security middleware and its components
keywords: fastapi guard api, security middleware api, python api reference
---

# API Reference Overview

FastAPI Guard consists of several core components:

## Core Components

- **SecurityMiddleware**: The main middleware that handles all security features
- **IPBanManager**: Manages IP banning functionality
- **IPInfoManager**: Handles IP geolocation using IPInfo's database
- **SusPatterns**: Manages suspicious patterns for threat detection
- **CloudManager**: Handles cloud provider IP range detection
- **Utilities**: Helper functions for logging and request analysis
- **RateLimitHandler**: Handles rate limiting functionality
- **RedisManager**: Handles Redis connections and atomic operations

## Key Classes and Instances

```python
# Core middleware
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

# Handler classes and their pre-initialized instances
from guard.handlers.cloud_handler import CloudManager, cloud_handler
from guard.handlers.ipban_handler import IPBanManager, ip_ban_manager
from guard.handlers.ratelimit_handler import RateLimitHandler, rate_limit_handler
from guard.handlers.redis_handler import RedisManager, redis_handler
from guard.sus_patterns import SusPatterns, sus_patterns_handler

# Special case - requires parameters
from guard.handlers.ipinfo_handler import IPInfoManager
```

## Singleton Pattern
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

## Configuration Model

The `SecurityConfig` class is the central configuration point:

```python
class SecurityConfig:
    def __init__(
        self,
        ipinfo_token: str,
        whitelist: Optional[List[str]] = None,
        blacklist: List[str] = [],
        blocked_countries: List[str] = [],
        whitelist_countries: List[str] = [],
        blocked_user_agents: List[str] = [],
        auto_ban_threshold: int = 5,
        auto_ban_duration: int = 3600,
        rate_limit: int = 100,
        rate_limit_window: int = 60,
        enable_cors: bool = False,
        # ... other parameters
    ):
        # ... initialization
```