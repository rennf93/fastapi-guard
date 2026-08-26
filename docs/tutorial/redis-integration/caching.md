---

title: Redis Integration - FastAPI Guard
description: Guide to using Redis for distributed state management in FastAPI Guard
keywords: redis configuration, distributed rate limiting, atomic operations
---

Redis Integration
=================

FastAPI Guard uses Redis for distributed state management across multiple instances.

___

Basic Configuration
-------------------

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://prod-redis:6379/1",
    redis_prefix="myapp:security:",
)
```

___

Key Features
------------

- Distributed Rate Limiting
- Shared IP Ban List
- Cloud IP Range Caching
- Pattern Storage for Penetration Detection

___

Fallback Behavior
-----------------

When Redis is disabled (`enable_redis=False`):

- Uses in-memory storage (TTLCache)
- Rate limits are instance-local
- IP bans only affect current instance
- Cloud IP ranges refresh hourly

___

Startup Failure
---------------

If Redis is enabled (`enable_redis=True`, the default) but unreachable when `SecurityMiddleware` initializes, guard-core's `redis_fail_open` setting decides what happens:

- `redis_fail_open=False` (the default): initialization raises, and every request gets a clean `503 Service temporarily unavailable` with a `Retry-After: 5` header until Redis becomes reachable, at which point the next request initializes successfully and starts serving normally. If a lifespan warmer (`guard_lifespan`, `make_lifespan`, `guard_startup`) is wired in, app startup itself still succeeds; the failure surfaces on the first request instead.
- `redis_fail_open=True`: guard-core degrades to the same in-memory backends used when `enable_redis=False`, for the life of the process, instead of returning 503.

___

Connection Management
---------------------

```python
# Get RedisManager instance from middleware
redis = request.app.state.security_middleware.redis_handler

# Manual connection handling example
async with redis.get_connection() as conn:
    await conn.set("key", "value")

# Automatic operation retry with proper arguments
await redis.safe_operation(
    lambda conn: conn.get("my_key"), namespace="data", key="my_key"
)
```

___

Key Namespacing
---------------

Keys are automatically prefixed using: `{redis_prefix}{namespace}:{key}`

Example: `fastapi_guard:cloud_ranges:AWS`

___

Best Practices
--------------

1. Use separate Redis databases for different environments
2. Set appropriate TTLs for transient data
3. Monitor connection pool size in high-traffic deployments
4. Use `safe_operation` for all Redis interactions
