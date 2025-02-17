---
title: Redis Integration - FastAPI Guard
description: Guide to using Redis for distributed state management in FastAPI Guard
keywords: redis configuration, distributed rate limiting, atomic operations
---

# Redis Integration

FastAPI Guard uses Redis for distributed state management across multiple instances.

## Basic Configuration

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://prod-redis:6379/1",
    redis_prefix="myapp:security:"
)
```

## Key Features

1. **Distributed Rate Limiting**
2. **Shared IP Ban List**
3. **Cloud IP Range Caching**
4. **Pattern Storage for Penetration Detection**

## Fallback Behavior

When Redis is disabled (`enable_redis=False`):
- Uses in-memory storage (TTLCache)
- Rate limits are instance-local
- IP bans only affect current instance
- Cloud IP ranges refresh hourly

## Connection Management

```python
# Get RedisManager instance from middleware
redis = request.app.state.security_middleware.redis_handler

# Manual connection handling example
async with redis.get_connection() as conn:
    await conn.set("key", "value")

# Automatic operation retry with proper arguments
await redis.safe_operation(
    lambda conn: conn.get("my_key"),
    namespace="data",
    key="my_key"
)
```

## Key Namespacing

Keys are automatically prefixed using:
`{redis_prefix}{namespace}:{key}`

Example: `fastapi_guard:cloud_ranges:AWS`

## Best Practices

1. Use separate Redis databases for different environments
2. Set appropriate TTLs for transient data
3. Monitor connection pool size in high-traffic deployments
4. Use `safe_operation` for all Redis interactions