---
title: Rate Limiting - FastAPI Guard
description: Learn how to implement rate limiting in your FastAPI application using FastAPI Guard
keywords: rate limiting, api security, ddos protection, request throttling, fastapi
---

# Rate Limiting

Rate limiting is a crucial security feature that protects your API from abuse, DoS attacks, and excessive usage. FastAPI Guard provides a robust rate limiting system through the dedicated `RateLimitManager` class.

## Basic Configuration

To enable rate limiting, configure the following parameters in your `SecurityConfig`:

```python
from fastapi import FastAPI
from guard import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    # NOTE: enable_rate_limiting is not required, it's enabled by default
    rate_limit=100,               # Maximum number of requests allowed
    rate_limit_window=60,         # Time window in seconds
    # ... other configuration options ...
)

app.add_middleware(SecurityMiddleware, config=config)
```

## How It Works

The rate limiter tracks requests by client IP address:

1. When a request arrives, the rate limiter checks if the client has exceeded their limit
2. If within limits, the request counter is incremented and the request proceeds
3. If the limit is exceeded, a 429 Too Many Requests response is returned
4. Counters automatically expire after the configured time window

## In-Memory vs. Redis Rate Limiting

FastAPI Guard supports two rate limiting storage backends:

### In-Memory Rate Limiting

By default, rate limiting uses an in-memory TTLCache for tracking request counts:

```python
config = SecurityConfig(
    # Rate limit is enabled by default
    rate_limit=100,
    rate_limit_window=60,
    enable_redis=False,
)
```

**Pros:**
- Simple setup (no external dependencies)
- Fast performance
- Automatic expiration of old counters

**Cons:**
- Doesn't work across multiple application instances
- Lost on application restart
- Consumes application memory

### Redis-Based Rate Limiting

For distributed environments, enable Redis-based rate limiting:

```python
config = SecurityConfig(
    # NOTE: enable_rate_limiting is not required, it's enabled by default
    rate_limit=100,
    rate_limit_window=60,
    redis_url="redis://localhost:6379/0",
    redis_prefix="myapp:"  # Optional prefix for Redis keys (override default)
)
```

**Pros:**
- Works across multiple application instances
- Persists through application restarts
- Centralized rate limit tracking

**Cons:**
- Requires a Redis server
- Slightly higher latency due to network calls
- Additional infrastructure dependency

## Custom Response Messages

You can customize the rate limit exceeded message:

```python
config = SecurityConfig(
    # NOTE: enable_rate_limiting is not required, it's enabled by default
    rate_limit=100,
    rate_limit_window=60,
    custom_error_responses={
        429: "Rate limit exceeded. Please try again later."
    }
)
```

## Advanced Usage

### Accessing the Rate Limiter Directly

For advanced use cases, you can access the rate limiter directly:

```python
from guard.handlers.ratelimit_handler import rate_limit_handler

# Get the singleton instance
async def some_route():
    # Get a reference to the handler
    handler = rate_limit_handler(config)

    # Reset rate limits (e.g., for a premium user)
    await handler.reset()
```

### Resetting Rate Limits

You might want to reset rate limits in certain scenarios:

```python
from guard.handlers.ratelimit_handler import rate_limit_handler

async def reset_rate_limits_for_user(user_id: str):
    handler = rate_limit_handler(config)

    # Clear all rate limits (use with caution)
    await handler.reset()
```

## Implementation Details

The `RateLimitManager` is implemented as a singleton to ensure consistent state across requests. It uses:

- TTLCache for in-memory storage with automatic expiration
- Redis increments with TTL for distributed storage
- Efficient counter storage to minimize memory footprint

## Best Practices

1. **Set reasonable limits**: Consider your API's typical usage patterns
2. **Use Redis in production**: For reliability in distributed environments
3. **Implement graduated limits**: Consider different limits for different API endpoints
4. **Inform clients**: Return appropriate headers with rate limit information
5. **Monitor usage patterns**: Keep an eye on rate limit hits to adjust as needed

## See Also

- [RateLimitManager API Reference](../../api/ratelimit-manager.md)
- [Redis Integration](../redis-integration/caching.md)
- [Security Middleware](../../api/security-middleware.md)