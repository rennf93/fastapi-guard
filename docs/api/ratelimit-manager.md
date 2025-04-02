---
title: RateLimitHandler - FastAPI Guard
description: API reference for the RateLimitHandler class in FastAPI Guard, handling rate limiting functionality
keywords: rate limiting, api security, fastapi, rate limit handler
---

# RateLimitHandler

The `RateLimitHandler` is responsible for managing rate limiting functionality in FastAPI Guard. It supports both in-memory rate limiting using TTLCache and distributed rate limiting using Redis.

## Overview

Rate limiting is an essential security feature that protects your API from abuse by limiting the number of requests a client can make within a specific time window. The `RateLimitHandler` implements this functionality with the following features:

- **In-memory rate limiting**: Uses TTLCache for efficient, expiring counters
- **Redis-based distributed rate limiting**: Optional support for distributed environments
- **Configurable limits and windows**: Set your own thresholds and time periods
- **Singleton pattern**: Ensures consistent state across requests
- **Automatic cleanup**: Expired limits are automatically removed

## Example Usage

```python
from fastapi import FastAPI
from guard import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

# Configure rate limiting
config = SecurityConfig(
    rate_limit=100,               # Max 100 requests
    rate_limit_window=60,         # Per minute
    enable_rate_limiting=True,    # Enable rate limiting (true by default)
    enable_redis=True,            # Use Redis for distributed setup (true by default)
    redis_url="redis://localhost:6379/0"
)

# Add middleware with rate limiting
app.add_middleware(SecurityMiddleware, config=config)
```

## Advanced Configuration

### Redis Integration

When using Redis for distributed rate limiting, the handler creates rate limit keys with the following pattern:

```
{redis_prefix}rate_limit:rate:{client_ip}
```

The keys automatically expire after the configured window duration.

### Direct Access

You can also access the handler directly if needed:

```python
from guard.handlers.ratelimit_handler import rate_limit_handler

# Get the singleton instance
handler = rate_limit_handler(config)

# Reset all rate limits
await handler.reset()
```

## Performance Considerations

- **In-memory rate limiting** is faster but doesn't work in distributed environments with multiple instances
- **Redis-based rate limiting** works across multiple instances but adds network overhead
- The TTLCache-based implementation automatically handles expiration without manual cleanup

## See Also

- [Rate Limiting Tutorial](../tutorial/ip-management/rate-limiter.md)
- [Redis Integration](../tutorial/redis-integration/caching.md)
- [SecurityMiddleware](./security-middleware.md)