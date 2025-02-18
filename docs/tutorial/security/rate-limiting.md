---
title: Rate Limiting - FastAPI Guard
description: Protect your FastAPI application from abuse with configurable rate limiting and request throttling
keywords: rate limiting, api throttling, request limiting, ddos protection
---

# Rate Limiting

FastAPI Guard includes built-in rate limiting to protect your API from abuse.

## Basic Rate Limiting

Configure basic rate limiting:

```python
config = SecurityConfig(
    rate_limit=100,  # Maximum requests per minute
    rate_limit_window=60  # Time window in seconds
)
```

## Custom Rate Limits

You can set different rate limits for different paths:

```python
config = SecurityConfig(
    rate_limit=100,  # Default rate limit
)
```

## Rate Limit Headers

The middleware adds rate limit headers to responses:

- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Remaining requests in window
- `X-RateLimit-Reset`: Time until rate limit resets

## Handling Rate Limits

When rate limits are exceeded, the middleware returns a 429 (Too Many Requests) response:

```python
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

@app.exception_handler(HTTPException)
async def rate_limit_handler(request: Request, exc: HTTPException):
    if exc.status_code == 429:
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "retry_after": request.headers.get("Retry-After")
            }
        )
    raise exc
```