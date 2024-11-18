---
title: SecurityMiddleware API - FastAPI Guard
description: Complete API reference for FastAPI Guard's SecurityMiddleware class and its configuration options
keywords: security middleware, fastapi middleware, api security, middleware configuration
---

# SecurityMiddleware

The `SecurityMiddleware` class is the core component of FastAPI Guard that handles all security features.

## Class Definition

```python
class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Callable[[Request], Awaitable[Response]],
        config: SecurityConfig
    ):
        # ... initialization
```

## Methods

### dispatch

```python
async def dispatch(
    self,
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """
    Main method that processes each request through
    the security pipeline.
    """
```

### create_error_response

```python
async def create_error_response(
    self,
    status_code: int,
    default_message: str
) -> Response:
    """
    Creates standardized error responses.
    """
```

## Usage Example

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    ipinfo_token="your_token",
    rate_limit=100
)

app.add_middleware(SecurityMiddleware, config=config)
``` 