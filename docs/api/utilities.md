---
title: Utilities API - FastAPI Guard
description: Helper functions and utilities for logging, security checks, and request handling in FastAPI Guard
keywords: security utilities, logging functions, security checks, request handling
---

# Utilities

The `utils` module provides various helper functions for security operations.

## Logging Functions

### setup_custom_logging

```python
async def setup_custom_logging(
    log_file: str
) -> logging.Logger:
    """
    Setup custom logging for the application.
    """
```

### log_request

```python
async def log_request(
    request: Request,
    logger: logging.Logger
):
    """
    Log details of an incoming request.
    """
```

### log_suspicious_activity

```python
async def log_suspicious_activity(
    request: Request,
    reason: str,
    logger: logging.Logger
):
    """
    Log suspicious activity detected in a request.
    """
```

## Security Check Functions

### is_user_agent_allowed

```python
async def is_user_agent_allowed(
    user_agent: str,
    config: SecurityConfig
) -> bool:
    """
    Check if user agent is allowed.
    """
```

### check_ip_country

```python
async def check_ip_country(
    request: Union[str, Request],
    config: SecurityConfig,
    ipinfo_db: IPInfoManager
) -> bool:
    """
    Check if IP is from a blocked country.
    """
```

### is_ip_allowed

```python
async def is_ip_allowed(
    ip: str,
    config: SecurityConfig,
    ipinfo_db: Optional[IPInfoManager] = None
) -> bool:
    """
    Check if IP address is allowed.
    """
```

### detect_penetration_attempt

```python
async def detect_penetration_attempt(
    request: Request
) -> bool:
    """
    Detect potential penetration attempts.
    """
```

## Usage Examples

```python
from guard.utils import (
    setup_custom_logging,
    log_request,
    detect_penetration_attempt
)

# Setup logging
logger = await setup_custom_logging("security.log")

# Log request
await log_request(request, logger)

# Check for penetration attempts
is_suspicious = await detect_penetration_attempt(request)
```