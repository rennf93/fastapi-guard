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

### log_activity

```python
async def log_activity(
    request: Request,
    logger: logging.Logger,
    log_type: str = "request",
    reason: str = "",
    passive_mode: bool = False,
    trigger_info: str = "",
    level: Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None = "WARNING"
):
    """
    Universal logging function for all types of requests and activities.
    """
```

This is a unified logging function that handles regular requests, suspicious activities, and passive mode logging.

Parameters:
- `request`: The FastAPI request object
- `logger`: The logger instance
- `log_type`: Type of log entry (default: "request", can also be "suspicious")
- `reason`: Reason for flagging an activity
- `passive_mode`: Whether to enable passive mode logging format
- `trigger_info`: Details about what triggered detection
- `level`: The logging level to use. `None` won't emit any log.

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
) -> tuple[bool, str]
```

Detect potential penetration attempts in the request.

This function checks various parts of the request (query params, body, path, headers) against a list of suspicious patterns to identify potential security threats.

Returns a tuple where:
- First element is a boolean: `True` if a potential attack is detected, `False` otherwise
- Second element is a string with details about what triggered the detection, or empty string if no attack detected

Example usage:

```python
from fastapi import Request
from guard.utils import detect_penetration_attempt

@app.post("/api/submit")
async def submit_data(request: Request):
    is_suspicious, trigger_info = await detect_penetration_attempt(request)
    if is_suspicious:
        # Log the detection with details
        logger.warning(f"Attack detected: {trigger_info}")
        return {"error": "Suspicious activity detected"}
    return {"success": True}
```

## Usage Examples

```python
from guard.utils import (
    setup_custom_logging,
    log_activity,
    detect_penetration_attempt
)

# Setup logging
logger = await setup_custom_logging("security.log")

# Log regular request
await log_activity(request, logger)

# Log suspicious activity
await log_activity(
    request,
    logger,
    log_type="suspicious",
    reason="Suspicious pattern detected"
)

# Check for penetration attempts
is_suspicious, trigger_info = await detect_penetration_attempt(request)
```