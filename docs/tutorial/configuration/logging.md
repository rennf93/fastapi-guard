---
title: Logging Configuration - FastAPI Guard
description: Configure security event logging and monitoring in FastAPI Guard with custom log formats and levels
keywords: fastapi logging, security logging, event monitoring, log configuration
---

# Logging Configuration

FastAPI Guard includes powerful logging capabilities to help you monitor and track security-related events in your application.

## Basic Logging Setup

Configure basic logging:

```python
config = SecurityConfig(
    custom_log_file="security.log"
)
```

## Log Levels

Configure different log levels:

```python
import logging

config = SecurityConfig(
    custom_log_file="security.log",
    log_level=logging.WARNING
)
```

## Custom Logger

```python
from guard.utils import setup_custom_logging

# Setup custom logging to a file
logger = await setup_custom_logging("security.log")
```

## Logging

FastAPI Guard uses a unified logging approach with the `log_activity` function that handles different types of log events:

```python
from guard.utils import log_activity

# Log a regular request
await log_activity(request, logger)

# Log suspicious activity
await log_activity(
    request,
    logger,
    log_type="suspicious",
    reason="Suspicious IP address detected"
)

# Log penetration attempt in passive mode
await log_activity(
    request,
    logger,
    log_type="suspicious",
    reason="SQL injection attempt detected",
    passive_mode=True,
    trigger_info="Detected pattern: ' OR 1=1 --"
)
```

## Logging Parameters

The `log_activity` function accepts the following parameters:

- `request`: The FastAPI request object
- `logger`: The logger instance to use
- `log_type`: Type of log entry (default: "request", can also be "suspicious")
- `reason`: Reason for flagging an activity
- `passive_mode`: Whether to format log as passive mode detection
- `trigger_info`: Details about what triggered detection

## Log Format

By default, logs include the following information:

- Timestamp
- Client IP address
- HTTP method
- Request path
- Request headers
- Request body (if available)
- Reason for logging (for suspicious activities)
- Detection trigger details (for penetration attempts)
