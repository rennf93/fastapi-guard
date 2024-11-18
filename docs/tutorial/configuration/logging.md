# Logging Configuration

FastAPI Guard provides detailed logging capabilities for security events.

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

Use the logging utilities directly:

```python
from guard.utils import setup_custom_logging, log_suspicious_activity

# Setup logger
logger = await setup_custom_logging("custom.log")

# Log suspicious activity
await log_suspicious_activity(
    request,
    "Suspicious pattern detected",
    logger
)
```

## Log Format

Default log format:
```
2024-01-20 10:15:23 - WARNING - Suspicious activity detected from 192.168.1.1: POST /api/data - Headers: {'User-Agent': 'curl/7.64.1'}
```

## Request Logging

Log all incoming requests:

```python
from guard.utils import log_request

@app.middleware("http")
async def log_requests(request: Request, call_next):
    await log_request(request, logger)
    response = await call_next(request)
    return response
``` 