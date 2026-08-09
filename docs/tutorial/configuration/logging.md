---

title: Logging Configuration - FastAPI Guard
description: Configure security event logging and monitoring in FastAPI Guard with custom log formats and levels
keywords: fastapi logging, security logging, event monitoring, log configuration
---

Logging Configuration
=====================

FastAPI Guard includes powerful logging capabilities to help you monitor and track security-related events in your application.

___

Basic Logging Setup
-------------------

FastAPI Guard uses guard-core's hierarchical logging namespace (`guard_core`) with automatic console output and optional file logging:

```python
config = SecurityConfig(
    # Optional: Enable file logging by providing a path
    custom_log_file="security.log"  # Creates file + console output
    # OR
    # custom_log_file=None  # Console output only (default)
)
```

**Key Features:**

- Console output is **always enabled** for visibility
- File logging is **optional** and only enabled when `custom_log_file` is set
- All logging comes from guard-core's `guard_core.*` namespace; fastapi-guard is a thin adapter and does not introduce its own logger namespace

___

Configurable Log Levels
------------------------

FastAPI Guard supports different log levels for normal and suspicious requests:

```python
config = SecurityConfig(
    # Log normal requests as INFO (or set to None to disable)
    log_request_level="INFO",
    # Log suspicious activity as WARNING
    log_suspicious_level="WARNING",
)
```

Available log levels:

- `"INFO"`: Informational messages
- `"DEBUG"`: Detailed debug information
- `"WARNING"`: Warning messages (default for suspicious activity)
- `"ERROR"`: Error conditions
- `"CRITICAL"`: Critical errors
- `None`: Disable logging completely

___

Structured JSON Logging
------------------------

FastAPI Guard supports structured JSON log output for integration with log aggregation systems like ELK, Datadog, or CloudWatch:

```python
config = SecurityConfig(log_format="json", custom_log_file="security.log")
```

When `log_format="json"` is set, all log output (both console and file) uses structured JSON:

```json
{"timestamp": "2026-03-14 08:30:00,123", "level": "INFO", "logger": "guard_core", "message": "Request from 192.168.1.1"}
{"timestamp": "2026-03-14 08:30:01,456", "level": "WARNING", "logger": "guard_core", "message": "Suspicious activity detected from 10.0.0.5"}
```

The default `log_format="text"` preserves the human-readable format:

```text
[guard_core] 2026-03-14 08:30:00 - INFO - Request from 192.168.1.1
```

___

Performance Optimization
-------------------------

For high-traffic production environments, consider disabling normal request logging:

```python
config = SecurityConfig(
    # Disable normal request logging (default)
    log_request_level=None,
    # Keep security event logging enabled
    log_suspicious_level="WARNING",
)
```

___

Custom Logger
-------------

The `setup_custom_logging` function is automatically called by the middleware during initialization:

```python
from guard_core.utils import setup_custom_logging

# Manual setup (if needed outside of middleware)
# Console only (no file)
logger = setup_custom_logging(None)

# Console + file logging
logger = setup_custom_logging("security.log")

# The logger uses the "guard_core" namespace
# Individual handlers use sub-namespaces like:
# - "guard_core.handlers.redis"
# - "guard_core.handlers.cloud"
# - "guard_core.handlers.ipban"
```

**Note:** The function is synchronous (not async) and handles directory creation automatically.

___

Logging
-------

FastAPI Guard uses a unified logging approach with the `log_activity` function that handles different types of log events:

```python
from guard_core.utils import log_activity

# Log a regular request
await log_activity(request, logger)

# Log suspicious activity
await log_activity(
    request, logger, log_type="suspicious", reason="Suspicious IP address detected"
)

# Log penetration attempt in passive mode
await log_activity(
    request,
    logger,
    log_type="suspicious",
    reason="SQL injection attempt detected",
    passive_mode=True,
    trigger_info="Detected pattern: ' OR 1=1 --",
)

# Log with specific level
await log_activity(request, logger, level="ERROR", reason="Authentication failure")
```

___

Logging Parameters
------------------

The `log_activity` function accepts the following parameters:

- `request`: The FastAPI request object
- `logger`: The logger instance to use
- `log_type`: Type of log entry (default: "request", can also be "suspicious")
- `reason`: Reason for flagging an activity
- `passive_mode`: Whether to format log as passive mode detection
- `trigger_info`: Details about what triggered detection
- `level`: The logging level to use. If `None`, logging is disabled. Defaults to "WARNING".

___

Logger Namespace Hierarchy
---------------------------

All security logging comes from guard-core's `guard_core` namespace, whether the app uses fastapi-guard or another framework adapter. This is every `logging.getLogger(...)` call reachable in guard-core's source as of this writing (every module that opens its own logger names it `guard_core` or a `guard_core.<dotted module path>` child, so this list only grows the same way; it is not filtered for relevance):

```diagram
guard_core                             # Root logger; the pipeline-init summary and
│                                       # per-request logging use this logger directly
├── guard_core.utils                   # Background agent-event-send failures
├── guard_core.enricher
├── guard_core.handlers                # Handler components
│   ├── guard_core.handlers.redis
│   ├── guard_core.handlers.cloud
│   ├── guard_core.handlers.ipinfo
│   ├── guard_core.handlers.ipban
│   ├── guard_core.handlers.ratelimit
│   ├── guard_core.handlers.behavior
│   ├── guard_core.handlers.suspatterns
│   ├── guard_core.handlers.security_headers
│   └── guard_core.handlers.dynamic_rule
├── guard_core.decorators              # Decorator components
│   └── guard_core.decorators.base
├── guard_core.detection_engine        # Detection engine components
│   └── guard_core.detection_engine.compiler
└── guard_core.core                    # Internal core modules
    ├── guard_core.core.initialization
    ├── guard_core.core.checks.pipeline
    ├── guard_core.core.responses.factory
    └── guard_core.core.events
        ├── guard_core.core.events.metrics
        └── guard_core.core.events.middleware_events
```

This namespace isolation ensures:

- guard-core's logs are separate from your application logs
- You can configure log levels for specific components
- Test frameworks can capture logs via propagation
- No interference with user-defined loggers

___

Log Format
----------

By default, logs include the following information:

- Timestamp
- Logger name (showing the component namespace)
- Log level
- Client IP address
- HTTP method
- Request path
- Request headers
- Request body (if available)
- Reason for logging (for suspicious activities)
- Detection trigger details (for penetration attempts)

___

Complete Examples
-----------------

Example 1: Production Setup with File Logging
----------------------------------------------

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

app = FastAPI()

# Production configuration
config = SecurityConfig(
    # File + console logging for audit trail
    custom_log_file="/var/log/fastapi-guard/security.log",
    # Disable normal request logging to reduce noise
    log_request_level=None,
    # Keep security events at WARNING level
    log_suspicious_level="WARNING",
    # Other security settings...
    enable_redis=True,
    enable_penetration_detection=True,
)

app.add_middleware(SecurityMiddleware, config=config)
```

Example 2: Development Setup with Console Only
-----------------------------------------------

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

app = FastAPI()

# Development configuration
config = SecurityConfig(
    # Console-only output for development
    custom_log_file=None,  # No file logging
    # Enable all logging for debugging
    log_request_level="INFO",
    log_suspicious_level="WARNING",
    # Other settings...
    passive_mode=True,  # Log-only mode for testing
)

app.add_middleware(SecurityMiddleware, config=config)
```

Example 3: Custom Component-Level Configuration
------------------------------------------------

```python
import logging
from guard import SecurityConfig

# Configure specific component log levels
logging.getLogger("guard_core.handlers.redis").setLevel(logging.DEBUG)
logging.getLogger("guard_core.handlers.ipban").setLevel(logging.INFO)
logging.getLogger("guard_core.detection_engine").setLevel(logging.WARNING)

# This works because guard-core uses hierarchical namespaces
config = SecurityConfig(
    custom_log_file="security.log",
    # ... other settings
)
```

Example 4: Integration with Application Logging
------------------------------------------------

```python
import logging
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

# Configure your application logging
app_logger = logging.getLogger("myapp")
app_logger.setLevel(logging.INFO)

# guard-core's logs are isolated under the "guard_core" namespace
# No interference with your app logs
app = FastAPI()

config = SecurityConfig(
    custom_log_file="security.log",  # Separate security log file
)

app.add_middleware(SecurityMiddleware, config=config)

# Your app logs and guard-core's security logs remain separate
app_logger.info("Application started")  # Goes to "myapp" logger
# Security events go to the "guard_core" logger
```
