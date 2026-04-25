---

title: Utilities API - FastAPI Guard
description: Helper functions and utilities for logging, security checks, and request handling in FastAPI Guard
keywords: security utilities, logging functions, security checks, request handling
---

Utilities
=========

The `utils` module provides various helper functions for security operations.

___

Logging Functions
-----------------

setup_custom_logging
---------------------

```python
def setup_custom_logging(
    log_file: str | None = None
) -> logging.Logger:
    """
    Setup custom logging for FastAPI Guard.
    
    Configures a hierarchical logger that outputs to both console and file.
    Console output is ALWAYS enabled for visibility.
    File output is optional for persistence.
    
    Args:
        log_file: Optional path to log file. If None, only console output is enabled.
                  If provided, creates the directory if it doesn't exist.
    
    Returns:
        logging.Logger: Configured logger with namespace "fastapi_guard"
    
    Note: This function is synchronous (not async).
    """
```

log_activity
------------

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

Parameters:

- `request`: The FastAPI request object
- `logger`: The logger instance
- `log_type`: Type of log entry (default: "request", can also be "suspicious")
- `reason`: Reason for flagging an activity
- `passive_mode`: Whether to enable passive mode logging format
- `trigger_info`: Details about what triggered detection
- `level`: The logging level to use. If `None`, logging is disabled. Defaults to "WARNING".

This is a unified logging function that handles regular requests, suspicious activities, and passive mode logging.

___

Security Check Functions
------------------------

is_user_agent_allowed
---------------------

```python
async def is_user_agent_allowed(
    user_agent: str,
    config: SecurityConfig
) -> bool:
    """
    Check if user agent is allowed.
    """
```

check_ip_country
----------------

```python
async def check_ip_country(
    request: str | Request,
    config: SecurityConfig,
    ipinfo_db: IPInfoManager
) -> bool:
    """
    Check if IP is from a blocked country.
    """
```

is_ip_allowed
-------------

```python
async def is_ip_allowed(
    ip: str,
    config: SecurityConfig,
    ipinfo_db: IPInfoManager | None = None
) -> bool:
    """
    Check if IP address is allowed.
    """
```

The `ipinfo_db` parameter is now properly optional - it's only needed when country filtering is configured. If it's not provided when country filtering is configured, the function will work correctly but won't apply country filtering rules rules.

This function intelligently handles:

- Whitelist/blacklist checking
- Country filtering (only when IPInfoManager is provided)
- Cloud provider detection (only when cloud blocking is configured)

This selective processing aligns with FastAPI Guard's smart resource loading to optimize performance.

detect_penetration_attempt
--------------------------

```python
async def detect_penetration_attempt(
    request: Request,
    config: SecurityConfig | None = None,
    route_config: RouteConfig | None = None,
) -> DetectionResult
```

Detect potential penetration attempts in the request using the enhanced Detection Engine.

This function analyzes various parts of the request (query params, body, path, headers) using the Detection Engine's components including pattern matching, semantic analysis, and performance monitoring.

Parameters:

- `request`: The FastAPI request object to analyze
- `config`: Optional `SecurityConfig`. When supplied, its detection-exclusion fields (`detection_excluded_query_params`, `detection_excluded_body_fields`, `detection_excluded_headers`) and `detection_enabled_categories` are honored as global defaults.
- `route_config`: Optional `RouteConfig` produced by a `SecurityDecorator` rule. Per-route exclusions and enabled categories override the global `config` values for the matched route.

Returns a `DetectionResult` dataclass:

```python
@dataclass
class DetectionResult:
    is_threat: bool
    trigger_info: str
    threat_categories: list[str] = field(default_factory=list)
    threat_scores: dict[str, float] = field(default_factory=dict)
```

- `is_threat`: `True` if a potential attack is detected, `False` otherwise.
- `trigger_info`: Human-readable string describing what triggered the detection, or empty string when no attack was detected.
- `threat_categories`: Ordered list of category labels that fired for the request (e.g. `"xss"`, `"sqli"`, `"dir_traversal"`, `"ssrf"`, `"xml"`, `"recon"`, `"sensitive_file"`, `"ldap"`, `"nosql"`, `"custom"`).
- `threat_scores`: Map of category label to highest threat score observed for that category in the request.

The Detection Engine provides:

- Timeout-protected pattern matching (configured via `detection_compiler_timeout` in SecurityConfig)
- Intelligent content preprocessing that preserves attack patterns
- Semantic analysis for obfuscated attacks (when enabled)
- Performance monitoring for pattern effectiveness

Example usage:

```python
from fastapi import Request
from guard_core.utils import detect_penetration_attempt

@app.post("/api/submit")
async def submit_data(request: Request):
    result = await detect_penetration_attempt(request)
    if result.is_threat:
        logger.warning(
            "Attack detected: %s (categories=%s)",
            result.trigger_info,
            result.threat_categories,
        )
        return {"error": "Suspicious activity detected"}
    return {"success": True}

@app.post("/api/critical")
async def critical_endpoint(request: Request, security_config: SecurityConfig):
    result = await detect_penetration_attempt(request, config=security_config)
    if result.is_threat:
        return {"error": "Security check failed", "categories": result.threat_categories}
    return {"success": True}
```

extract_client_ip
-----------------

```python
def extract_client_ip(request: Request, config: SecurityConfig) -> str:
    """
    Securely extract the client IP address from the request, considering trusted proxies.

    This function implements a secure approach to IP extraction that protects against
    X-Forwarded-For header injection attacks.
    """
```

This function provides a secure way to extract client IPs by:

1. Only trusting X-Forwarded-For headers from configured trusted proxies
2. Using the connecting IP when not from a trusted proxy
3. Properly handling proxy chains based on configured depth

___

Usage Examples
--------------

```python
from guard_core.utils import (
    setup_custom_logging,
    log_activity,
    detect_penetration_attempt
)

# Setup logging (synchronous function)
# Console only
logger = setup_custom_logging()  # or setup_custom_logging(None)

# Console + file
logger = setup_custom_logging("security.log")

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
result = await detect_penetration_attempt(request)
if result.is_threat:
    logger.warning("Attack detected: %s", result.trigger_info)
```
