---

title: Penetration Detection - FastAPI Guard
description: Detect and prevent common attack patterns including SQL injection, XSS, and other security threats
keywords: penetration detection, attack prevention, security patterns, threat detection
---

Penetration Detection
=====================

FastAPI Guard includes sophisticated penetration attempt detection to identify and block malicious requests.

___

Basic Configuration
-------------------

Enable penetration detection:

```python
config = SecurityConfig(
    enable_penetration_detection=True,
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600,  # Ban duration in seconds
    regex_timeout=2.0  # Timeout for regex pattern matching (default: 2.0 seconds)
)
```

___

Detection Patterns
------------------

The system checks for various attack patterns including:

- SQL Injection attempts
- XSS (Cross-Site Scripting)
- Command Injection
- Path Traversal
- Template Injection
- HTTP Response Splitting
- LDAP Injection
- XML Injection
- NoSQL Injection
- File Upload attacks

___

Regex Timeout Protection
------------------------

To prevent ReDoS (Regular Expression Denial of Service) attacks, FastAPI Guard implements a timeout mechanism for regex pattern matching:

```python
config = SecurityConfig(
    regex_timeout=2.0  # Default: 2.0 seconds
)
```

The `regex_timeout` parameter:
- Prevents malicious inputs from causing excessive CPU usage through regex backtracking
- Can be configured between 0.1 and 30.0 seconds
- Defaults to 2.0 seconds for balanced security and performance
- If a regex match exceeds the timeout, it's considered non-matching and logged as a potential ReDoS attempt

When a timeout occurs, you'll see a warning in the logs:
```text
WARNING - Regex timeout exceeded for pattern '<pattern>' - Potential ReDoS attack blocked.
```

___

Custom Detection Logic
----------------------

You can use the penetration detection directly in your routes:

```python
from guard.utils import detect_penetration_attempt

@app.post("/api/data")
async def submit_data(request: Request):
    # Use custom timeout if needed (default is 2.0 seconds)
    is_suspicious, trigger_info = await detect_penetration_attempt(request, regex_timeout=1.5)
    if is_suspicious:
        return JSONResponse(
            status_code=400,
            content={"error": f"Suspicious activity detected: {trigger_info}"}
        )
    # Process legitimate request
    return {"status": "success"}
```

___

Logging Suspicious Activity
----------------------------

Configure logging for suspicious activities:

```python
config = SecurityConfig(
    custom_log_file="security.log",
    log_level="WARNING"
)
```

Example log output:

```text
2024-01-20 10:15:23 - WARNING - Suspicious activity detected from 192.168.1.1: POST /api/data - Reason: SQL injection attempt
```

___

Passive Mode
------------

When `passive_mode` is enabled, FastAPI Guard will:

1. Detect potential penetration attempts (work as usual)
2. Log them with detailed information about what triggered the detection
3. Allow the requests to proceed without blocking

This helps you understand your traffic patterns and fine-tune your security settings before enforcing blocks that might affect legitimate users.

___

How to Use Passive Mode
-----------------------

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

app = FastAPI()

# Create a configuration with passive mode enabled
config = SecurityConfig(
    enable_penetration_detection=True,  # True by default
    passive_mode=True,  # Enable passive mode
)

# Add the middleware to your application
app.add_middleware(SecurityMiddleware, config=config)
```

___

Checking Logs
-------------

When using passive mode, watch your logs for entries starting with "[PASSIVE MODE]". These entries provide detailed information about what triggered the detection, including:

- The client's IP address
- The HTTP method and URL
- The specific pattern that was matched
- Which part of the request triggered the detection (query parameter, body, header, etc.)
