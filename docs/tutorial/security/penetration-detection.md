---
title: Penetration Detection - FastAPI Guard
description: Detect and prevent common attack patterns including SQL injection, XSS, and other security threats
keywords: penetration detection, attack prevention, security patterns, threat detection
---

# Penetration Detection

FastAPI Guard includes sophisticated penetration attempt detection to identify and block malicious requests.

## Basic Configuration

Enable penetration detection:

```python
config = SecurityConfig(
    enable_penetration_detection=True,
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600  # Ban duration in seconds
)
```

## Detection Patterns

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

## Custom Detection Logic

You can use the penetration detection directly in your routes:

```python
from guard.utils import detect_penetration_attempt

@app.post("/api/data")
async def submit_data(request: Request):
    is_suspicious, trigger_info = await detect_penetration_attempt(request)
    if is_suspicious:
        return JSONResponse(
            status_code=400,
            content={"error": f"Suspicious activity detected: {trigger_info}"}
        )
    # Process legitimate request
    return {"status": "success"}
```

## Logging Suspicious Activity

Configure logging for suspicious activities:

```python
config = SecurityConfig(
    custom_log_file="security.log",
    log_level="WARNING"
)
```

Example log output:
```
2024-01-20 10:15:23 - WARNING - Suspicious activity detected from 192.168.1.1: POST /api/data - Reason: SQL injection attempt
```

## Passive Mode

When `passive_mode` is enabled, FastAPI Guard will:

1. Detect potential penetration attempts (work as usual)
2. Log them with detailed information about what triggered the detection
3. Allow the requests to proceed without blocking

This helps you understand your traffic patterns and fine-tune your security settings before enforcing blocks that might affect legitimate users.

### How to Use Passive Mode

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

app = FastAPI()

# Create a configuration with passive mode enabled
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token",
    enable_penetration_detection=True,  # True by default
    passive_mode=True,  # Enable passive mode
)

# Add the middleware to your application
app.add_middleware(SecurityMiddleware, config=config)
```

### Checking Logs

When using passive mode, watch your logs for entries starting with "[PASSIVE MODE]". These entries provide detailed information about what triggered the detection, including:

- The client's IP address
- The HTTP method and URL
- The specific pattern that was matched
- Which part of the request triggered the detection (query parameter, body, header, etc.)
