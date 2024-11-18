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
    if await detect_penetration_attempt(request):
        return JSONResponse(
            status_code=400,
            content={"error": "Suspicious activity detected"}
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