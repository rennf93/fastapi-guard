---
title: Custom Security Patterns - FastAPI Guard
description: Create and manage custom security patterns for detecting specific threats in your FastAPI application
keywords: security patterns, custom detection, threat patterns, security rules
---

# Custom Patterns

FastAPI Guard allows you to add custom patterns for detecting suspicious activity.

## Adding Custom Patterns

Add your own patterns to the detection system:

```python
from guard.sus_patterns import SusPatterns

async def setup_patterns():
    # Add custom pattern
    await SusPatterns.add_pattern(
        r"malicious_pattern.*",
        custom=True
    )
```

## Pattern Types

You can add patterns for different types of attacks:

```python
# Custom XSS pattern
await SusPatterns.add_pattern(
    r"<script\s*src=.*>",
    custom=True
)

# Custom SQL injection pattern
await SusPatterns.add_pattern(
    r";\s*DROP\s+TABLE",
    custom=True
)

# Custom file path pattern
await SusPatterns.add_pattern(
    r"\.\.\/.*\/etc\/passwd",
    custom=True
)
```

## Managing Patterns

Remove or modify existing patterns:

```python
# Remove a custom pattern
await SusPatterns.remove_pattern(
    r"malicious_pattern.*",
    custom=True
)

# Get all patterns
patterns = await SusPatterns.get_all_patterns()

# Get compiled patterns
compiled_patterns = await SusPatterns.get_all_compiled_patterns()
```

## Pattern Testing

Test your patterns against requests:

```python
from guard.utils import detect_penetration_attempt

@app.post("/test/patterns")
async def test_patterns(request: Request):
    is_suspicious = await detect_penetration_attempt(request)
    return {
        "suspicious": is_suspicious,
        "request_body": await request.body()
    }
``` 