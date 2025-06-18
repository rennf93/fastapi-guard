---

title: Custom Security Patterns - FastAPI Guard
description: Create and manage custom security patterns for detecting specific threats in your FastAPI application
keywords: security patterns, custom detection, threat patterns, security rules
---

Custom Patterns
===============

FastAPI Guard allows you to add custom patterns for detecting suspicious activity.

___

Adding Custom Patterns
-----------------------

Add your own patterns to the detection system:

```python
from guard.handlers.suspatterns_handler import SusPatternsManager

async def setup_patterns():
    # Add custom pattern
    await SusPatternsManager.add_pattern(
        r"malicious_pattern.*",
        custom=True
    )
```

___

Pattern Types
-------------

You can add patterns for different types of attacks:

```python
# Custom XSS pattern
await SusPatternsManager.add_pattern(
    r"<script\s*src=.*>",
    custom=True
)

# Custom SQL injection pattern
await SusPatternsManager.add_pattern(
    r";\s*DROP\s+TABLE",
    custom=True
)

# Custom file path pattern
await SusPatternsManager.add_pattern(
    r"\.\.\/.*\/etc\/passwd",
    custom=True
)
```

___

Managing Patterns
-----------------

Remove or modify existing patterns:

```python
# Remove a custom pattern
success = await SusPatternsManager.remove_pattern(
    r"malicious_pattern.*",
    custom=True
)
if success:
    print("Pattern removed successfully")
else:
    print("Pattern not found")

# Get all patterns (both default and custom)
all_patterns = await SusPatternsManager.get_all_patterns()

# Get only default patterns
default_patterns = await SusPatternsManager.get_default_patterns()

# Get only custom patterns
custom_patterns = await SusPatternsManager.get_custom_patterns()

# Get all compiled patterns
all_compiled_patterns = await SusPatternsManager.get_all_compiled_patterns()

# Get only default compiled patterns
default_compiled = await SusPatternsManager.get_default_compiled_patterns()

# Get only custom compiled patterns
custom_compiled = await SusPatternsManager.get_custom_compiled_patterns()
```

___

Pattern Testing
---------------

Test your patterns against requests:

```python
from guard.utils import detect_penetration_attempt

@app.post("/test/patterns")
async def test_patterns(request: Request):
    is_suspicious, trigger_info = await detect_penetration_attempt(request)
    return {
        "suspicious": is_suspicious,
        "trigger_info": trigger_info,
        "request_body": await request.body()
    }
```
