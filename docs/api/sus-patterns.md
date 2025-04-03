---
title: SusPatternsManager API - FastAPI Guard
description: API documentation for FastAPI Guard's suspicious pattern detection and management system
keywords: security patterns, threat detection, pattern management, security rules api
---

# SusPatternsManager

The `SusPatternsManager` class manages suspicious patterns for security threat detection.

## Class Definition

```python
class SusPatternsManager:
    """
    A singleton class that manages suspicious patterns
    for security checks.
    """
```

## Class Methods

### add_pattern

```python
@classmethod
async def add_pattern(
    cls,
    pattern: str,
    custom: bool = False
) -> None:
    """
    Add a new pattern to the detection system.
    """
```

### remove_pattern

```python
@classmethod
async def remove_pattern(
    cls,
    pattern: str,
    custom: bool = False
) -> None:
    """
    Remove a pattern from the detection system.
    """
```

### get_all_patterns

```python
@classmethod
async def get_all_patterns(cls) -> List[str]:
    """
    Get all registered patterns.
    """
```

## Pattern Synchronization
Custom patterns are stored in Redis when enabled:

```python
# Add pattern to Redis
await SusPatternsManager.add_pattern(r"malicious.*", custom=True)

# Get patterns from Redis
patterns = await redis.get_key("patterns", "custom")
```

## Usage Example

```python
from guard.handlers.suspatterns_handler import SusPatternsManager

# Add custom pattern
await SusPatternsManager.add_pattern(
    r"malicious_pattern.*",
    custom=True
)

# Get all patterns
patterns = await SusPatternsManager.get_all_patterns()

# Remove pattern
await SusPatternsManager.remove_pattern(
    r"malicious_pattern.*",
    custom=True
)
```