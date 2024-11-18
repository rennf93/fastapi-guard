---
title: SusPatterns API - FastAPI Guard
description: API documentation for FastAPI Guard's suspicious pattern detection and management system
keywords: security patterns, threat detection, pattern management, security rules api
---

# SusPatterns

The `SusPatterns` class manages suspicious patterns for security threat detection.

## Class Definition

```python
class SusPatterns:
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

## Usage Example

```python
from guard.sus_patterns import SusPatterns

# Add custom pattern
await SusPatterns.add_pattern(
    r"malicious_pattern.*",
    custom=True
)

# Get all patterns
patterns = await SusPatterns.get_all_patterns()

# Remove pattern
await SusPatterns.remove_pattern(
    r"malicious_pattern.*",
    custom=True
)
``` 