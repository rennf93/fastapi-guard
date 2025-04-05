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
) -> bool:
    """
    Remove a pattern from the detection system.

    Returns:
        bool: True if pattern was successfully removed, False otherwise
    """
```

### get_default_patterns

```python
@classmethod
async def get_default_patterns(cls) -> list[str]:
    """
    Retrieve only the default patterns.

    Returns:
        list[str]: A list containing only default patterns.
    """
```

### get_custom_patterns

```python
@classmethod
async def get_custom_patterns(cls) -> list[str]:
    """
    Retrieve only the custom patterns.

    Returns:
        list[str]: A list containing only custom patterns.
    """
```

### get_all_patterns

```python
@classmethod
async def get_all_patterns(cls) -> list[str]:
    """
    Get all registered patterns (both default and custom).
    """
```

### get_default_compiled_patterns

```python
@classmethod
async def get_default_compiled_patterns(cls) -> list[re.Pattern]:
    """
    Retrieve only the default compiled patterns.

    Returns:
        list[re.Pattern]: A list containing only default compiled patterns.
    """
```

### get_custom_compiled_patterns

```python
@classmethod
async def get_custom_compiled_patterns(cls) -> list[re.Pattern]:
    """
    Retrieve only the custom compiled patterns.

    Returns:
        list[re.Pattern]: A list containing only custom compiled patterns.
    """
```

### get_all_compiled_patterns

```python
@classmethod
async def get_all_compiled_patterns(cls) -> list[re.Pattern]:
    """
    Get all compiled patterns (both default and custom).
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

# Get default patterns only
default_patterns = await SusPatternsManager.get_default_patterns()

# Get custom patterns only
custom_patterns = await SusPatternsManager.get_custom_patterns()

# Get all patterns
all_patterns = await SusPatternsManager.get_all_patterns()

# Remove pattern (returns True if successfully removed)
success = await SusPatternsManager.remove_pattern(
    r"malicious_pattern.*",
    custom=True
)
```