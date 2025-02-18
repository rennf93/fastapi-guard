---
title: RedisManager API - FastAPI Guard
description: API reference for Redis-based distributed state management
keywords: redis integration, distributed state, connection pooling, atomic operations
---

# RedisManager

The `RedisManager` class handles Redis connections and atomic operations with automatic retries.

## Class Definition

```python
class RedisManager:
    """
    Robust Redis handler with connection pooling and automatic reconnection.
    """
```

## Key Methods

### initialize
```python
async def initialize(self):
    """Initialize Redis connection with retry logic"""
```

### get_connection
```python
@asynccontextmanager
async def get_connection(self):
    """Context manager for safe Redis operations"""
```

### safe_operation
```python
async def safe_operation(self, func, *args, **kwargs):
    """Execute Redis operation with error handling"""
```

## Atomic Operations

### get_key
```python
async def get_key(self, namespace: str, key: str) -> Any:
    """Get namespaced key with prefix"""
```

### set_key
```python
async def set_key(self, namespace: str, key: str, value: Any, ttl: Optional[int]) -> bool:
    """Set namespaced key with optional TTL"""
```

### incr
```python
async def incr(self, namespace: str, key: str, ttl: Optional[int]) -> int:
    """Atomic increment with expiration"""
```

## Usage Example

```python
from guard.handlers.redis_handler import RedisManager
from guard.models import SecurityConfig

config = SecurityConfig(redis_url="redis://localhost:6379")
redis = RedisManager(config)

async def example():
    await redis.initialize()
    async with redis.get_connection() as conn:
        await conn.set("test_key", "value")

    # Atomic operation
    await redis.set_key("namespace", "key", "value", ttl=3600)
```
