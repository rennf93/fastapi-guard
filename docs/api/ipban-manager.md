---
title: IPBanManager API - FastAPI Guard
description: API reference for FastAPI Guard's IP banning system, including automatic and manual IP management
keywords: ip ban api, ban management, ip blocking api, security api
---

# IPBanManager

The `IPBanManager` class handles temporary IP bans in your FastAPI application.

## Overview

```python
from guard.handlers.ipban_handler import IPBanManager

ip_ban_manager = IPBanManager()
```

The `IPBanManager` uses an in-memory cache to track banned IPs and their ban durations.

## Methods

### ban_ip

Ban an IP address for a specified duration.

```python
async def ban_ip(ip: str, duration: int) -> None
```

**Parameters**:
- `ip`: The IP address to ban
- `duration`: Ban duration in seconds

**Example**:
```python
await ip_ban_manager.ban_ip("192.168.1.1", 3600)  # Ban for 1 hour
```

### is_ip_banned

Check if an IP address is currently banned.

```python
async def is_ip_banned(ip: str) -> bool
```

**Parameters**:
- `ip`: The IP address to check

**Returns**:
- `bool`: True if the IP is banned, False otherwise

**Example**:
```python
is_banned = await ip_ban_manager.is_ip_banned("192.168.1.1")
```

### reset

Reset all banned IPs.

```python
async def reset() -> None
```

**Example**:
```python
await ip_ban_manager.reset()
```

## Usage with SecurityMiddleware

The `IPBanManager` is automatically integrated when you use the `SecurityMiddleware`:

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600  # Ban for 1 hour
)

app.add_middleware(SecurityMiddleware, config=config)
```