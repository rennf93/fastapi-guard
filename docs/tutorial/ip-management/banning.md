---
title: IP Banning - FastAPI Guard
description: Implement automatic and manual IP banning in FastAPI applications using FastAPI Guard's IPBanManager
keywords: ip banning, ip blocking, security middleware, fastapi security
---

# IP Banning

FastAPI Guard provides powerful IP banning capabilities through the `IPBanManager`.

## Automatic IP Banning

Configure automatic IP banning based on suspicious activity:

```python
config = SecurityConfig(
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    auto_ban_duration=3600,  # Ban duration in seconds (1 hour)
)
```

## Manual IP Banning

You can also manually ban IPs using the `IPBanManager`:

```python
from guard.handlers.ipban_handler import ip_ban_manager

@app.post("/admin/ban/{ip}")
async def ban_ip(ip: str, duration: int = 3600):
    await ip_ban_manager.ban_ip(ip, duration)
    return {"message": f"IP {ip} banned for {duration} seconds"}
```

## Checking Ban Status

Check if an IP is currently banned:

```python
@app.get("/admin/check/{ip}")
async def check_ban(ip: str):
    is_banned = await ip_ban_manager.is_ip_banned(ip)
    return {"ip": ip, "banned": is_banned}
```

## Reset All Bans

Clear all active IP bans:

```python
@app.post("/admin/reset")
async def reset_bans():
    await ip_ban_manager.reset()
    return {"message": "All IP bans cleared"}