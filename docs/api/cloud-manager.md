---
title: CloudManager API - FastAPI Guard
description: API reference for managing and detecting IP addresses from major cloud providers
keywords: cloud ip detection, aws ip ranges, gcp ip ranges, azure ip ranges
---

# CloudManager

The `CloudManager` class manages detection of IP addresses from major cloud providers. It uses a singleton pattern to ensure only one instance exists throughout the application.

## Class Definition

```python
class CloudManager:
    _instance = None
    ip_ranges: dict[str, set[ipaddress.IPv4Network]]
    redis_handler: Any = None
    logger: logging.Logger

    def __new__(cls: type["CloudManager"]) -> "CloudManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.ip_ranges = {
                "AWS": set(),
                "GCP": set(),
                "Azure": set(),
            }
            cls._instance.redis_handler = None
            cls._instance.logger = logging.getLogger(__name__)
            # IP ranges are loaded on-demand, not at initialization
        return cls._instance
```

## Redis Integration
When Redis is enabled, CloudManager automatically:
- Caches cloud IP ranges in Redis with 1-hour TTL
- Uses cached ranges if available
- Synchronizes ranges across instances

## Methods

### refresh

```python
def refresh(self):
    """
    Refresh IP ranges from all cloud providers.
    """
```

### is_cloud_ip

```python
def is_cloud_ip(
    self,
    ip: str,
    providers: set[str]
) -> bool:
    """
    Check if an IP belongs to specified cloud providers.

    Args:
        ip: IP address to check
        providers: Set of provider names ('AWS', 'GCP', 'Azure')
    """
```

## Usage Example

```python
from guard.handlers.cloud_handler import cloud_handler

# The singleton instance is already created

# Check if IP is from AWS
is_aws = cloud_handler.is_cloud_ip("54.239.28.85", {"AWS"})

# Check multiple providers
is_cloud = cloud_handler.is_cloud_ip(
    "35.186.224.25",
    {"AWS", "GCP", "Azure"}
)

# Refresh IP ranges manually if needed
cloud_handler.refresh()  # Synchronous refresh
await cloud_handler.refresh_async()  # Asynchronous with Redis
```