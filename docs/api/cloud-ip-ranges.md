---
title: CloudIPRanges API - FastAPI Guard
description: API reference for managing and detecting IP addresses from major cloud providers
keywords: cloud ip detection, aws ip ranges, gcp ip ranges, azure ip ranges
---

# CloudIPRanges

The `CloudIPRanges` class manages detection of IP addresses from major cloud providers.

## Class Definition

```python
class CloudIPRanges:
    def __init__(self):
        """
        Initialize cloud IP ranges manager.
        """
        self.ip_ranges: Dict[str, Set[ipaddress.IPv4Network]] = {}
        self.refresh()
```

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
    providers: Set[str]
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
from guard.cloud_ips import cloud_ip_ranges

# Refresh IP ranges
cloud_ip_ranges.refresh()

# Check if IP is from AWS
is_aws = cloud_ip_ranges.is_cloud_ip("54.239.28.85", {"AWS"})

# Check multiple providers
is_cloud = cloud_ip_ranges.is_cloud_ip(
    "35.186.224.25",
    {"AWS", "GCP", "Azure"}
)
``` 