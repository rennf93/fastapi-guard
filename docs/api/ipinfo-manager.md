---
title: IPInfoManager API - FastAPI Guard
description: API documentation for IP geolocation and country-based filtering using IPInfo's database
keywords: ip geolocation, country filtering, ipinfo integration, location detection
---

# IPInfoManager

The `IPInfoManager` class handles IP geolocation using IPInfo's database.

## Class Definition

```python
class IPInfoManager:
    def __init__(
        self,
        token: str,
        db_path: Optional[Path] = None
    ):
        """
        Initialize IPInfoManager with IPInfo token.

        :param token: IPInfo API token
        :param db_path: Optional custom path for database storage
        """
```

## Methods

### initialize

```python
async def initialize(self):
    """
    Initialize and download the database if needed.
    """
```

### get_country

```python
def get_country(self, ip: str) -> Optional[str]:
    """
    Get country code for an IP address.
    """
```

### close

```python
def close(self):
    """
    Close the database connection.
    """
```

## Usage Example

```python
from guard.handlers.ipinfo_handler import IPInfoManager
from pathlib import Path

# Initialize with custom database location
ipinfo_db = IPInfoManager(
    token="your_token",
    db_path=Path("/custom/path/ipinfo.db") # default is ./data/ipinfo/country_asn.mmdb
)
await ipinfo_db.initialize()

# Get country for IP
country = ipinfo_db.get_country("8.8.8.8")
print(f"Country: {country}")  # Output: "US"

# Clean up
ipinfo_db.close()
```