---
title: IPInfoManager API - FastAPI Guard
description: API documentation for IP geolocation and country-based filtering and/or cloud blocking using IPInfo's database
keywords: ip geolocation, country filtering, ipinfo integration, location detection, cloud provider blocking
---

# IPInfoManager

The `IPInfoManager` class handles IP geolocation using IPInfo's database. It uses a singleton pattern to ensure only one instance exists throughout the application.

**Performance Note**: The IPInfo database is only downloaded and initialized when country-based filtering and/or cloud blocking is configured in your application, improving startup time and reducing resource usage when these features aren't needed.

## Class Definition

```python
class IPInfoManager:
    _instance = None
    token: str
    db_path: Path
    reader: Reader | None = None
    redis_handler: Any = None

    def __new__(cls: type["IPInfoManager"], token: str, db_path: Path | None = None) -> "IPInfoManager":
        if not token:
            raise ValueError("IPInfo token is required!")

        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.token = token
            cls._instance.db_path = db_path or Path("data/ipinfo/country_asn.mmdb")
            cls._instance.reader = None
            cls._instance.redis_handler = None
        # Update token
        elif token:
            cls._instance.token = token
            # Update db_path
            if db_path is not None:
                cls._instance.db_path = db_path
        return cls._instance
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
def get_country(self, ip: str) -> str | None:
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

## Redis Caching
The database is cached in Redis with 24-hour TTL when enabled:

```python
# Get cached database
db_content = await redis.get_key("ipinfo", "database")

# Force refresh cache
await ipinfo_db.initialize()  # Will update Redis cache
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

# Get the same instance
same_db = IPInfoManager(token="your_token")  # Same instance returned
```