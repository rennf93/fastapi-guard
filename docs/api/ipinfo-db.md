---
title: IPInfoDB API - FastAPI Guard
description: API documentation for IP geolocation and country-based filtering using IPInfo's database
keywords: ip geolocation, country filtering, ipinfo integration, location detection
---

# IPInfoDB

The `IPInfoDB` class handles IP geolocation using IPInfo's database.

## Class Definition

```python
class IPInfoDB:
    def __init__(self, token: str):
        """
        Initialize IPInfoDB with IPInfo token.
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
from guard.handlers.ipinfo_handler import IPInfoDB

# Initialize database
ipinfo_db = IPInfoDB(token="your_token")
await ipinfo_db.initialize()

# Get country for IP
country = ipinfo_db.get_country("8.8.8.8")
print(f"Country: {country}")  # Output: "US"

# Clean up
ipinfo_db.close()
``` 