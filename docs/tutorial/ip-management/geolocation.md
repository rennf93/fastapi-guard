---
title: IP Geolocation - FastAPI Guard
description: Configure country-based IP filtering and geolocation features using IPInfo's database in FastAPI Guard
keywords: ip geolocation, country blocking, ipinfo integration, location filtering
---

# IP Geolocation

FastAPI Guard accepts an arbitrary class that implements geolocation and country-based filtering. All it needs is to implement the following protocol:

```python
class GeographicalIPHandler(Protocol):
    """
    Protocol for geographical IP handler.
    """

    @property
    def is_initialized(self) -> bool: ...

    async def initialize(self) -> None: ...

    async def initialize_redis(self, redis_handler: "RedisManager") -> None: ...

    def get_country(self, ip: str) -> str | None: ...
```

It provides an implementation that uses the [ipinfo.io](https://ipinfo.io/signup) service:

```python
from guard.handlers.ipinfo_handler import IPInfoManager
```

The geolocation handler is only initialized and used when country filtering is configured, improving performance for applications that don't need these features.

## Setup

### Option 1: Using the built-in IPInfoHandler

1. Get your IPInfo token from [ipinfo.io](https://ipinfo.io/signup)
2. Configure geolocation in your app:

```python
config = SecurityConfig(
    geographical_ip_handler=IPInfoManager("your_ipinfo_token_here"),  # NOTE: Required when using country filtering
    blocked_countries=["CN", "RU"],  # Block specific countries
    whitelist_countries=["US", "CA"],
    db_path="custom/ipinfo.db",  # Optional custom database path
    block_cloud_providers={"AWS", "GCP"}  # Case-sensitive provider names
)
```

### Option 2: Providing a custom geographical IP handler

```python

class CustomGeographicalIPHandler:
    """
    Your custom class.
    """

    @property
    def is_initialized(self) -> bool:
        # your implementation
        ...

    async def initialize(self) -> None:
        # your implementation
        ...

    async def initialize_redis(self, redis_handler: "RedisManager") -> None:
        # your implementation
        ...

    def get_country(self, ip: str) -> str | None:
        # your implementation
        ...


config = SecurityConfig(
    geographical_ip_handler=CustomGeographicalIPHandler(),
    blocked_countries=["CN", "RU"],  # Block specific countries
    whitelist_countries=["US", "CA"],
    db_path="custom/ipinfo.db",  # Optional custom database path
    block_cloud_providers={"AWS", "GCP"}  # Case-sensitive provider names
)
```

## Country Blocking

Block requests from specific countries using ISO 3166-1 alpha-2 country codes:

```python
config = SecurityConfig(
    geographical_ip_handler=IPInfoManager("your_ipinfo_token_here"),  # NOTE: Required when using country filtering
    blocked_countries=[
        "CN",  # China
        "RU",  # Russia
        "IR",  # Iran
        "KP"   # North Korea
    ]
)
```

## Country Whitelisting

Only allow requests from specific countries:

```python
config = SecurityConfig(
    geographical_ip_handler=IPInfoManager("your_ipinfo_token_here"),  # NOTE: Required when using country filtering
    whitelist_countries=[
        "US",  # United States
        "CA",  # Canada
        "GB",  # United Kingdom
        "AU"   # Australia
    ]
)
```

## Custom Geolocation Logic

You can also use the `IPInfoManager` directly for custom geolocation logic:

```python
from guard.handlers.ipinfo_handler import IPInfoManager

ipinfo_db = IPInfoManager(token="your_ipinfo_token_here")  # NOTE: Required when using custom geolocation
await ipinfo_db.initialize()

@app.get("/country/{ip}")
async def get_ip_country(ip: str):
    country = ipinfo_db.get_country(ip)
    return {"ip": ip, "country": country}
```