---
title: IP Geolocation - FastAPI Guard
description: Configure country-based IP filtering and geolocation features using IPInfo's database in FastAPI Guard
keywords: ip geolocation, country blocking, ipinfo integration, location filtering
---

# IP Geolocation

FastAPI Guard uses IPInfo's database for IP geolocation and country-based filtering.

## Setup

1. Get your IPInfo token from [ipinfo.io](https://ipinfo.io/signup)
2. Configure geolocation in your app:

```python
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here",
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
    ipinfo_token="your_ipinfo_token_here",
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
    ipinfo_token="your_ipinfo_token_here",
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

ipinfo_db = IPInfoManager(token="your_ipinfo_token_here")
await ipinfo_db.initialize()

@app.get("/country/{ip}")
async def get_ip_country(ip: str):
    country = ipinfo_db.get_country(ip)
    return {"ip": ip, "country": country}
```