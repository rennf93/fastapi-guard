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
    whitelist_countries=["US", "CA"]  # Optional: only allow specific countries
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

You can also use the `IPInfoDB` directly for custom geolocation logic:

```python
from guard.handlers.ipinfo_handler import IPInfoDB

ipinfo_db = IPInfoDB(token="your_ipinfo_token_here")
await ipinfo_db.initialize()

@app.get("/country/{ip}")
async def get_ip_country(ip: str):
    country = ipinfo_db.get_country(ip)
    return {"ip": ip, "country": country}
``` 