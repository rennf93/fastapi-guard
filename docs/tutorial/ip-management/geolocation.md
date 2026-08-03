---

title: IP Geolocation - FastAPI Guard
description: Configure country-based IP filtering and geolocation features using IPInfo's database in FastAPI Guard
keywords: ip geolocation, country blocking, ipinfo integration, location filtering
---

IP Geolocation
==============

FastAPI Guard accepts an arbitrary class that implements geolocation and country-based filtering. All it needs is to implement the following protocol:

```python
class GeoIPHandler(Protocol):
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
from guard import IPInfoManager
```

The geolocation handler is only initialized and used when country filtering is configured, improving performance for applications that don't need these features.

___

Setup
-----

Option 1: Using the built-in IPInfoHandler
-------------------------------------------

1. Get your IPInfo token from [ipinfo.io](https://ipinfo.io/signup)
2. Configure geolocation in your app:

```python
config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),  # NOTE: Required when using country filtering
    blocked_countries=["CN", "RU"],  # Block specific countries
    whitelist_countries=["US", "CA"],  # Exempt from blocked_countries (not a restrict-to list)
    db_path="custom/ipinfo.db",  # Optional custom database path
    block_cloud_providers={"AWS", "GCP"}  # Case-sensitive provider names
)
```

These options are shown together for reference; they are independent and you normally set only the ones you need. In particular, `whitelist_countries` at this global level **exempts** countries from `blocked_countries` — it does not restrict traffic to those countries. See [Country Whitelisting](#country-whitelisting) below for the exact semantics and how to restrict access to a set of countries.

Option 2: Providing a custom geographical IP handler
----------------------------------------------------

```python

class CustomGeoIPHandler:
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
    geo_ip_handler=CustomGeoIPHandler(),
    blocked_countries=["CN", "RU"],  # Block specific countries
    whitelist_countries=["US", "CA"],  # Exempt from blocked_countries (not a restrict-to list)
    db_path="custom/ipinfo.db",  # Optional custom database path
    block_cloud_providers={"AWS", "GCP"}  # Case-sensitive provider names
)
```

___

Country Blocking
----------------

Block requests from specific countries using ISO 3166-1 alpha-2 country codes:

```python
config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),  # NOTE: Required when using country filtering
    blocked_countries=[
        "CN",  # China
        "RU",  # Russia
        "IR",  # Iran
        "KP"   # North Korea
    ]
)
```

___

Country Whitelisting
--------------------

At the global `SecurityConfig` level, `whitelist_countries` is an **exemption** from `blocked_countries`, not a restrict-to list. A country in `whitelist_countries` is always allowed — it wins even if it also appears in `blocked_countries` — and a country in **neither** list is still allowed. With no `blocked_countries` set, `whitelist_countries` has no effect on its own.

Use it to carve safe countries out of a block list:

```python
config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),  # NOTE: Required when using country filtering
    blocked_countries=["CN", "RU"],
    whitelist_countries=["US", "CA"],  # always allowed, even if also in blocked_countries
)
```

Here CN and RU are blocked, US and CA are guaranteed allowed (redundant in this example since neither is in the block list), and every other country (DE, GB, BR, …) is also allowed. `whitelist_countries` does **not** block countries that are not listed.

To **restrict** access to specific countries — allow only a set and block everyone else, including unknown/missing countries — use the route-level `allow_countries` decorator instead. The global `whitelist_countries` is exemption-only by design; `allow_countries` is a true allow-list:

```python
from guard import SecurityConfig, SecurityDecorator

config = SecurityConfig(geo_ip_handler=IPInfoManager("your_ipinfo_token_here"))
guard_deco = SecurityDecorator(config)

@app.get("/api/us-only")
@guard_deco.allow_countries(["US", "CA"])
def us_only_endpoint():
    return {"data": "US and Canada only — all other countries blocked"}
```

See [Access Control Decorators](../decorators/access-control.md#allow-only-specific-countries) for the full route-level API. `block_cloud_providers` is independent of both: a cloud-provider IP is blocked regardless of country, even a whitelisted one.

___

Custom Geolocation Logic
------------------------

You can also use the `IPInfoManager` directly for custom geolocation logic:

```python
from guard import IPInfoManager

ipinfo_db = IPInfoManager(token="your_ipinfo_token_here")  # NOTE: Required when using custom geolocation
await ipinfo_db.initialize()

@app.get("/country/{ip}")
async def get_ip_country(ip: str):
    country = ipinfo_db.get_country(ip)
    return {"ip": ip, "country": country}
```
