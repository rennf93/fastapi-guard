---

title: Installation - FastAPI Guard
description: Learn how to install and set up FastAPI Guard, a comprehensive security middleware for FastAPI applications
keywords: fastapi guard installation, python security middleware, fastapi security setup
---

Installation
============

Install `fastapi-guard` using pip:

```bash
pip install fastapi-guard
```

**Note**: Ensure you have Python 3.10 or higher installed.

___

Prerequisites
-------------

Before using `fastapi-guard`'s country filtering features, obtain an IPInfo token:

1. Visit [IPInfo's website](https://ipinfo.io/signup) to create a free account.
2. After signing up, you'll receive an API token.
3. The free tier includes:
   - Up to 50,000 requests per month.
   - Access to IP to Country database.
   - Daily database updates.
   - IPv4 & IPv6 support.

Note: The IPInfo token is only required when using the country filtering features (`blocked_countries`, `whitelist_countries` and/or `block_cloud_providers`).

**Usage Example**:

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.handlers.ipinfo_handler import IPInfoManager

app = FastAPI()
config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_ipinfo_token_here"),  # NOTE: Required when using country blocking
    enable_redis=True,  # Enabled by default, disable to use in-memory storage
    redis_url="redis://localhost:6379/0",
    redis_prefix="prod:security:",
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
    blocked_countries=["AR", "IT"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    custom_log_file="security.log",
)

app.add_middleware(SecurityMiddleware, config=config)
```

**Note**: When Redis is disabled:
- Rate limiting and IP bans become instance-local
- Cloud provider IP ranges refresh every hour
- Penetration patterns reset on app restart

___

Secure Proxy Configuration
---------------------------

If your application is behind a proxy or load balancer, configure trusted proxies:

```python
config = SecurityConfig(
    # Security configuration for proxies
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # Only trust specific IPs/ranges
    trusted_proxy_depth=1,  # Default proxy depth
    trust_x_forwarded_proto=True,  # Trust X-Forwarded-Proto from trusted proxies

    # Other config options...
)
```

This prevents IP spoofing attacks via X-Forwarded-For header manipulation.
