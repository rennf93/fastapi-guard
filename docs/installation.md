---
title: Installation - FastAPI Guard
description: Learn how to install and set up FastAPI Guard, a comprehensive security middleware for FastAPI applications
keywords: fastapi guard installation, python security middleware, fastapi security setup
---

# Installation

Install `fastapi-guard` using pip:

```bash
pip install fastapi-guard
```


**Note**: Ensure you have Python 3.10 or higher installed.

## Prerequisites

Before using `fastapi-guard`, obtain an IPInfo token:

1. Visit [IPInfo's website](https://ipinfo.io/signup) to create a free account.
2. After signing up, you'll receive an API token.
3. The free tier includes:
   - Up to 50,000 requests per month.
   - Access to IP to Country database.
   - Daily database updates.
   - IPv4 & IPv6 support.

**Usage Example**:

```python
from fastapi import FastAPI
from fastapi_guard.middleware import SecurityMiddleware
from fastapi_guard.models import SecurityConfig

app = FastAPI()
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here", # Required for IP geolocation
    whitelist=["192.168.1.1"],
    blacklist=["10.0.0.1"],
    blocked_countries=["AR", "IT"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    custom_log_file="security.log",
)

app.add_middleware(SecurityMiddleware, config=config)
```
