---
title: FastAPI Guard - Security Middleware for FastAPI
description: Comprehensive security library for FastAPI applications providing IP control, request logging, and penetration detection
keywords: fastapi, security, middleware, python, ip control
---

# FastAPI Guard

![FastAPI Guard Logo](assets/big_logo.svg)

[![PyPI version](https://badge.fury.io/py/fastapi-guard.svg?cache=none)](https://badge.fury.io/py/fastapi-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml)
[![Release](https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml)
[![CodeQL](https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml)
[![Downloads](https://pepy.tech/badge/fastapi-guard)](https://pepy.tech/project/fastapi-guard)

`fastapi-guard` is a comprehensive security library for FastAPI applications, providing middleware to control IPs, log requests, and detect penetration attempts. It integrates seamlessly with FastAPI to offer robust protection against various security threats, ensuring your application remains secure and reliable.

## Quick Start

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    ipinfo_token="your_token_here",
    rate_limit=100,
    auto_ban_threshold=5
)

app.add_middleware(SecurityMiddleware, config=config)
```

## Features

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Limit the number of requests from a single IP.
- **Automatic IP Banning**: Automatically ban IPs after a certain number of suspicious requests.
- **Penetration Attempt Detection**: Detect and log potential penetration attempts.
- **Custom Logging**: Log security events to a custom file.
- **CORS Configuration**: Configure CORS settings for your FastAPI application.
- **Cloud Provider IP Blocking**: Block requests from cloud provider IPs (AWS, GCP, Azure).
- **IP Geolocation**: Use IPInfo.io API to determine the country of an IP address.

## Documentation

- [Installation](installation.md)
- [First Steps](tutorial/first-steps.md)
- [IP Management](tutorial/ip-management/banning.md)
- [Security Features](tutorial/security/rate-limiting.md)
- [API Reference](api/overview.md)

[📖 **Learn More in the Tutorial**](tutorial/first-steps.md)