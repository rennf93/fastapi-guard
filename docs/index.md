---
title: FastAPI Guard - Security Middleware for FastAPI
description: Comprehensive security library for FastAPI applications providing IP control, request logging, and penetration detection
keywords: fastapi, security, middleware, python, ip control, penetration detection, cybersecurity
---

# FastAPI Guard

![FastAPI Guard Logo](assets/big_logo.svg)

[![PyPI version](https://badge.fury.io/py/fastapi-guard.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4)](https://badge.fury.io/py/fastapi-guard)
[![Release](https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml)

[![pages-build-deployment](https://github.com/rennf93/fastapi-guard/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages)](https://github.com/rennf93/fastapi-guard/actions/workflows/pages/pages-build-deployment)
[![Docs Update](https://github.com/rennf93/fastapi-guard/actions/workflows/docs.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/docs.yml)
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
    enable_redis=False,
    rate_limit=100,
    auto_ban_threshold=5
)

app.add_middleware(SecurityMiddleware, config=config)
```

## Example App

Inside [examples](https://github.com/rennf93/fastapi-guard/tree/master/examples), you can find a simple example app that demonstrates how to use FastAPI Guard.

You can also download the example app as a Docker container from [GitHub Container Registry](https://github.com/orgs/rennf93/packages/container/fastapi-guard-example).

```bash
# Pull the latest version
docker pull ghcr.io/rennf93/fastapi-guard-example:latest

# Or pull a specific version (matches library releases)
docker pull ghcr.io/rennf93/fastapi-guard-example:v1.2.2
```

### Running the Example App

#### Using Docker Compose (Recommended)

The easiest way to run the example app is with Docker Compose, which automatically sets up Redis:

```bash
# Clone the repository
git clone https://github.com/rennf93/fastapi-guard.git
cd fastapi-guard/examples

# Start the app with Redis
docker compose up
```

This will start both the FastAPI Guard example app and Redis service. The app will be available at http://0.0.0.0:8000.

#### Using Docker Container Only

Alternatively, you can run just the container:

```bash
# Run with default settings
docker run -host 0.0.0.0 -p 8000:8000 ghcr.io/rennf93/fastapi-guard-example:latest

# Run with custom Redis connection
docker run -host 0.0.0.0 -p 8000:8000
 -e REDIS_URL=redis://your-redis-host:your-redis-port
 -e REDIS_PREFIX=your-redis-prefix
 -e IPINFO_TOKEN=your-ipinfo-token
 ghcr.io/rennf93/fastapi-guard-example:latest
```

The example app includes endpoints to test various security features of FastAPI Guard. Access the Swagger documentation at http://0.0.0.0:8000/docs after running the container.

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
- **Flexible Storage**: Choose between Redis-backed distributed state or in-memory storage
- **Automatic Fallback**: Seamless operation with/without Redis connection

## Documentation

- [Installation](installation.md)
- [First Steps](tutorial/first-steps.md)
- [IP Management](tutorial/ip-management/banning.md)
- [Rate Limiting](tutorial/ip-management/rate-limiter.md)
- [API Reference](api/overview.md)
- [Redis Integration Guide](tutorial/redis-integration/caching.md)
- [Example App](tutorial/examples/example-app.md)

[📖 **Learn More in the Tutorial**](tutorial/first-steps.md)