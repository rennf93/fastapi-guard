---
title: Getting Started with FastAPI Guard
description: First steps guide for implementing FastAPI Guard security features in your FastAPI application
keywords: fastapi security tutorial, fastapi guard setup, python security middleware
---

# First Steps

Let's start with a simple example that shows how to add FastAPI Guard to your application.

## Create a FastAPI application

First, create a new FastAPI application:

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()
```

## Configure Security Settings

Create a `SecurityConfig` instance with your desired settings:

```python
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here",  # Required for geolocation
    rate_limit=100,  # Max requests per minute
    auto_ban_threshold=5,  # Ban after 5 suspicious requests
    custom_log_file="security.log"
)
```

## Add the Middleware

Add the security middleware to your application:

```python
app.add_middleware(SecurityMiddleware, config=config)
```

## Complete Example

Here's a complete example showing basic usage:

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here",
    whitelist=["192.168.1.1"],
    blacklist=["10.0.0.1"],
    blocked_countries=["AR", "IT"],
    rate_limit=100,
    custom_log_file="security.log"
)

app.add_middleware(SecurityMiddleware, config=config)

@app.get("/")
async def root():
    return {"message": "Hello World"}
```

## Run the Application

Run your application using uvicorn:

```bash
uvicorn main:app --reload
```

Your API is now protected by FastAPI Guard! 🛡️

## What's Next

- Learn about [IP Management](ip-management/banning.md)
- Configure [Rate Limiting](security/rate-limiting.md)
- Set up [Penetration Detection](security/penetration-detection.md)