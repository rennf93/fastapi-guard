---
title: Example Application - FastAPI Guard Demo
description: Learn how to use FastAPI Guard with a complete example application
keywords: fastapi-guard example, example application, security middleware demo, docker compose
---

# Example Application

FastAPI Guard comes with a fully functional example application that demonstrates its key security features. This example serves both as a reference implementation and a testing ground for your security settings.

## Features Demonstrated

The example app demonstrates:

- IP whitelist/blacklist filtering
- Rate limiting
- Penetration detection and prevention
- Auto-banning of suspicious IPs
- Geolocation-based filtering
- User agent filtering
- Redis integration

## Code Overview

The example app is built using FastAPI and shows how to integrate FastAPI Guard as middleware:

[Example Code](https://github.com/rennf93/fastapi-guard/blob/master/examples/main.py)

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

# Initialize FastAPI app
app = FastAPI(title="FastAPI Guard Playground")

# Configure FastAPI Guard
config = SecurityConfig(
    # Whitelist/Blacklist
    whitelist=["0.0.0.0/32", "0.0.0.0"],
    blacklist=["192.168.1.100/32", "192.168.1.100"],
    ...
)
app.add_middleware(SecurityMiddleware, config=config)
```

## Running the Example App

### Using Docker Compose (Recommended)

The easiest way to run the example is with Docker Compose, which automatically sets up Redis:

```bash
# Clone the repository
git clone https://github.com/rennf93/fastapi-guard.git
cd fastapi-guard/examples

# Start the app with Redis
docker compose up
```

The Docker Compose file does the following:
- Builds the FastAPI Guard example app
- Runs Redis with persistent data volume
- Connects the application to Redis
- Exposes the app on port 8000

### Docker Compose File

[Docker Compose File](https://github.com/rennf93/fastapi-guard/blob/master/examples/docker-compose.yml)

```yaml
services:
  fastapi-guard-example:
    build:
      context: .
      dockerfile: ./Dockerfile
    command: uvicorn main:app --host 0.0.0.0 --reload
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379
      - REDIS_PREFIX=${REDIS_PREFIX:-"fastapi_guard:"}
      - IPINFO_TOKEN=${IPINFO_TOKEN:-"test_token"}
    depends_on:
      redis:
        condition: service_started
  ...
```

## Test Endpoints

Once running, you can access the following endpoints:

- **`/`**: Basic endpoint to test connection and rate limiting
- **`/ip`**: Returns your client IP address as seen by the server
- **`/test?input=<script>alert(1)</script>`**: Test with various inputs to trigger penetration detection
- **`/docs`**: Swagger UI documentation for interactive testing

## Testing Security Features

You can use the included test battery to verify security features:

[Test battery](https://github.com/rennf93/fastapi-guard/blob/master/examples/test_battery.txt)

```bash
# For rate limiting (will trigger after 15 requests)
for i in {1..20}; do curl http://0.0.0.0:8000/; echo " Request $i"; sleep 0.2; done

# For XSS detection
curl "http://0.0.0.0:8000/test?input=<script>alert(1)</script>"

# For SQL injection detection
curl "http://0.0.0.0:8000/test?query=SELECT%20*%20FROM%20users"

# For path traversal detection
curl "http://0.0.0.0:8000/test?path=../../../etc/passwd"

# For command injection detection
curl "http://0.0.0.0:8000/test?cmd=;ls;pwd;"

...
```

## Environment Variables

The example app supports the following environment variables:

- `IPINFO_TOKEN`: Your IPInfo API token (default: test_token)
- `REDIS_URL`: Redis connection URL (default: redis://redis:6379)
- `REDIS_PREFIX`: Prefix for Redis keys (default: fastapi_guard:)

## Source Code

You can find the complete example code in the [examples directory](https://github.com/rennf93/fastapi-guard/tree/master/examples) of the GitHub repository.
