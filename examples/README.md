FastAPI Guard Example App
==========================

This example demonstrates how to use FastAPI Guard as middleware in your FastAPI application.

___

Playground
----------

You can try FastAPI Guard without installation at the interactive demo site:

**[https://playground.fastapi-guard.com](https://playground.fastapi-guard.com)**

___

Running the example
-------------------

Using Docker Compose
-------------

```bash
# Start the example app and Redis
docker compose up

# Restart
docker compose restart

# Stop
docker compose down
```

___

Available endpoints
-------------------

- `/` - Test app (various scenarios)
- `/ip` - Return client IP address
- `/test` - Test endpoint with query parameters

___

Environment variables
---------------------

- `IPINFO_TOKEN` - Token for IPInfo geolocation (required for country blocking)
- `REDIS_URL` - URL for Redis connection (default: `redis://localhost:6379`)
- `REDIS_PREFIX` - Prefix for Redis keys (default: `fastapi_guard:`)

___

Configuration
-------------

See the configuration in `main.py` for an example of how to set up the middleware with various security options.
