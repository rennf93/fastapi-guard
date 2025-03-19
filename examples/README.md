# FastAPI Guard Example App

This example demonstrates how to use FastAPI Guard as middleware in your FastAPI application.

## Running the example

### Using Docker Compose

```bash
# Start the example app and Redis
docker compose up --build

# Restart
docker compose restart

# Stop
docker compose down
```

## Available endpoints

- `/` - Test app (various scenarios)
- `/ip` - Return client IP address
- `/test` - Test endpoint with query parameters

## Environment variables

- `IPINFO_TOKEN` - Token for IPInfo geolocation (required for country blocking)
- `REDIS_URL` - URL for Redis connection (default: `redis://localhost:6379`)
- `REDIS_PREFIX` - Prefix for Redis keys (default: `fastapi_guard:`)

## Configuration

See the configuration in `main.py` for an example of how to set up the middleware with various security options.