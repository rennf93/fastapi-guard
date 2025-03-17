# FastAPI Guard Example App

This example demonstrates how to use FastAPI Guard as middleware in your FastAPI application.

## Running the example

### Using Docker Compose

```bash
# Start the example app and Redis
make start-example

# Or start the entire stack
make start
```

### Using Poetry

```bash
# Install dependencies
make install

# Run the example
make example
```

## Available endpoints

- `/` - Hello World
- `/health` - Health check
- `/whitelist-test` - Test IP whitelist functionality
- `/blacklist-test` - Test IP blacklist functionality
- `/rate-limit-test` - Test rate limiting functionality
- `/ban-test` - Test auto-ban functionality
- `/test` - Test endpoint with query parameters
- `/protected` - Protected endpoint
- `/ip` - Return client IP address

## Environment variables

- `IPINFO_TOKEN` - Token for IPInfo geolocation (required for country blocking)
- `REDIS_URL` - URL for Redis connection (default: `redis://localhost:6379`)

## Configuration

See the configuration in `main.py` for an example of how to set up the middleware with various security options.