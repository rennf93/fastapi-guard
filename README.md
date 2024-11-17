# FastAPI Guard

[![PyPI version](https://badge.fury.io/py/fastapi-guard.svg?cache=none)](https://badge.fury.io/py/fastapi-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml)
[![Release](https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml)
[![CodeQL](https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml/badge.svg)](https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml)

`fastapi-guard` is a security library for FastAPI that provides middleware to control IPs, log requests, and detect penetration attempts. It integrates seamlessly with FastAPI to offer robust protection against various security threats.

## Prerequisites

Before using `fastapi-guard`, you'll need to obtain an IPInfo token:

1. Visit [IPInfo's website](https://ipinfo.io/signup) to create a free account
2. After signing up, you'll receive an API token
3. The free tier includes:
   - Up to 50,000 requests per month
   - Access to IP to Country database
   - Daily database updates
   - IPv4 & IPv6 support

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

## Installation

To install `fastapi-guard`, use pip:

```
pip install fastapi-guard
```

## Usage

### Basic Setup

To use `fastapi-guard`, you need to configure the middleware in your FastAPI application. Here's a basic example:

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

# Define your security configuration
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here",  # Required for IP geolocation
    whitelist=["192.168.1.1"],
    blacklist=["10.0.0.1"],
    blocked_countries=["AR", "IT"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    custom_log_file="security.log",
    rate_limit=100,
    enforce_https=True,
    enable_cors=True,
    cors_allow_origins=["*"],
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Custom-Header"],
    cors_max_age=600,
    block_cloud_providers={"AWS", "GCP", "Azure"},
)

# Add the security middleware
app.add_middleware(SecurityMiddleware, config=config)

@app.get("/")
async def read_root():
    return {"message": "Hello, World!"}
```

### IP Whitelisting and Blacklisting

You can control access based on IP addresses using the `whitelist` and `blacklist` options in the `SecurityConfig`.

```python
config = SecurityConfig(
    whitelist=["192.168.1.1"],
    blacklist=["10.0.0.1"],
)
```

### User Agent Filtering

Block requests from specific user agents by adding patterns to the `blocked_user_agents` list.

```python
config = SecurityConfig(
    blocked_user_agents=["curl", "wget"],
)
```

### Rate Limiting

Limit the number of requests from a single IP using the `rate_limit` option.

```python
config = SecurityConfig(
    rate_limit=100,  # Maximum 100 requests per minute
)
```

### Automatic IP Banning

Automatically ban IPs after a certain number of suspicious requests using the `auto_ban_threshold` and `auto_ban_duration` options.

```python
config = SecurityConfig(
    auto_ban_threshold=5,  # Ban IP after 5 suspicious requests
    auto_ban_duration=86400,  # Ban duration in seconds (1 day)
)
```

### Penetration Attempt Detection

Detect and log potential penetration attempts using the `detect_penetration_attempt` function.

```python
from fastapi import Request
from guard.utils import detect_penetration_attempt

@app.post("/submit")
async def submit_data(request: Request):
    if await detect_penetration_attempt(request):
        return {"error": "Potential attack detected"}
    return {"message": "Data submitted successfully"}
```

### Custom Logging

Log security events to a custom file using the `custom_log_file` option.

```python
config = SecurityConfig(
    custom_log_file="security.log",
)
```

### CORS Configuration

Configure CORS settings for your FastAPI application using the `enable_cors` and related options.

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=["*"],
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Custom-Header"],
    cors_max_age=600,
)
```

### Cloud Provider IP Blocking

Block requests from cloud provider IPs (AWS, GCP, Azure) using the `block_cloud_providers` option.

```python
config = SecurityConfig(
    block_cloud_providers={"AWS", "GCP", "Azure"},
)
```

### IP Geolocation and Country Blocking

The library uses IPInfo's [IP to Country database](https://ipinfo.io/products/free-ip-database) which provides:

- Full accuracy IP to country mapping
- Daily updates
- Support for both IPv4 and IPv6
- Country and continent information
- ASN details

To use the geolocation features:

```python
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here",  # Required
    blocked_countries=["AR", "IT"],  # Block specific countries using ISO 3166-1 alpha-2 codes
    whitelist_countries=["US", "CA"]  # Optional: Only allow specific countries
)
```

The database is automatically downloaded and cached locally when the middleware starts, and it's updated daily to ensure accuracy.

## Advanced Usage

### Custom Request Check

You can define a custom function to perform additional checks on the request using the `custom_request_check` option.

```python
from fastapi import Request, Response

async def custom_check(request: Request) -> Optional[Response]:
    if "X-Custom-Header" not in request.headers:
        return Response("Missing custom header", status_code=400)
    return None

config = SecurityConfig(
    custom_request_check=custom_check,
)
```

### Custom Response Modifier

You can define a custom function to modify the response before it's sent using the `custom_response_modifier` option.

```python
from fastapi import Response

async def custom_modifier(response: Response) -> Response:
    response.headers["X-Custom-Header"] = "CustomValue"
    return response

config = SecurityConfig(
    custom_response_modifier=custom_modifier,
)
```

## Detailed Configuration Options

### SecurityConfig

The `SecurityConfig` class defines the structure for security configuration, including IP whitelists and blacklists, blocked countries, blocked user agents, rate limiting, automatic IP banning, IP2Location settings, HTTPS enforcement, custom hooks, CORS settings, and blocking of cloud provider IPs.

#### Attributes

- `ipinfo_token`: str - The IPInfo API token required for IP geolocation functionality.
- `whitelist`: Optional[List[str]] - A list of IP addresses or ranges that are always allowed. If set to None, no whitelist is applied.
- `blacklist`: List[str] - A list of IP addresses or ranges that are always blocked.
- `blocked_countries`: List[str] - A list of country codes whose IP addresses should be blocked.
- `blocked_user_agents`: List[str] - A list of user agent strings or patterns that should be blocked.
- `auto_ban_threshold`: int - The threshold for auto-banning an IP address after a certain number of requests.
- `auto_ban_duration`: int - The duration in seconds for which an IP address should be banned after reaching the auto-ban threshold.
- `custom_log_file`: Optional[str] - The path to a custom log file for logging security events.
- `custom_error_responses`: Dict[int, str] - A dictionary of custom error responses for specific HTTP status codes.
- `rate_limit`: int - The maximum number of requests allowed per minute from a single IP.
- `enforce_https`: bool - Whether to enforce HTTPS connections. If True, all HTTP requests will be redirected to HTTPS.
- `custom_request_check`: Optional[Callable[[Request], Awaitable[Optional[Response]]]] - A custom function to perform additional checks on the request. If it returns a Response, that response will be sent instead of continuing the middleware chain.
- `custom_response_modifier`: Optional[Callable[[Response], Awaitable[Response]]] - A custom function to modify the response before it's sent.
- `enable_cors`: bool - Whether to enable CORS.
- `cors_allow_origins`: List[str] - A list of origins that are allowed to access the API.
- `cors_allow_methods`: List[str] - A list of methods that are allowed to access the API.
- `cors_allow_headers`: List[str] - A list of headers that are allowed in CORS requests.
- `cors_allow_credentials`: bool - Whether to allow credentials in CORS requests.
- `cors_expose_headers`: List[str] - A list of headers that are exposed in CORS responses.
- `cors_max_age`: int - The maximum age in seconds that the results of a preflight request can be cached.
- `block_cloud_providers`: Optional[Set[str]] - A set of cloud provider names to block. Supported values: 'AWS', 'GCP', 'Azure'.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

Renzo Franceschini - [rennf93@gmail.com](mailto:rennf93@gmail.com)

## Acknowledgements

- [FastAPI](https://fastapi.tiangolo.com/)
- [IPInfo](https://ipinfo.io/)
- [aiohttp](https://docs.aiohttp.org/)
- [cachetools](https://cachetools.readthedocs.io/)
- [requests](https://docs.python-requests.org/)
- [uvicorn](https://www.uvicorn.org/)
