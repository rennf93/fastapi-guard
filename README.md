<p align="center">
    <a href="https://rennf93.github.io/fastapi-guard/latest/">
        <img src="https://rennf93.github.io/fastapi-guard/latest/assets/big_logo.svg" alt="FastAPI Guard">
    </a>
</p>

---

<p align="center">
    <strong>fastapi-guard is a security library for FastAPI that provides middleware to control IPs, log requests, detect penetration attempts and more. It integrates seamlessly with FastAPI to offer robust protection against various security threats.</strong>
</p>

<p align="center">
    <a href="https://badge.fury.io/py/fastapi-guard">
        <img src="https://badge.fury.io/py/fastapi-guard.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4" alt="PyPiVersion">
    </a>
    <a href="https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml">
        <img src="https://github.com/rennf93/fastapi-guard/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml">
        <img src="https://github.com/rennf93/fastapi-guard/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml">
        <img src="https://github.com/rennf93/fastapi-guard/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/rennf93/fastapi-guard/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/rennf93/fastapi-guard/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/rennf93/fastapi-guard/actions/workflows/docs.yml">
        <img src="https://github.com/rennf93/fastapi-guard/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/rennf93/fastapi-guard?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Python-3776AB.svg?style=flat&amp;logo=Python&amp;logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/FastAPI-009688.svg?style=flat&amp;logo=FastAPI&amp;logoColor=white" alt="FastAPI">
    <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&amp;logo=Redis&amp;logoColor=white" alt="Redis">
    <a href="https://pepy.tech/project/fastapi-guard">
        <img src="https://pepy.tech/badge/fastapi-guard" alt="Downloads">
    </a>
</p>

---

Documentation
=============

🌐 **[Website](https://fastapi-guard.com)** - Check out the website!

🎮 **[Join our Discord Community](https://discord.gg/ZW7ZJbjMkK)** - Connect with other developers!

📚 **[Documentation](https://rennf93.github.io/fastapi-guard)** - Full technical documentation and deep dive into its inner workings.

🕹️ **[Live Playground](https://playground.fastapi-guard.com)** - Testing playground for FastAPI Guard's features in action.

🤖 **[Monitoring Agent Integration](https://github.com/rennf93/fastapi-guard-agent)** - Monitor your FastAPI Guard instance with a monitoring agent.

___

Features
--------

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Limit the number of requests from a single IP.
- **Automatic IP Banning**: Automatically ban IPs after a certain number of suspicious requests.
- **Penetration Attempt Detection**: Detect and log potential penetration attempts.
- **HTTP Security Headers**: Comprehensive security headers management (CSP, HSTS, X-Frame-Options, etc.)
- **Custom Logging**: Log security events to a custom file.
- **CORS Configuration**: Configure CORS settings for your FastAPI application.
- **Cloud Provider IP Blocking**: Block requests from cloud provider IPs (AWS, GCP, Azure).
- **IP Geolocation**: Use a service like IPInfo.io API to determine the country of an IP address.
- **Distributed State Management**: (Optional) Redis integration for shared security state across instances
- **Flexible Storage**: Redis-enabled distributed storage or in-memory storage for single instance deployments

___

Installation
------------

To install `fastapi-guard`, use pip:

```bash
pip install fastapi-guard
```

___

Usage
-----------

Basic Setup
-----------

To use `fastapi-guard`, you need to configure the middleware in your FastAPI application. Here's a basic example:

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.handlers.ipinfo_handler import IPInfoManager

app = FastAPI()

# Define your security configuration
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here",  # Optional: IPInfo token required for IP geolocation
    ipinfo_db_path="custom/ipinfo.db",  # Optional custom database path
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
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

IP Whitelisting and Blacklisting
---------------------------------

You can control access based on IP addresses using the `whitelist` and `blacklist` options in the `SecurityConfig`.

```python
config = SecurityConfig(
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
)
```

User Agent Filtering
--------------------

Block requests from specific user agents by adding patterns to the `blocked_user_agents` list.

```python
config = SecurityConfig(
    blocked_user_agents=["curl", "wget"],
)
```

Rate Limiting
-------------

Limit the number of requests from a single IP using the `rate_limit` option.

```python
config = SecurityConfig(
    rate_limit=100,  # Maximum 100 requests per minute
)
```

Automatic IP Banning
--------------------

Automatically ban IPs after a certain number of suspicious requests using the `auto_ban_threshold` and `auto_ban_duration` options.

```python
config = SecurityConfig(
    auto_ban_threshold=5,  # Ban IP after 5 suspicious requests
    auto_ban_duration=86400,  # Ban duration in seconds (1 day)
)
```

Penetration Attempt Detection
-----------------------------

Enable penetration attempt detection using the `enable_penetration_detection` option.

```python
config = SecurityConfig(
    enable_penetration_detection=True,  # True by default
)
```

Optional: Enable `passive mode` to log suspicious activity without blocking requests.

```python
config = SecurityConfig(
    passive_mode=True,  # False by default
)
```

Custom Penetration Detection
----------------------------

Detect and log potential penetration attempts using the `detect_penetration_attempt` function.

```python
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from guard.utils import detect_penetration_attempt

@app.post("/submit")
async def submit_data(request: Request):
    is_suspicious, trigger_info = await detect_penetration_attempt(request)
    if is_suspicious:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": f"Suspicious activity detected: {trigger_info}"}
        )
    return {"message": "Data submitted successfully"}

```

Custom Logging
--------------

Log security events with console output (always enabled) and optional file logging:

```python
config = SecurityConfig(
    custom_log_file="security.log",  # Optional: adds file logging
    # custom_log_file=None,  # Default: console output only
)
```

**Note:** Console output is always enabled for visibility. File logging is only activated when `custom_log_file` is provided.

HTTP Security Headers
---------------------

Configure comprehensive security headers following OWASP best practices:

```python
config = SecurityConfig(
    security_headers={
        "enabled": True,
        "hsts": {
            "max_age": 31536000,  # 1 year
            "include_subdomains": True,
            "preload": False
        },
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://trusted.cdn.com"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "connect-src": ["'self'", "https://api.example.com"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"]
        },
        "frame_options": "DENY",
        "content_type_options": "nosniff",
        "xss_protection": "1; mode=block",
        "referrer_policy": "strict-origin-when-cross-origin",
        "permissions_policy": "geolocation=(), microphone=(), camera=()",
        "custom": {
            "X-Custom-Header": "CustomValue"
        }
    }
)
```

Key security headers supported:
- **Content Security Policy (CSP)**: Prevent XSS attacks by controlling resource loading
- **HTTP Strict Transport Security (HSTS)**: Force HTTPS connections
- **X-Frame-Options**: Prevent clickjacking attacks
- **X-Content-Type-Options**: Prevent MIME type sniffing
- **X-XSS-Protection**: Enable browser XSS filtering
- **Referrer-Policy**: Control referrer information
- **Permissions-Policy**: Restrict browser features
- **Cross-Origin Policies**: Control cross-origin resource access and embedding
- **Header Injection Prevention**: Automatic validation against injection attacks
- **CORS Security**: Secure wildcard and credentials handling

CORS Configuration
------------------

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

Cloud Provider IP Blocking
---------------------------

Block requests from cloud provider IPs (AWS, GCP, Azure) using the `block_cloud_providers` option.

```python
config = SecurityConfig(
    block_cloud_providers={"AWS", "GCP", "Azure"},
)
```

IP Geolocation and Country Blocking
------------------------------------

If you want to use `fastapi-guard`'s built-in country filtering features, you'll need to obtain an IPInfo token:

1. Visit [IPInfo's website](https://ipinfo.io/signup) to create a free account
2. After signing up, you'll receive an API token
3. The free tier includes:
   - Up to 50,000 requests per month
   - Access to IP to Country database
   - Daily database updates
   - IPv4 & IPv6 support

Note: This is only required if you use country filtering (`blocked_countries`, `whitelist_countries`). You can also provide your own handler that uses any other service.

___

Route-Level Security with Decorators
------------------------------------

FastAPI Guard provides powerful decorators that allow you to apply security controls to individual routes, giving you fine-grained control over your API endpoints.

. Basic Decorator Usage
--------------------

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.decorators import SecurityDecorator

app = FastAPI()
config = SecurityConfig()

# Create decorator instance
guard_deco = SecurityDecorator(config)

# Apply decorators to specific routes
@app.get("/api/public")
def public_endpoint():
    return {"data": "public"}

@app.get("/api/limited")
@guard_deco.rate_limit(requests=10, window=300)  # 10 requests per 5 minutes
def limited_endpoint():
    return {"data": "limited"}

@app.get("/api/restricted")
@guard_deco.require_ip(whitelist=["192.168.1.0/24"])
@guard_deco.block_countries(["CN", "RU"])
def restricted_endpoint():
    return {"data": "restricted"}

# Add global middleware
app.add_middleware(SecurityMiddleware, config=config)

# Required: Set decorator handler on app state
app.state.guard_decorator = guard_deco
```

. Available Decorators
-------------------

Access Control
- `@guard_deco.require_ip(whitelist=[], blacklist=[])` - IP address filtering
- `@guard_deco.block_countries(["CN", "RU"])` - Block specific countries
- `@guard_deco.allow_countries(["US", "CA"])` - Allow only specific countries
- `@guard_deco.block_clouds(["AWS", "GCP"])` - Block cloud provider IPs

Rate Limiting
- `@guard_deco.rate_limit(requests=10, window=60)` - Basic rate limiting
- `@guard_deco.geo_rate_limit(limits={"US": 100, "default": 50})` - Geographic rate limiting

Authentication & Headers
- `@guard_deco.require_https()` - Force HTTPS
- `@guard_deco.require_auth(type="bearer")` - Require authentication
- `@guard_deco.api_key_auth(header_name="X-API-Key")` - API key authentication
- `@guard_deco.require_headers({"X-Custom": "required"})` - Require specific headers

Content Filtering
- `@guard_deco.block_user_agents(["curl", "wget"])` - Block user agent patterns
- `@guard_deco.content_type_filter(["application/json"])` - Filter content types
- `@guard_deco.max_request_size(1048576)` - Limit request size (1MB)
- `@guard_deco.require_referrer(["myapp.com"])` - Require specific referrers

Behavioral Analysis
- `@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")` - Monitor endpoint usage
- `@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="alert")` - Monitor return patterns
- `@guard_deco.suspicious_frequency(max_frequency=0.1, window=300, action="log")` - Detect suspicious frequency

Advanced Controls
- `@guard_deco.time_window("09:00", "17:00", "UTC")` - Time-based access control
- `@guard_deco.honeypot_detection(trap_fields=["hidden_field"])` - Detect bots using honeypot fields
- `@guard_deco.bypass(checks=["rate_limit"])` - Bypass specific security checks

. Complex Route Protection
-----------------------

Combine multiple decorators for comprehensive protection:

```python
@app.post("/api/admin/sensitive")
@guard_deco.require_https()                        # Security requirement
@guard_deco.require_auth(type="bearer")            # Authentication
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])   # Access control
@guard_deco.rate_limit(requests=5, window=3600)    # Rate limiting
@guard_deco.suspicious_detection(enabled=True)     # Monitoring
def admin_endpoint():
    return {"status": "admin action"}

@app.get("/api/rewards")
@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="ban")
@guard_deco.block_countries(["CN", "RU", "KP"])
def rewards_endpoint():
    # This endpoint is protected against:
    # - Excessive usage (>50 calls/hour results in ban)
    # - Suspicious return patterns (>3 rare items/day results in ban)
    # - Geographic restrictions
    return {"reward": "rare_item", "value": 1000}
```

. Decorator Configuration Priority
-------------------------------

Security settings are applied in the following priority order:

1. Decorator Settings (highest priority)
2. Global Middleware Settings
3. Default Settings (lowest priority)

This allows routes to override global settings while maintaining sensible defaults.

___

Advanced Usage
--------------

. Secure Proxy Configuration
---------------------------

Configure trusted proxies to securely handle X-Forwarded-For headers:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # List of trusted proxy IPs or CIDR ranges
    trusted_proxy_depth=1,                           # How many proxies to expect in chain
    trust_x_forwarded_proto=True,                    # Whether to trust X-Forwarded-Proto for HTTPS detection (default: True)
)
```

When `trusted_proxies` is configured, FastAPI Guard will:
1. Only trust X-Forwarded-For headers from these IPs
2. Extract the appropriate client IP based on proxy depth
3. Prevent IP spoofing attacks through header manipulation

. Custom Geolocation Handler
---------------------------

The library implements a handler that uses IPInfo's [IP to Country database](https://ipinfo.io/products/free-ip-database), which provides:

- Full accuracy IP to country mapping
- Daily updates
- Support for both IPv4 and IPv6
- Country and continent information
- ASN details

To use the geolocation feature with this handler:

```python
from guard.protocols.geoip_handler import GeoIPHandler

config = SecurityConfig(
    geo_ip_handler=GeoIPHandler,
    blocked_countries=["AR", "IT"],   # Block specific countries using ISO 3166-1 alpha-2 codes
    whitelist_countries=["US", "CA"]  # Optional: Only allow specific countries
)
```

The database is automatically downloaded and cached locally when the middleware starts, if required, and it's updated daily to ensure accuracy.

You can also use a service other than IPInfo, as long as you implement the same protocol:

```python
# implement the required methods of guard.protocols.geoip_handler.GeoIPHandler protocol

class GeoIPHandler:
    """
    Your custom class.
    """

    @property
    def is_initialized(self) -> bool:
        # your implementation
        ...

    async def initialize(self) -> None:
        # your implementation
        ...

    async def initialize_redis(self, redis_handler: "RedisManager") -> None:
        # your implementation
        ...

    def get_country(self, ip: str) -> str | None:
        # your implementation
        ...


config = SecurityConfig(
    geo_ip_handler=GeoIPHandler,
    blocked_countries=["AR", "IT"],  # Block specific countries using ISO 3166-1 alpha-2 codes
    whitelist_countries=["US", "CA"]  # Optional: Only allow specific countries
)
```

. Custom Request Check
--------------------

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

. Custom Response Modifier
------------------------

You can define a custom function to modify the response before it's sent using the `custom_response_modifier` option.

```python
from fastapi import Response
from fastapi.responses import JSONResponse

async def custom_modifier(response: Response) -> Response:
    # Add custom headers
    response.headers["X-Custom-Header"] = "CustomValue"

    # Convert text responses to FastAPI-style JSON responses
    if response.status_code >= 400 and not isinstance(response, JSONResponse):
        try:
            content = response.body.decode()
            return JSONResponse(
                status_code=response.status_code,
                content={"detail": content}
            )
        except:
            pass

    return response

config = SecurityConfig(
    custom_response_modifier=custom_modifier,
)
```

The example above shows how to:
1. Add custom headers to all responses
2. Convert plain text error responses to JSON format with a "detail" field, matching FastAPI's HTTPException format

___

Redis Configuration
-------------------

Enable distributed state management across multiple instances:

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://prod-redis:6379/1",
    redis_prefix="myapp:security:",
)
```

The Redis integration provides:
- Atomic increment operations for rate limiting
- Distributed IP ban tracking
- Cloud provider IP range caching
- Pattern storage for penetration detection

___

Detailed Configuration Options
------------------------------

. SecurityConfig
--------------

The `SecurityConfig` class defines the structure for security configuration, including IP whitelists and blacklists, blocked countries, blocked user agents, rate limiting, automatic IP banning, HTTPS enforcement, custom hooks, CORS settings, and blocking of cloud provider IPs.

. Attributes
----------

- **geo_ip_handler**: ```GeoIPHandler``` - Protocol that allows for IP geolocation functionality.
- **enable_redis**: ```bool``` - Enable Redis for distributed state (default: True). When disabled, uses in-memory storage.
- **redis_url**: ```str | None``` - Redis connection URL (default: "redis://localhost:6379").
- **redis_prefix**: ```str``` - Prefix for Redis keys (default: "fastapi_guard:").
- **trusted_proxies**: ```list[str] | None``` - List of trusted proxy IPs or CIDR ranges.
- **trusted_proxy_depth**: ```int``` - How many proxies to expect in chain.
- **trust_x_forwarded_proto**: ```bool``` - Whether to trust X-Forwarded-Proto for HTTPS detection.
- **whitelist**: ```list[str] | None``` - A list of IP addresses or ranges that are always allowed. If set to None, no whitelist is applied.
- **blacklist**: ```list[str]``` - A list of IP addresses or ranges that are always blocked.
- **blocked_countries**: ```list[str]``` - A list of country codes whose IP addresses should be blocked.
- **blocked_user_agents**: ```list[str]``` - A list of user agent strings or patterns that should be blocked.
- **auto_ban_threshold**: ```int``` - The threshold for auto-banning an IP address after a certain number of requests.
- **auto_ban_duration**: ```int``` - The duration in seconds for which an IP address should be banned after reaching the auto-ban threshold.
- **custom_log_file**: ```str | None``` - Optional path to a log file. When provided, enables file logging in addition to console output (which is always enabled). Default: `None` (console only).
- **custom_error_responses**: ```dict[int, str]``` - A dictionary of custom error responses for specific HTTP status codes.
- **rate_limit**: ```int``` - The maximum number of requests allowed per minute from a single IP.
- **enforce_https**: ```bool``` - Whether to enforce HTTPS connections. If True, all HTTP requests will be redirected to HTTPS.
- **custom_request_check**: ```Callable[[Request], Awaitable[Response | None]] | None``` - A custom function to perform additional checks on the request. If it returns a Response, that response will be sent instead of continuing the middleware chain.
- **custom_response_modifier**: ```Callable[[Response], Awaitable[Response]] | None``` - A custom function to modify the response before it's sent.
- **enable_cors**: ```bool``` - Whether to enable CORS.
- **cors_allow_origins**: ```list[str]``` - A list of origins that are allowed to access the API.
- **cors_allow_methods**: ```list[str]``` - A list of methods that are allowed to access the API.
- **cors_allow_headers**: ```list[str]``` - A list of headers that are allowed in CORS requests.
- **cors_allow_credentials**: ```bool``` - Whether to allow credentials in CORS requests.
- **cors_expose_headers**: ```list[str]``` - A list of headers that are exposed in CORS responses.
- **cors_max_age**: ```int``` - The maximum age in seconds that the results of a preflight request can be cached.
- **block_cloud_providers**: ```set[str]``` - Case-sensitive cloud provider names to block. Valid values: 'AWS', 'GCP', 'Azure'. Invalid entries are silently ignored.
- **ipinfo_token**: ```str``` (DEPRECATED) - The IPInfo API token required for IP geolocation functionality.
- **ipinfo_db_path**: ```str``` (DEPRECATED) - Custom path for IPInfo database storage (default: ./data/ipinfo/country_asn.mmdb)

___

Contributing
------------

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

___

License
-------

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

___

Author
------

Renzo Franceschini - [rennf93@users.noreply.github.com](mailto:rennf93@users.noreply.github.com) .

___

Acknowledgements
----------------

- [FastAPI](https://fastapi.tiangolo.com/)
- [IPInfo](https://ipinfo.io/)
- [cachetools](https://cachetools.readthedocs.io/)
- [requests](https://docs.python-requests.org/)
- [Redis](https://redis.io/)
- [uvicorn](https://www.uvicorn.org/)
