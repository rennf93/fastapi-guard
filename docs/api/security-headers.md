---

title: Security Headers Manager - FastAPI Guard
description: Comprehensive HTTP security header management following OWASP best practices
keywords: security headers, CSP, HSTS, X-Frame-Options, OWASP headers

---

Security Headers Manager
========================

The Security Headers Manager provides comprehensive HTTP security header management following OWASP best practices.

___

Overview
--------

The `SecurityHeadersManager` is a singleton class that manages security headers for HTTP responses, including Content Security Policy (CSP), HTTP Strict Transport Security (HSTS), and other essential security headers.

___

Class Reference
---------------

SecurityHeadersManager
----------------------

```python
from guard.handlers.security_headers_handler import SecurityHeadersManager

security_headers_manager = SecurityHeadersManager()
```

Methods
-------

configure
---------

Configure security headers settings.

```python
security_headers_manager.configure(
    enabled=True,
    csp={
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://trusted.cdn.com"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "https:"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "connect-src": ["'self'"],
        "frame-ancestors": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"]
    },
    hsts_max_age=31536000,  # 1 year
    hsts_include_subdomains=True,
    hsts_preload=False,
    frame_options="SAMEORIGIN",
    content_type_options="nosniff",
    xss_protection="1; mode=block",
    referrer_policy="strict-origin-when-cross-origin",
    permissions_policy="geolocation=(), microphone=(), camera=()",
    custom_headers={
        "X-Custom-Header": "CustomValue"
    },
    cors_origins=["https://app.example.com"],
    cors_allow_credentials=True,
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["*"]
)
```

**Parameters:**

- `enabled` (bool): Enable/disable security headers. Default: `True`
- `csp` (dict[str, list[str]] | None): Content Security Policy directives
- `hsts_max_age` (int | None): HSTS max-age in seconds (e.g., 31536000 for 1 year)
- `hsts_include_subdomains` (bool): Include subdomains in HSTS. Default: `True`
- `hsts_preload` (bool): Enable HSTS preload. Default: `False`
- `frame_options` (str | None): X-Frame-Options value (`DENY`, `SAMEORIGIN`)
- `content_type_options` (str | None): X-Content-Type-Options value
- `xss_protection` (str | None): X-XSS-Protection value
- `referrer_policy` (str | None): Referrer-Policy value
- `permissions_policy` (str | None): Permissions-Policy value
- `custom_headers` (dict[str, str] | None): Additional custom security headers
- `cors_origins` (list[str] | None): Allowed CORS origins
- `cors_allow_credentials` (bool): Allow credentials in CORS. Default: `False`
- `cors_allow_methods` (list[str] | None): Allowed CORS methods
- `cors_allow_headers` (list[str] | None): Allowed CORS headers

get_headers
-----------

Get security headers for a response.

```python
headers = await security_headers_manager.get_headers(
    request_path="/api/endpoint"
)
```

**Parameters:**

- `request_path` (str | None): Optional request path for path-specific headers

**Returns:**

- `dict[str, str]`: Dictionary of security headers

get_cors_headers
----------------

Get CORS headers if origin is allowed.

```python
cors_headers = await security_headers_manager.get_cors_headers(
    origin="https://app.example.com"
)
```

**Parameters:**

- `origin` (str): Request origin

**Returns:**

- `dict[str, str]`: Dictionary of CORS headers

validate_csp_report
-------------------

Validate and process CSP violation reports.

```python
is_valid = await security_headers_manager.validate_csp_report(
    report={
        "csp-report": {
            "document-uri": "https://example.com/page",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
            "source-file": "https://example.com/app.js",
            "line-number": 10
        }
    }
)
```

**Parameters:**

- `report` (dict[str, Any]): CSP violation report

**Returns:**

- `bool`: True if report is valid

initialize_redis
----------------

Initialize Redis connection for caching header configurations.

```python
await security_headers_manager.initialize_redis(redis_handler)
```

**Parameters:**

- `redis_handler` (Any): Redis handler instance

initialize_agent
----------------

Initialize agent integration for security event tracking.

```python
await security_headers_manager.initialize_agent(agent_handler)
```

**Parameters:**

- `agent_handler` (Any): Agent handler instance

reset
-----

Reset all security headers configuration.

```python
await security_headers_manager.reset()
```

___

Default Headers
---------------

The following headers are configured by default:

| Header | Default Value | Description |
|--------|--------------|-------------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME type sniffing |
| `X-Frame-Options` | `SAMEORIGIN` | Prevents clickjacking attacks |
| `X-XSS-Protection` | `1; mode=block` | Enables XSS filtering |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer information |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Restricts browser features |
| `X-Permitted-Cross-Domain-Policies` | `none` | Restricts Adobe Flash cross-domain access |
| `X-Download-Options` | `noopen` | Prevents file download execution in IE |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Controls cross-origin resource embedding |
| `Cross-Origin-Opener-Policy` | `same-origin` | Controls cross-origin window interactions |
| `Cross-Origin-Resource-Policy` | `same-origin` | Controls cross-origin resource access |

___

Content Security Policy (CSP)
------------------------------

CSP helps prevent XSS attacks by specifying which sources are allowed for various content types.

Common CSP Directives
---------------------

- `default-src`: Default policy for all resource types
- `script-src`: Valid sources for JavaScript
- `style-src`: Valid sources for stylesheets
- `img-src`: Valid sources for images
- `font-src`: Valid sources for fonts
- `connect-src`: Valid sources for fetch, XMLHttpRequest, WebSocket
- `frame-src`: Valid sources for frames
- `frame-ancestors`: Valid parents that may embed a page
- `base-uri`: Restricts URLs for `<base>` element
- `form-action`: Valid endpoints for form submissions
- `report-uri`: URL to send CSP violation reports

CSP Source Values
-----------------

- `'self'`: Same origin
- `'none'`: No sources allowed
- `'unsafe-inline'`: Allow inline scripts/styles (use with caution)
- `'unsafe-eval'`: Allow eval() (use with caution)
- `https:`: Any HTTPS source
- `data:`: Data URIs
- Specific domains: `https://trusted.cdn.com`

___

HTTP Strict Transport Security (HSTS)
---------------------------------------

HSTS forces browsers to use HTTPS connections.

HSTS Configuration
------------------

```python
hsts_config = {
    "max_age": 31536000,        # 1 year in seconds
    "include_subdomains": True,  # Apply to all subdomains
    "preload": False            # Submit to HSTS preload list
}
```

HSTS Preload Requirements
-------------------------

To enable HSTS preload:

1. Serve a valid certificate
2. Redirect all HTTP to HTTPS
3. Serve all subdomains over HTTPS
4. Set `max_age` to at least 31536000 (1 year)
5. Include `includeSubDomains`
6. Include `preload`

___

CORS Integration
----------------

The Security Headers Manager integrates with CORS configuration:

```python
# CORS headers are automatically added when:
# 1. An origin header is present in the request
# 2. The origin is in the allowed list
cors_config = {
    "origins": ["https://app.example.com", "https://admin.example.com"],
    "allow_credentials": True,
    "allow_methods": ["GET", "POST", "PUT", "DELETE"],
    "allow_headers": ["*"]
}
```

___

Redis Caching
-------------

Header configurations are cached in Redis for performance:

- CSP configuration: Cached with key `security_headers:csp_config`
- HSTS configuration: Cached with key `security_headers:hsts_config`
- Custom headers: Cached with key `security_headers:custom_headers`
- TTL: 86400 seconds (24 hours)

___

Agent Integration
-----------------

When agent is configured, the following events are sent:

- `security_headers_applied`: When headers are added to a response
- `csp_violation`: When a CSP violation report is received

___

Example Usage
-------------

Basic Configuration
-------------------

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    security_headers={
        "enabled": True,
        "hsts": {
            "max_age": 31536000,
            "include_subdomains": True,
            "preload": False
        },
        "frame_options": "DENY",
        "content_type_options": "nosniff",
        "xss_protection": "1; mode=block",
        "referrer_policy": "no-referrer",
        "permissions_policy": "geolocation=(), microphone=(), camera=()"
    }
)

app.add_middleware(SecurityMiddleware, config=config)
```

Advanced CSP Configuration
--------------------------

```python
config = SecurityConfig(
    security_headers={
        "enabled": True,
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            "img-src": ["'self'", "data:", "https:"],
            "font-src": ["'self'", "https://fonts.gstatic.com"],
            "connect-src": ["'self'", "https://api.example.com"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"],
            "report-uri": ["/api/csp-report"]
        }
    }
)
```

CSP Report Endpoint
-------------------

```python
from fastapi import Request

@app.post("/api/csp-report")
async def handle_csp_report(request: Request):
    report = await request.json()
    is_valid = await security_headers_manager.validate_csp_report(report)
    
    if is_valid:
        # Report is logged automatically by the manager
        return {"status": "received"}
    
    return {"status": "invalid"}
```

Disabling Specific Headers
---------------------------

```python
config = SecurityConfig(
    security_headers={
        "enabled": True,
        "frame_options": None,  # Disable X-Frame-Options
        "permissions_policy": None,  # Disable Permissions-Policy
        # Other headers remain at defaults
    }
)
```

___

Best Practices
--------------

1. **Gradual HSTS Rollout**: Start with a small `max_age` and gradually increase
2. **Test Thoroughly**: Security headers can break functionality if too restrictive
3. **Monitor CSP Reports**: Set up monitoring for CSP violations
4. **Use HTTPS**: Many security headers require HTTPS to be effective
5. **Browser Compatibility**: Check browser support for specific headers

___

Security Considerations
------------------------

- **Header Injection Prevention**: All header values are validated against injection attacks, newlines, and excessive length
- **CORS Security**: Wildcard origins (`*`) cannot be used with credentials to prevent security vulnerabilities
- **Thread Safety**: SecurityHeadersManager uses thread-safe singleton pattern with double-checked locking
- **Cache Security**: Cache keys are generated using SHA256 hashing to prevent cache poisoning attacks
- **CSP Validation**: Unsafe directives like `'unsafe-inline'` and `'unsafe-eval'` trigger security warnings
- **HSTS Preload**: Strict validation ensures preload requirements (max_age ≥ 1 year, includeSubDomains)
- **CSP Bypasses**: Be aware of potential CSP bypasses with `'unsafe-inline'` and `'unsafe-eval'`
- **HSTS Commitment**: Once HSTS is enabled with a long `max_age`, it cannot be easily undone
- **Frame Options**: Consider using CSP's `frame-ancestors` instead of `X-Frame-Options`
- **Legacy Headers**: Some headers like `X-XSS-Protection` are being phased out in modern browsers
- **Performance**: Complex CSP policies can impact page load performance

___

See Also
--------

- [HTTP Security Headers Tutorial](../tutorial/security/http-security-headers.md) - Comprehensive guide
- [Security Configuration](../tutorial/configuration/security-config.md) - Configuration options
- [Security Middleware](security-middleware.md) - Middleware integration
