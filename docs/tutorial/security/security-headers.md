---
title: Security Headers - FastAPI Guard
description: Learn how to secure your FastAPI application with security headers
keywords: security headers, CSP, HSTS, XSS protection, FastAPI security
---

# Security Headers

FastAPI Guard provides robust security headers to protect your application from common web vulnerabilities. This guide explains how to configure security headers via `SecurityMiddleware` and `SecurityConfig` so they are automatically applied to all responses.

## Overview

Security headers help protect your web application from various attacks such as:
- Cross-Site Scripting (XSS)
- Clickjacking
- MIME-type sniffing
- Protocol downgrade attacks
- Cross-origin attacks

## Available Headers

### Content Security Policy (CSP)
Controls which resources can be loaded by the browser, helping to prevent XSS attacks.

### HTTP Strict Transport Security (HSTS)
Instructs browsers to only connect via HTTPS, preventing protocol downgrade attacks.

### X-Frame-Options
Prevents clickjacking by controlling whether your site can be embedded in an iframe.

### X-Content-Type-Options
Prevents MIME-type sniffing, forcing the browser to respect the declared content type.

### X-XSS-Protection
Enables the browser's built-in XSS protection (legacy but still useful for older browsers).

### Referrer-Policy
Controls how much referrer information is included in requests.

### Permissions Policy
Controls which browser features can be used by your site.

### Cross-Origin Policies
- **Cross-Origin-Opener-Policy**: Prevents cross-origin attacks
- **Cross-Origin-Resource-Policy**: Controls which sites can embed your resources
- **Cross-Origin-Embedder-Policy**: Controls cross-origin embedding of resources

## Basic Usage

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    csp_directives={
        "default-src": ["'self'"],
        "script-src": ["'self'", "trusted.cdn.com"],
        "style-src": ["'self'"],
    },
    hsts_max_age=31536000,  # 1 year
    frame_options="DENY",
    content_type_options="nosniff",
    xss_protection="1; mode=block",
    referrer_policy="no-referrer",
    permissions_policy={
        "geolocation": ["'self'"],
        "camera": ["'none'"],
    },
    cross_origin_opener_policy="same-origin",
    cross_origin_resource_policy="same-origin",
    cross_origin_embedder_policy="require-corp",
)

app.add_middleware(SecurityMiddleware, config=config)

@app.get("/")
async def root():
    return {"message": "Hello, World!"}
```

## Configuration Options

### `csp_directives` (dict[str, list[str]] | None)
Content Security Policy directives. Each key is a directive name and the value is a list of sources.

### `hsts_max_age` (int, default: 63072000)
Max age for HSTS header in seconds (default is 2 years).

### `frame_options` (str, default: "SAMEORIGIN")
Value for X-Frame-Options header. Common values:
- `DENY`: Prevent any domain from framing the content
- `SAMEORIGIN`: Allow only same-origin framing
- `ALLOW-FROM uri`: Allow specific URI to frame the content

### `content_type_options` (str, default: "nosniff")
Value for X-Content-Type-Options header. Should always be "nosniff".

### `xss_protection` (str, default: "1; mode=block")
Value for X-XSS-Protection header.

### `referrer_policy` (str, default: "strict-origin-when-cross-origin")
Value for Referrer-Policy header. Common values:
- `no-referrer`
- `no-referrer-when-downgrade`
- `origin`
- `origin-when-cross-origin`
- `same-origin`
- `strict-origin`
- `strict-origin-when-cross-origin`
- `unsafe-url`

### `permissions_policy` (dict[str, list[str]] | None)
Permissions Policy directives. Each key is a feature name and the value is a list of origins.

### Cross-Origin Policies
- `cross_origin_opener_policy` (str, default: "same-origin")
- `cross_origin_resource_policy` (str, default: "same-origin")
- `cross_origin_embedder_policy` (str, default: "require-corp")

## Best Practices

1. **Always use HTTPS** and set an appropriate HSTS max age
2. **Use strict CSP policies** and only allow trusted sources
3. **Deny framing** unless specifically needed
4. **Keep software updated** to protect against known vulnerabilities
5. **Test your headers** using security headers scanners

## Testing Headers

You can test your security headers using:
- Browser Developer Tools (Network tab)
- [Security Headers](https://securityheaders.com/)
- [Mozilla Observatory](https://observatory.mozilla.org/)

## Example: Secure Configuration

```python
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

config = SecurityConfig(
    csp_directives={
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'"],  # Note: Avoid 'unsafe-inline' in production
        "style-src": ["'self'", "'unsafe-inline'"],
        "img-src": ["'self'", "data:"],
        "font-src": ["'self'"],
        "connect-src": ["'self'"],
        "frame-ancestors": ["'none'"],
        "form-action": ["'self'"],
        "base-uri": ["'self'"],
        "object-src": ["'none'"],
    },
    hsts_max_age=31536000,  # 1 year
    frame_options="DENY",
    content_type_options="nosniff",
    xss_protection="1; mode=block",
    referrer_policy="strict-origin-when-cross-origin",
    permissions_policy={
        "geolocation": ["'self'"],
        "camera": ["'none'"],
        "microphone": ["'none'"],
        "payment": ["'none'"],
    },
    cross_origin_opener_policy="same-origin",
    cross_origin_resource_policy="same-origin",
    cross_origin_embedder_policy="require-corp",
)

app.add_middleware(SecurityMiddleware, config=config)
```

## Troubleshooting

### Headers Not Being Set
- Ensure `SecurityMiddleware` is added (and with the intended `SecurityConfig`)
- Check for any other middleware that might be removing or overriding headers

### CSP Blocking Resources
- Check browser console for CSP violation reports
- Adjust CSP directives to allow necessary resources
- Consider using `report-uri` or `report-to` for violation reports

### Mixed Content Warnings
- Ensure all resources are loaded over HTTPS
- Update any hardcoded HTTP URLs to use HTTPS
