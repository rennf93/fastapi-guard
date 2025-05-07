---
title: Release Notes - FastAPI Guard
description: Release notes for FastAPI Guard, detailing new features, improvements, and bug fixes
keywords: release notes, fastapi guard, security middleware, api security
---

# Release Notes

## v2.1.0 (2025-05-07)

### Improvements
- **Rate Limiting**: Replaced fixed window rate limiting with true sliding window algorithm
- Added atomic Redis Lua script for distributed rate limiting
- Improved timestamp tracking for more accurate request counting
- Fixed edge cases in rate limiting that could cause unexpected 429 errors

## v2.0.0 (2025-05-05)

### Security Fixes
- **IMPORTANT**: Fixed Remote Header Injection vulnerability via X-Forwarded-For manipulation (GHSA-77q8-qmj7-x7pp)
- **CVE ID**: CVE-2025-46814
- Added secure client IP extraction with trusted proxy validation
- Added new configuration parameters for proxy security:
  - `trusted_proxies`: List of trusted proxy IPs or CIDR ranges
  - `trusted_proxy_depth`: Configurable proxy chain depth
  - `trust_x_forwarded_proto`: Option to trust X-Forwarded-Proto header

### New Features
- IPInfo is now completely optional, you can implement your own `GeoIPHandler`
- Added protocol-based design for customizable geographical IP handling
- Introduced `GeoIPHandler` protocol allowing custom implementations
- Separated protocol definitions into dedicated modules

### Improvements
- Deprecated `ipinfo_token` and `ipinfo_db_path` in favor of `geo_ip_handler`
- Improved type safety and code readability
- Added runtime type checking for custom GeoIP handlers

## v1.5.0 (2025-05-01)
### Improvements
- IpInfo token is now only required when using country filtering or cloud blocking
- Performance: Selective loading of IP geolocation database and cloud IP ranges
- Only download/process IP geolocation data when country filtering is configured
- Only fetch cloud provider IP ranges when cloud blocking is enabled
- Reduced startup time and memory usage when not using all security features

## v1.4.0 (2025-04-30)
### New Features
- Added configurable logging levels for normal and suspicious requests
- Enhanced log_activity function to support all logging levels
- Added ability to completely disable request logging

### Improvements
- Improved performance by allowing complete disabling of normal request logging
- Better log level control for different environments (dev/prod)

## v1.3.2 (2025-04-27)
### New Features
- Created an interactive [FastAPI Guard Playground](https://playground.fastapi-guard.com)
- Added `passive_mode` option to log suspicious activity without blocking requests
- Enhanced `detect_penetration_attempt` function to return trigger information

## v1.2.2 (2025-04-07)
### Improvements
- Added an empty `py.typed`
- Fixed the `package_data` configuration in `setup.py`
- Added `mypy` configuration to `pyproject.toml`
- Added `MANIFEST.in`

## v1.2.1 (2025-04-05)

### New Features
- Added new pattern management methods to `SusPatternsManager`:
  - `get_default_patterns()` and `get_custom_patterns()` for separate pattern access
  - `get_default_compiled_patterns()` and `get_custom_compiled_patterns()` for separate compiled pattern access
- Enhanced `remove_pattern()` method to return success/failure status

### Improvements
- Fixed issue with default pattern removal in `SusPatternsManager`
- Improved pattern separation between default and custom patterns

## v1.2.0 (2025-04-04)
### New Features
- Added dedicated `RateLimitManager` for improved rate limiting functionality
- TTLCache-based in-memory rate limiting still available
- Extended Redis support for distributed rate limiting

### Improvements
- Fixed rate limiting logic to properly handle rate limiting
- Standardized Singleton pattern across all handlers
- Added new `keys`and `delete_pattern` methods to `RedisManager` for easy key/pattern retrieval/cleanup

## v1.1.0 (2025-03-21)
### New Features
- Added proper typing throughout the codebase
- Added custom Docker container for example app
- Added better Docker Compose support

### Improvements
- Fixed multiple typing issues across test files
- Improved documentation for Docker container usage
- Enhanced serialization of Redis data

## v1.0.0 (2025-02-19)
### New Features
- Added Redis integration for distributed state management

### Improvements
- Improved tests & testing coverage (100% coverage)

## v0.4.0 (2025-02-16)
### New Features
- Added `db_path` parameter to `IPInfoManager` for custom database locations

### Improvements
- Improved IPInfo database handling with local caching

### Bug Fixes
- Fixed Azure IP ranges download by adding proper User-Agent headers ([#19](https://github.com/rennf93/fastapi-guard/pull/19))
- Fixed cloud provider validation logic to properly filter invalid entries
- Resolved test coverage gaps on all test files

## v0.3.4 (2025-01-26)

### Bug Fixes
- Fixed issue with accepted `Headers` on `Swagger UI` access/requests.

## v0.3.3 (2024-12-14)

### Bug Fixes
- Fixed package structure to properly include all required modules
- Resolved import issues with handlers package
- Improved package installation reliability