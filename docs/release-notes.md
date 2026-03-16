---

title: Release Notes - FastAPI Guard
description: Release notes for FastAPI Guard, detailing new features, improvements, and bug fixes
keywords: release notes, fastapi guard, security middleware, api security
---

Release Notes
=============

___

v4.4.1 (2026-03-16)
-------------------

Bug Fixes (v4.4.1)
------------

- **Per-endpoint rate limit check**: Fixed rate limit check to properly evaluate endpoint-specific rate limits. Previously, the rate limit check was only evaluating global rate limits.

___

v4.4.0 (2026-03-14)
-------------------

New Features (v4.4.0)
------------

- **Configurable cloud IP refresh interval**: New `cloud_ip_refresh_interval` config field (default: 3600s, valid range: 60-86400s) allows tuning how often cloud provider IP ranges are refreshed. The interval is propagated to Redis TTL for cache consistency.
- **Change detection logging for cloud IP refreshes**: When cloud IP ranges are refreshed, additions and removals are logged per provider (e.g., `+12 added, -3 removed`), providing visibility into IP range mutations.
- **Context-aware detection engine**: Suspicious pattern rules are now tagged with applicable input contexts (`query_param`, `url_path`, `header`, `request_body`). Patterns are only evaluated against relevant input sources, reducing false positives.
- **Structured JSON logging**: New `log_format="json"` config option outputs logs as structured JSON (`{"timestamp": "...", "level": "...", "logger": "...", "message": "..."}`), enabling integration with log aggregation systems (ELK, Datadog, CloudWatch).
- **Per-provider `last_updated` timestamps**: `CloudManager` now tracks when each provider's IP ranges were last refreshed via `cloud_handler.last_updated["AWS"]`, returning `datetime | None`.

___

v4.3.1 (2026-03-11)
-------------------

Bug Fixes (v4.3.1)
------------

- **Geographic rate limit check**: Fixed geo-based rate limiting by implementing the missing `_check_geo_rate_limit` method in `RateLimitCheck`. Previously, geo rate limits configured via the `@security.geo_rate_limit` decorator were stored but never enforced. The rate limit pipeline now correctly evaluates geo-based limits at priority 3 (after endpoint-specific and route-specific limits).
- **Geo rate limit decorator**: Fixed `RateLimitingMixin.geo_rate_limit` decorator to store limits on `route_config.geo_rate_limits` instead of incorrectly serializing them into `required_headers`.
- **IPInfo country whitelist fail-closed**: When `whitelist_countries` is configured and a client's country cannot be determined, `IPInfoManager.check_country_access` now correctly blocks the request (fail-closed) instead of allowing it through.

Enhancements (v4.3.1)
------------

- **Timezone-aware time windows**: Time window restrictions now support configurable timezones via the `timezone` field in `time_restrictions`. Uses `ZoneInfo` for proper timezone handling with a safe fallback to UTC for invalid timezone strings.
- **Geo rate limit RouteConfig support**: Added `geo_rate_limits` attribute to `RouteConfig` for proper type-safe storage of geographic rate limit configurations.

___

v4.3.0 (2026-03-10)
-------------------

Bug Fixes (v4.3.0)
------------

- **Whitelisted IP bypass**: Whitelisted IPs now correctly bypass rate limiting, cloud provider blocking, user agent filtering, and suspicious activity detection checks. Previously, the whitelist flag was only checked during IP security validation but not propagated to downstream security checks.

Enhancements (v4.3.0)
------------

- **Version bump helper**: Added `make bump-version VERSION=x.y.z` command and `.github/scripts/bump_version.py` script to automate version updates across all project files (pyproject.toml, .mike.yml, versions.json, docs/index.md, changelogs).

CI/CD (v4.3.0)
------------

- **Docker actions**: Bumped `docker/login-action` from 3 to 4 and `docker/setup-compose-action` from 1 to 2.
- **Pre-commit**: Simplified pre-commit checks in scheduled lint workflow and disabled semgrep in pre-commit configuration.

___

v4.2.2 (2025-12-02)
-------------------

Support/Compatibility (v4.2.2)
------------

- **Python 3.14**: Added support for Python 3.14.

___

v4.2.1 (2025-11-05)
-------------------

Bug Fixes (v4.2.1)
------------

- **IPInfo redirect URLs**: IPInfo API sometimes responds with 302 code, and by not handling the redirect, the database would not be downloaded. Now, `IPInfoManager` class follows redirects.

___

v4.2.0 (2025-10-16)
-------------------

Internal Refactoring (No Breaking Changes) (v4.2.0)
------------

**Major architectural transformation** completed (v4.2.0):

- **Middleware Refactoring**: Broke down `middleware.py` from monolithic file into modular architecture.
- **Maintainability Improvement**: Improved from MI 0.00 (Rank C - "unmaintainable") to MI 54.51 (Rank A)
- **Complexity Reduction**: Average complexity reduced from ~15 to 2.35 (84.3% improvement)
- **Code Reduction**: middleware.py reduced by 77.4% through modular extraction
- **Test Coverage**: Maintained at 100% throughout refactoring
- **Zero Breaking Changes**: All public APIs remain unchanged

New Internal Architecture (`guard/core/`) (v4.2.0)
------------

There are now 9 specialized modules (all achieving Rank A maintainability, MI 56-82):

1. **`checks/`** - Security check implementations using Chain of Responsibility pattern
   - `SecurityCheck` base class
   - `SecurityCheckPipeline` for orchestration
   - 17 check implementations in `implementations/`

2. **`events/`** - Event system for middleware actions
   - `SecurityEventBus` for centralized event dispatching
   - `MetricsCollector` for request metrics collection

3. **`initialization/`** - Handler initialization logic
   - `HandlerInitializer` for centralized Redis, Agent, and handler setup

4. **`responses/`** - Response handling
   - `ErrorResponseFactory` for response creation and processing
   - `ResponseContext` for dependency injection

5. **`routing/`** - Routing and decorator resolution
   - `RouteConfigResolver` for route configuration
   - `RoutingContext` for dependency injection

6. **`validation/`** - Request validation utilities
   - `RequestValidator` for HTTPS checks, proxy validation, time windows
   - `ValidationContext` for dependency injection

7. **`bypass/`** - Security bypass handling
   - `BypassHandler` for passthrough and bypass logic
   - `BypassContext` for dependency injection

8. **`behavioral/`** - Behavioral rule processing
   - `BehavioralProcessor` for usage and return rules
   - `BehavioralContext` for dependency injection

Benefits (v4.2.0)
------------

- **Faster Development**: Faster feature additions
- **Better Testability**: Each module independently testable
- **Improved Performance**: Better code organization and caching
- **Maintainable Codebase**: Single Responsibility Principle applied throughout

Migration Notes (v4.2.0)
------------

**For Users**: No migration needed - all existing code works unchanged
**For Contributors**: See `ARCHITECTURE_CHANGES.md` for detailed module breakdown

**Important**: The `guard/core/*` modules are internal implementation details. Always import from public API.

___

v4.1.2 (2025-09-12)
-------------------

Enhancements (v4.1.2)
------------

- Added dynamic rule updated event type.

___

v4.1.0 (2025-09-07)
-------------------

New Features (v4.1.0)
------------

- **Enhanced Security Headers**: Added 5 new default security headers following OWASP best practices:
  - `X-Permitted-Cross-Domain-Policies: none` - Restricts Adobe Flash cross-domain access
  - `X-Download-Options: noopen` - Prevents file download execution in Internet Explorer
  - `Cross-Origin-Embedder-Policy: require-corp` - Controls cross-origin resource embedding
  - `Cross-Origin-Opener-Policy: same-origin` - Controls cross-origin window interactions
  - `Cross-Origin-Resource-Policy: same-origin` - Controls cross-origin resource access
- **Security Validation Framework**: Comprehensive input validation for all header configurations
- **Advanced CORS Validation**: Runtime validation and logging for CORS misconfiguration attempts
- **Security Event Logging**: Enhanced logging for security violations and configuration warnings

Security Fixes (v4.1.0)
---------

- Fixed header injection vulnerability in SecurityHeadersManager - preventing injection attacks via newlines and control characters
- Enhanced CORS security - wildcard origins (`*`) now properly blocked when credentials are enabled to prevent security bypass
- Implemented thread-safe singleton pattern with double-checked locking to prevent race conditions in multi-threaded environments
- Secure cache key generation using SHA256 hashing to prevent cache poisoning attacks
- Added CSP unsafe directive validation - warnings for `'unsafe-inline'` and `'unsafe-eval'` directives
- HSTS preload validation - ensures preload requirements (max_age ≥ 31536000, includeSubDomains) are met
- Input validation for all header values - sanitization of control characters and length limits (8192 bytes)

Improvements (v4.1.0)
------------

- **Performance**: Optimized cache key generation using SHA256 with path normalization
- **Reliability**: Thread-safe singleton implementation prevents multiple instances in concurrent environments
- **Security**: All header values now validated against injection attacks, newlines, and excessive length
- **Monitoring**: Improved security event logging for better observability and debugging
- **Documentation**: Updated security headers documentation with new features and best practices

___

v4.0.3 (2025-08-09)
-------------------

Bug Fixes (v4.0.3)
---------

- **Logging Configuration Fix**: Fixed `custom_log_file` configuration being ignored - file logging now works correctly
- **Logging Behavior**: File logging is now truly optional - only enabled when `custom_log_file` is explicitly set
- **Namespace Consistency**: All FastAPI Guard components now use consistent `fastapi_guard.*` logger namespace hierarchy
  - Root logger: `fastapi_guard`
  - Handlers: `fastapi_guard.handlers.{component}`
  - Decorators: `fastapi_guard.decorators.{component}`
  - Detection Engine: `fastapi_guard.detection_engine`
- **Console Output**: Console logging is now always enabled for visibility, regardless of file logging configuration
- **Passive Mode Enhancement**: Fixed passive mode to properly log without blocking for all security checks including rate limiting, suspicious patterns, and decorator violations

Improvements (v4.0.3)
------------

- **Logger Isolation**: FastAPI Guard logs are now properly isolated from user application logs
- **Test Compatibility**: Logger propagation enabled for better test framework integration
- **Documentation**: Updated all logging documentation to reflect actual behavior
- **Passive Mode Consistency**: All security checks now properly respect passive mode - logging violations without blocking requests
- **Enhanced Logging Context**: Improved log messages with better context for passive mode operations, including trigger information for suspicious patterns

___

v4.0.2 (2025-08-07)
-------------------

New Features (v4.0.2)
------------

- **Sus Patterns Handler Overhaul**: Complete redesign of the suspicious patterns detection system with modular architecture
  - **Pattern Compiler**: Safe regex execution with configurable timeouts to prevent ReDoS attacks
  - **Content Preprocessor**: Intelligent content truncation that preserves attack signatures
  - **Semantic Analyzer**: Heuristic-based detection using TF-IDF and n-gram analysis for obfuscated attacks
  - **Performance Monitor**: Real-time tracking of pattern execution times and anomaly detection
  - **Enhanced Detection API**: Rich detection results with threat scores, detailed threat information, and performance metrics
  - **Lazy Component Initialization**: Detection components only load when explicitly configured
  - **Comprehensive Configuration**: New `detection_*` configuration options for fine-tuning all components

Improvements (v4.0.2)
------------

- **Pattern Matching Performance**: Timeout protection prevents slow patterns from blocking requests
- **Detection Accuracy**: Multi-layered approach combines regex patterns with semantic analysis
- **Memory Efficiency**: Configurable limits on content length and pattern tracking
- **Observability**: Detailed performance metrics and slow pattern identification
- **Backward Compatibility**: Legacy `detect_pattern_match` API maintained for smooth migration
- **Agent Integration**: Automatic telemetry for pattern detection events and performance metrics

___

v3.0.2 (2025-07-22)
-------------------

Security Fixes (v3.0.2)
------------

- **IMPORTANT**: Enhanced ReDoS prevention - Prevent regex bypass due to length limitations on pattern regex. (GHSA-rrf6-pxg8-684g)
- **CVE ID**: CVE-2025-54365
- Added timeout to avoid catastrophical backtracking and/or regex bypass by length limitation expression.
- Added new `regex_timeout` parameter to `SecurityConfig` to allow for custom timeout for regex pattern matching.

___

v3.0.1 (2025-07-07)
-------------------

Security Fixes (v3.0.1)
------------

- **IMPORTANT**: Prevented ReDoS (Regular Expression Denial of Service - CWE-1333) attacks by replacing unbounded regex quantifiers with bounded ones. (GHSA-j47q-rc62-w448)
- **CVE ID**: CVE-2025-53539

___

v3.0.0 (2025-06-21)
-------------------

New Features (v3.0.0)
------------

- **Security Decorators**: Added comprehensive route-level security decorator system
  - `SecurityDecorator` class combining all security capabilities
  - Access control decorators for IP filtering, geographic restrictions, and cloud provider blocking
  - Authentication decorators for HTTPS enforcement, auth requirements, and API key validation
  - Rate limiting decorators with custom limits and geographic rate limiting
  - Behavioral analysis decorators for usage monitoring, return pattern detection, and frequency analysis
  - Content filtering decorators for content type validation, size limits, and user agent blocking
  - Advanced decorators for time windows, suspicious detection, and honeypot detection
  - Route-specific configuration that can override global middleware settings
  - Seamless integration with existing SecurityMiddleware
- **Behavior Manager**: Added behavioral analysis and monitoring system
  - `BehaviorTracker` for tracking and analyzing user behavior patterns
  - `BehaviorRule` for defining behavioral analysis rules
  - Support for endpoint usage tracking, return pattern analysis, and frequency detection
  - Multiple pattern formats including JSON paths, regex, and status codes
  - Automated actions (ban, alert, log, throttle) based on behavioral thresholds
  - Redis integration for distributed behavioral tracking

___

v2.1.3 (2025-06-18)
-------------------

Bug Fixes (v2.1.3)
---------

- Fixed IPv6 address support throughout the project - PR [#51](https://github.com/rennf93/fastapi-guard/pull/51) - Issue [#50](https://github.com/rennf93/fastapi-guard/issues/50)

___

v2.1.2 (2025-05-26)
-------------------

Improvements (v2.1.2)
------------

- Switched from Poetry to uv for package management

___

v2.1.1 (2025-05-08)
-------------------

Bug Fixes (v2.1.1)
---------

- Fixed `custom_response_modifier` implementation.

___

v2.1.0 (2025-05-08)
-------------------

Improvements (v2.1.0)
------------

- **Rate Limiting**: Replaced fixed window rate limiting with true sliding window algorithm
- Added atomic Redis Lua script for distributed rate limiting
- Improved timestamp tracking for more accurate request counting
- Fixed edge cases in rate limiting that could cause unexpected 429 errors

___

v2.0.0 (2025-05-05)
-------------------

Security Fixes (v2.0.0)
--------------

- **IMPORTANT**: Fixed Remote Header Injection vulnerability via X-Forwarded-For manipulation (GHSA-77q8-qmj7-x7pp)
- **CVE ID**: CVE-2025-46814
- Added secure client IP extraction with trusted proxy validation
- Added new configuration parameters for proxy security:
  - `trusted_proxies`: List of trusted proxy IPs or CIDR ranges
  - `trusted_proxy_depth`: Configurable proxy chain depth
  - `trust_x_forwarded_proto`: Option to trust X-Forwarded-Proto header

New Features (v2.0.0)
------------

- IPInfo is now completely optional, you can implement your own `GeoIPHandler`
- Added protocol-based design for customizable geographical IP handling
- Introduced `GeoIPHandler` protocol allowing custom implementations
- Separated protocol definitions into dedicated modules

Improvements (v2.0.0)
------------

- Deprecated `ipinfo_token` and `ipinfo_db_path` in favor of `geo_ip_handler`
- Improved type safety and code readability
- Added runtime type checking for custom GeoIP handlers

___

v1.5.0 (2025-05-01)
-------------------

Improvements (v1.5.0)
------------

- IpInfo token is now only required when using country filtering or cloud blocking
- Performance: Selective loading of IP geolocation database and cloud IP ranges
- Only download/process IP geolocation data when country filtering is configured
- Only fetch cloud provider IP ranges when cloud blocking is enabled
- Reduced startup time and memory usage when not using all security features

___

v1.4.0 (2025-04-30)
-------------------

New Features (v1.4.0)
------------

- Added configurable logging levels for normal and suspicious requests
- Enhanced log_activity function to support all logging levels
- Added ability to completely disable request logging

Improvements (v1.4.0)
------------

- Improved performance by allowing complete disabling of normal request logging
- Better log level control for different environments (dev/prod)

___

v1.3.2 (2025-04-27)
-------------------

New Features (v1.3.2)
------------

- Created an interactive [FastAPI Guard Playground](https://playground.fastapi-guard.com)
- Added `passive_mode` option to log suspicious activity without blocking requests
- Enhanced `detect_penetration_attempt` function to return trigger information

___

v1.2.2 (2025-04-07)
-------------------

Improvements (v1.2.2)
------------

- Added an empty `py.typed`
- Fixed the `package_data` configuration in `setup.py`
- Added `mypy` configuration to `pyproject.toml`
- Added `MANIFEST.in`

___

v1.2.1 (2025-04-05)
-------------------

New Features (v1.2.1)
------------

- Added new pattern management methods to `SusPatternsManager`:
  - `get_default_patterns()` and `get_custom_patterns()` for separate pattern access
  - `get_default_compiled_patterns()` and `get_custom_compiled_patterns()` for separate compiled pattern access
- Enhanced `remove_pattern()` method to return success/failure status

Improvements (v1.2.1)
------------

- Fixed issue with default pattern removal in `SusPatternsManager`
- Improved pattern separation between default and custom patterns

___

v1.2.0 (2025-04-04)
-------------------

New Features (v1.2.0)
------------

- Added dedicated `RateLimitManager` for improved rate limiting functionality
- TTLCache-based in-memory rate limiting still available
- Extended Redis support for distributed rate limiting

Improvements (v1.2.0)
------------

- Fixed rate limiting logic to properly handle rate limiting
- Standardized Singleton pattern across all handlers
- Added new `keys`and `delete_pattern` methods to `RedisManager` for easy key/pattern retrieval/cleanup

___

v1.1.0 (2025-03-21)
-------------------

New Features (v1.1.0)
------------

- Added proper typing throughout the codebase
- Added custom Docker container for example app
- Added better Docker Compose support

Improvements (v1.1.0)
------------

- Fixed multiple typing issues across test files
- Improved documentation for Docker container usage
- Enhanced serialization of Redis data

___

v1.0.0 (2025-02-19)
-------------------

New Features (v1.0.0)
------------

- Added Redis integration for distributed state management

Improvements (v1.0.0)
------------

- Improved tests & testing coverage (100% coverage)

___

v0.4.0 (2025-02-16)
-------------------

New Features (v0.4.0)
------------

- Added `db_path` parameter to `IPInfoManager` for custom database locations

Improvements (v0.4.0)
------------

- Improved IPInfo database handling with local caching

Bug Fixes (v0.3.4)
---------

- Fixed Azure IP ranges download by adding proper User-Agent headers ([#19](https://github.com/rennf93/fastapi-guard/pull/19))
- Fixed cloud provider validation logic to properly filter invalid entries
- Resolved test coverage gaps on all test files

___

v0.3.4 (2025-01-26)
-------------------

Bug Fixes (v0.3.3)
---------

- Fixed issue with accepted `Headers` on `Swagger UI` access/requests.

___

v0.3.3 (2024-12-14)
-------------------

Bug Fixes (v0.3.2)
---------

- Fixed package structure to properly include all required modules
- Resolved import issues with handlers package
- Improved package installation reliability
