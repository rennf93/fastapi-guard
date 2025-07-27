Release Notes
=============

___

v4.0.0 (2025-07-27)
-------------------

New Features (v4.0.0)
------------

- **Sus Patterns Handler Overhaul**: Complete redesign of the suspicious patterns detection system with modular architecture
  - **Pattern Compiler**: Safe regex execution with configurable timeouts to prevent ReDoS attacks
  - **Content Preprocessor**: Intelligent content truncation that preserves attack signatures
  - **Semantic Analyzer**: Heuristic-based detection using TF-IDF and n-gram analysis for obfuscated attacks
  - **Performance Monitor**: Real-time tracking of pattern execution times and anomaly detection
  - **Enhanced Detection API**: Rich detection results with threat scores, detailed threat information, and performance metrics
  - **Lazy Component Initialization**: Detection components only load when explicitly configured
  - **Comprehensive Configuration**: New `detection_*` configuration options for fine-tuning all components

Improvements (v4.0.0)
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
