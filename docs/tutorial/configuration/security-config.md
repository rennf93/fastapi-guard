---

title: Security Configuration - FastAPI Guard
description: Complete guide to FastAPI Guard's SecurityConfig model and configuration options
keywords: security config, configuration, settings, environment variables
---

Security Configuration
=====================

FastAPI Guard uses Pydantic models for configuration and data structures.

___

SecurityConfig
--------------

The main configuration model for FastAPI Guard middleware.

```python
class SecurityConfig(BaseSettings):
    """
    Main configuration model for FastAPI Guard.
    All settings can be configured via environment variables with FASTAPI_GUARD_ prefix.
    """
```

Core Security Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | True | Enable/disable the middleware |
| `passive_mode` | bool | False | If True, only log without blocking |
| `enable_penetration_detection` | bool | True | Enable penetration attempt detection |
| `auto_ban_threshold` | int | 5 | Number of suspicious requests before auto-ban |
| `auto_ban_duration` | int | 3600 | Auto-ban duration in seconds |

Detection Engine Settings
-------------------------

New configuration fields for the enhanced Detection Engine:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `detection_compiler_timeout` | float | 2.0 | Timeout for pattern compilation and execution (seconds) |
| `detection_max_content_length` | int | 10000 | Maximum content length to analyze |
| `detection_preserve_attack_patterns` | bool | True | Preserve attack patterns during content truncation |
| `detection_semantic_threshold` | float | 0.7 | Minimum threat score for semantic detection (0.0-1.0) |
| `detection_anomaly_threshold` | float | 3.0 | Standard deviations to consider performance anomaly |
| `detection_slow_pattern_threshold` | float | 0.1 | Execution time to consider pattern slow (seconds) |
| `detection_monitor_history_size` | int | 1000 | Number of performance metrics to keep in history |
| `detection_max_tracked_patterns` | int | 1000 | Maximum patterns to track for performance |

IP Management Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trusted_ips` | list[str] | [] | List of always-allowed IP addresses |
| `blocked_ips` | list[str] | [] | List of always-blocked IP addresses |
| `blocked_countries` | list[str] | [] | List of blocked country codes |
| `blocked_user_agents` | list[str] | [] | List of blocked user agent patterns |
| `trusted_hosts` | list[str] | ["*"] | List of allowed host headers |
| `real_ip_header` | str | None | Header containing real IP (e.g., 'X-Forwarded-For') |
| `global_rate_limit` | str | "5000/hour" | Global rate limit for all requests |

Redis Settings
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `use_redis` | bool | False | Enable Redis integration |
| `redis_host` | str | "localhost" | Redis server hostname |
| `redis_port` | int | 6379 | Redis server port |
| `redis_password` | str | None | Redis password |
| `redis_db` | int | 0 | Redis database number |
| `redis_ssl` | bool | False | Use SSL for Redis connection |
| `redis_pool_size` | int | 10 | Connection pool size |
| `redis_ttl` | int | 86400 | Default TTL for Redis keys (seconds) |

Agent Settings
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_agent` | bool | False | Enable FastAPI Guard Agent integration |
| `agent_api_key` | str | None | API key for agent authentication |
| `agent_api_base_url` | str | "https://api.fastapiguard.com/v1/agent" | Agent API endpoint |
| `agent_enable_events` | bool | True | Send events to agent |
| `agent_enable_metrics` | bool | True | Send metrics to agent |
| `agent_send_interval` | int | 60 | Metric sending interval (seconds) |

Cloud Provider Settings
-----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ipinfo_token` | str | None | IPInfo API token for geolocation |
| `block_cloud_providers` | dict | {} | Cloud providers to block |
| `cloud_provider_cache_ttl` | int | 86400 | Cache TTL for cloud provider data |

Security Headers Settings
------------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `security_headers` | dict[str, Any] | See below | Security headers configuration |

Default security_headers configuration:

```python
{
    "enabled": True,
    "hsts": {
        "max_age": 31536000,  # 1 year
        "include_subdomains": True,
        "preload": False
    },
    "csp": None,  # Content Security Policy directives
    "frame_options": "SAMEORIGIN",
    "content_type_options": "nosniff",
    "xss_protection": "1; mode=block",
    "referrer_policy": "strict-origin-when-cross-origin",
    "permissions_policy": "geolocation=(), microphone=(), camera=()",
    "custom": None  # Additional custom headers
}
```

The following additional security headers are now included by default:

- `X-Permitted-Cross-Domain-Policies: none`
- `X-Download-Options: noopen`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`

Security Headers Sub-fields
----------------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | True | Enable security headers |
| `hsts.max_age` | int | 31536000 | HSTS max-age in seconds |
| `hsts.include_subdomains` | bool | True | Include subdomains in HSTS |
| `hsts.preload` | bool | False | Enable HSTS preload |
| `csp` | dict[str, list[str]] | None | Content Security Policy directives |
| `frame_options` | str | "SAMEORIGIN" | X-Frame-Options value (DENY, SAMEORIGIN) |
| `content_type_options` | str | "nosniff" | X-Content-Type-Options value |
| `xss_protection` | str | "1; mode=block" | X-XSS-Protection value |
| `referrer_policy` | str | "strict-origin-when-cross-origin" | Referrer-Policy value |
| `permissions_policy` | str | See default | Permissions-Policy value |
| `custom` | dict[str, str] | None | Additional custom headers |

CORS Settings
-------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cors_enabled` | bool | True | Enable CORS handling |
| `cors_origins` | list[str] | ["*"] | Allowed origins |
| `cors_methods` | list[str] | ["*"] | Allowed methods |
| `cors_headers` | list[str] | ["*"] | Allowed headers |
| `cors_credentials` | bool | False | Allow credentials |
| `cors_max_age` | int | 600 | Preflight cache duration |

Logging Settings
----------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_enabled` | bool | True | Enable request logging |
| `log_level` | str | "INFO" | Logging level |
| `custom_log_file` | str | None | Custom log file path |
| `log_format` | str | "default" | Log format (default, json) |
| `mask_sensitive_data` | bool | True | Mask sensitive data in logs |

Usage Example
-------------

```python
from guard import SecurityConfig

# Basic configuration
config = SecurityConfig(
    enable_penetration_detection=True,
    auto_ban_threshold=5,
    detection_semantic_threshold=0.7
)

# Full configuration
config = SecurityConfig(
    # Core settings
    enabled=True,
    passive_mode=False,

    # Detection engine
    enable_penetration_detection=True,
    detection_compiler_timeout=2.0,
    detection_max_content_length=10000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.7,
    detection_anomaly_threshold=3.0,
    detection_slow_pattern_threshold=0.1,
    detection_monitor_history_size=1000,
    detection_max_tracked_patterns=1000,

    # Security headers
    security_headers={
        "enabled": True,
        "hsts": {
            "max_age": 31536000,  # 1 year
            "include_subdomains": True,
            "preload": False
        },
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"],
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
        "referrer_policy": "no-referrer",
        "permissions_policy": "geolocation=(), microphone=(), camera=()",
        "custom": {
            "X-Custom-Header": "CustomValue"
        }
    },

    # Redis
    use_redis=True,
    redis_host="localhost",
    redis_port=6379,

    # Agent
    enable_agent=True,
    agent_api_key="your-api-key",

    # Logging
    custom_log_file="security.log",
    log_level="WARNING"
)
```

Environment Variables
---------------------

All settings can be configured using environment variables with the `FASTAPI_GUARD_` prefix:

```bash
export FASTAPI_GUARD_ENABLED=true
export FASTAPI_GUARD_DETECTION_SEMANTIC_THRESHOLD=0.8
export FASTAPI_GUARD_REDIS_HOST=redis.example.com
export FASTAPI_GUARD_AGENT_API_KEY=your-api-key
```

___

Other Models
------------

IPInfo
------

```python
class IPInfo(BaseModel):
    """IP address information from geolocation service"""
    ip: str
    country: str | None = None
    region: str | None = None
    city: str | None = None
    is_cloud: bool = False
    cloud_provider: str | None = None
```

RateLimitStatus
----------------

```python
class RateLimitStatus(BaseModel):
    """Rate limit status for a client"""
    allowed: bool
    current_requests: int
    limit: int
    window_seconds: int
    reset_time: datetime
```

ThreatDetectionResult
---------------------

```python
class ThreatDetectionResult(TypedDict):
    """Result from detection engine analysis"""
    is_threat: bool
    threat_score: float
    threats: list[dict[str, Any]]
    context: str
    original_length: int
    processed_length: int
    execution_time: float
    detection_method: str
    timeouts: list[str]
    correlation_id: str | None
```

BehaviorProfile
----------------

```python
class BehaviorProfile(BaseModel):
    """Client behavior profile for analysis"""
    ip_address: str
    request_count: int
    suspicious_count: int
    last_seen: datetime
    user_agents: list[str]
    paths_accessed: list[str]
    methods_used: list[str]
    risk_score: float
```

___

Configuration Validation
------------------------

The SecurityConfig model validates settings on initialization:

```python
# Validation examples
try:
    config = SecurityConfig(
        detection_compiler_timeout=0.05  # Too low
    )
except ValidationError as e:
    print(f"Configuration error: {e}")

# Valid ranges
config = SecurityConfig(
    detection_compiler_timeout=2.0,      # 0.1 - 30.0
    detection_semantic_threshold=0.7,    # 0.0 - 1.0
    detection_anomaly_threshold=3.0,     # 1.0 - 10.0
    auto_ban_threshold=5,                # 1 - 1000
    auto_ban_duration=3600,              # 60 - 86400
)
```

___

Model Serialization
-------------------

All models support standard Pydantic serialization:

```python
# Export configuration
config_dict = config.dict(exclude_unset=True)
config_json = config.json(indent=2)

# Import configuration
config = SecurityConfig.parse_obj(config_dict)
config = SecurityConfig.parse_raw(config_json)

# Schema generation
schema = SecurityConfig.schema()
```

___

Custom Validators
-----------------

The models include custom validators for complex fields:

```python
@validator("detection_semantic_threshold")
def validate_threshold(cls, v):
    if not 0.0 <= v <= 1.0:
        raise ValueError("Threshold must be between 0.0 and 1.0")
    return v

@validator("redis_host")
def validate_redis_host(cls, v, values):
    if values.get("use_redis") and not v:
        raise ValueError("Redis host required when use_redis is True")
    return v
```

___

See Also
--------

- [Security Middleware](../../api/security-middleware.md) - Using SecurityConfig with middleware
- [Detection Engine Configuration](../security/detection-engine/configuration.md) - Detailed configuration guide
- [Logging Configuration](logging.md) - Logging configuration
- [CORS Configuration](cors.md) - CORS configuration
