---

title: Security Configuration - FastAPI Guard
description: Complete guide to FastAPI Guard's SecurityConfig model and configuration options
keywords: security config, configuration, settings, pydantic model
---

Security Configuration
=====================

FastAPI Guard uses Pydantic models for configuration and data structures.

___

SecurityConfig
--------------

The main configuration model for FastAPI Guard middleware.

```python
class SecurityConfig(BaseModel):
    """
    Main configuration model for FastAPI Guard.
    """
```

Core Security Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `passive_mode` | bool | False | If True, only log without blocking |
| `enable_ip_banning` | bool | True | Enable/disable IP banning functionality |
| `enable_rate_limiting` | bool | True | Enable/disable rate limiting functionality |
| `enable_penetration_detection` | bool | True | Enable penetration attempt detection |
| `fail_secure` | bool | True | Block the request when a security check raises an unexpected exception |
| `auto_ban_threshold` | int | 10 | Number of suspicious requests before auto-ban |
| `auto_ban_duration` | int | 3600 | Auto-ban duration in seconds |
| `rate_limit` | int | 10 | Maximum requests per `rate_limit_window` |
| `rate_limit_window` | int | 60 | Rate limiting time window (seconds) |
| `enforce_https` | bool | False | Whether to enforce HTTPS connections |
| `exclude_paths` | list[str] | `["/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static"]` | Paths to exclude from security checks |

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
| `whitelist` | list[str] \| None | None | Allowed IP addresses or CIDR ranges |
| `blacklist` | list[str] | [] | Blocked IP addresses or CIDR ranges |
| `whitelist_countries` | frozenset[str] | `frozenset()` | Country codes that are always allowed |
| `blocked_countries` | frozenset[str] | `frozenset()` | Country codes that are always blocked |
| `blocked_user_agents` | list[str] | [] | Blocked user agents |
| `trusted_proxies` | list[str] | [] | Trusted proxy IPs or CIDR ranges for X-Forwarded-For |
| `trusted_proxy_depth` | int | 1 | How many proxies to expect in the X-Forwarded-For chain |
| `trust_x_forwarded_proto` | bool | False | Trust X-Forwarded-Proto header for HTTPS detection |

Redis Settings
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_redis` | bool | True | Enable/disable Redis for distributed state management |
| `redis_url` | str \| None | "redis://localhost:6379" | Redis URL for distributed state management |
| `redis_prefix` | str | "guard_core:" | Prefix for Redis keys to avoid collisions with other apps |

Agent Settings
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_agent` | bool | False | Enable Guard Agent telemetry and monitoring |
| `agent_api_key` | str \| None | None | API key for Guard Agent SaaS platform |
| `agent_endpoint` | str | "https://api.guard-core.com" | Guard Agent SaaS platform endpoint |
| `agent_project_id` | str \| None | None | Project ID for organizing telemetry data |
| `agent_buffer_size` | int | 100 | Number of events to buffer before auto-flush |
| `agent_flush_interval` | int | 30 | Interval in seconds between automatic buffer flushes |
| `agent_enable_events` | bool | True | Enable sending security events to SaaS platform |
| `agent_enable_metrics` | bool | True | Enable sending performance metrics to SaaS platform |

Cloud Provider Settings
-----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ipinfo_token` | str \| None | None | IPInfo API token for geolocation (deprecated; use a custom `geo_ip_handler`) |
| `ipinfo_db_path` | Path \| None | `Path("data/ipinfo/country_asn.mmdb")` | Path to the IPInfo database file (deprecated; use a custom `geo_ip_handler`) |
| `block_cloud_providers` | set[CloudProvider] \| None | None | Set of cloud provider names to block (`"AWS"`, `"GCP"`, `"Azure"`) |
| `cloud_ip_refresh_interval` | int | 3600 | Interval in seconds between cloud IP range refreshes (60-86400) |

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
| `enable_cors` | bool | False | Enable/disable CORS |
| `cors_allow_origins` | list[str] | ["*"] | Origins allowed in CORS requests |
| `cors_allow_methods` | list[str] | `["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]` | Methods allowed in CORS requests |
| `cors_allow_headers` | list[str] | ["*"] | Headers allowed in CORS requests |
| `cors_allow_credentials` | bool | False | Whether to allow credentials in CORS requests |
| `cors_expose_headers` | list[str] | [] | Headers exposed in CORS responses |
| `cors_max_age` | int | 600 | Maximum age of CORS preflight results |

Logging Settings
----------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_suspicious_level` | Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] \| None | "WARNING" | Log level for suspicious requests |
| `log_request_level` | Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] \| None | None | Log level for requests |
| `custom_log_file` | str \| None | None | Custom log file path |
| `log_format` | Literal["text", "json"] | "text" | Log output format: "text" for plain text, "json" for structured JSON |

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
    enable_redis=True,
    redis_url="redis://localhost:6379",
    redis_prefix="guard_core:",

    # Agent
    enable_agent=True,
    agent_api_key="your-api-key",

    # Logging
    custom_log_file="security.log",
    log_suspicious_level="WARNING",
    log_format="json",

    # Cloud provider refresh
    cloud_ip_refresh_interval=1800,
)
```

___

Other Models
------------

DetectionResult
---------------

The result returned by the detection engine when analyzing a request:

```python
@dataclass
class DetectionResult:
    is_threat: bool
    trigger_info: str
    threat_categories: list[str] = field(default_factory=list)
    threat_scores: dict[str, float] = field(default_factory=dict)
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
    detection_compiler_timeout=2.0,      # 0.1 - 10.0
    detection_semantic_threshold=0.7,    # 0.0 - 1.0
    detection_anomaly_threshold=3.0,     # 1.0 - 10.0
    auto_ban_threshold=10,
    auto_ban_duration=3600,
)
```

___

Model Serialization
-------------------

All models support standard Pydantic serialization:

```python
# Export configuration
config_dict = config.model_dump(exclude_unset=True)
config_json = config.model_dump_json(indent=2)

# Import configuration
config = SecurityConfig.model_validate(config_dict)
config = SecurityConfig.model_validate_json(config_json)

# Schema generation
schema = SecurityConfig.model_json_schema()
```

___

Custom Validators
-----------------

The models include custom validators for complex fields:

```python
@field_validator("whitelist", "blacklist")
def validate_ip_lists(cls, v: list[str] | None) -> list[str] | None:
    if v is None:
        return None
    validated = []
    for entry in v:
        try:
            if "/" in entry:
                validated.append(str(ip_network(entry, strict=False)))
            else:
                validated.append(str(ip_address(entry)))
        except ValueError:
            raise ValueError(f"Invalid IP or CIDR range: {entry}") from None
    return validated

@model_validator(mode="after")
def validate_agent_config(self) -> Self:
    if self.enable_agent and not self.agent_api_key:
        raise ValueError("agent_api_key is required when enable_agent is True")
    return self
```

___

See Also
--------

- [Security Middleware](../../api/security-middleware.md) - Using SecurityConfig with middleware
- [Detection Engine Configuration](../security/detection-engine/configuration.md) - Detailed configuration guide
- [Logging Configuration](logging.md) - Logging configuration
- [CORS Configuration](cors.md) - CORS configuration
