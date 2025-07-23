from collections.abc import Awaitable, Callable
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Literal

from fastapi import Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from typing_extensions import Self

from guard.protocols.geo_ip_protocol import GeoIPHandler


class SecurityConfig(BaseModel):
    """
    Configuration model for security settings.

    This class defines the structure for security configuration,
    including IP whitelists and blacklists, blocked countries,
    blocked user agents, rate limiting, automatic IP banning,
    HTTPS enforcement, custom hooks, CORS settings,
    and blocking of cloud provider IPs.

    Whitelist takes precedence over all other rules.
    IP addresses can be specified as individual IPs or CIDR ranges.
    Country codes should be specified in ISO 3166-1 alpha-2 format.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    trusted_proxies: list[str] = Field(
        default_factory=list,
        description="List of trusted proxy IPs or CIDR ranges for X-Forwarded-For",
    )
    """
    list[str]:
        List of trusted proxy IPs or CIDR ranges.
        Only accept X-Forwarded-For headers from these IPs.
        If empty, X-Forwarded-For headers will not be trusted.
    """

    trusted_proxy_depth: int = Field(
        default=1,
        description="How many proxies to expect in the X-Forwarded-For chain",
    )
    """
    int:
        How many proxies to expect in the proxy chain.
        Determines which IP to extract from X-Forwarded-For header.
        Default is 1 (extract the first IP in the chain).
    """

    trust_x_forwarded_proto: bool = Field(
        default=False,
        description="Trust X-Forwarded-Proto header for HTTPS detection",
    )
    """
    bool:
        Whether to trust X-Forwarded-Proto header for HTTPS detection.
        Only applies when trusted_proxies is not empty.
    """

    passive_mode: bool = Field(
        default=False,
        description="Enable Log-Only mode. Won't block requests, only log.",
    )
    """
    bool:
        Enable Log-Only mode. Won't block requests, only log.
    """

    geo_ip_handler: GeoIPHandler | None = Field(
        default=None,
        description="Geographical IP handler to use for IP geolocation",
    )
    """
    GeoIPHandler | None:
        The geographical IP handler to use for IP geolocation.
        Must be provided if blocked_countries or whitelist_countries is set.
        Must implement the GeoIPHandler protocol.

        This library provides a manager that uses the ipinfo API:
        `from guard import IPInfoManager`
    """

    enable_redis: bool = Field(
        default=True,
        description="Enable/disable Redis for distributed state management",
    )
    """
    bool:
        Whether to enable Redis for distributed state management.
    """

    redis_url: str | None = Field(
        default="redis://localhost:6379",
        description="Redis URL for distributed state management",
    )
    """
    str | None:
        The URL of the Redis server.
    """

    redis_prefix: str = Field(
        default="fastapi_guard:",
        description="Prefix for Redis keys to avoid collisions with other apps",
    )
    """
    str:
        The prefix for Redis keys to avoid collisions with other applications.
    """

    whitelist: list[str] | None = Field(
        default=None, description="Allowed IP addresses or CIDR ranges"
    )
    """
    list[str] | None:
        A list of IP addresses or
        ranges that are always allowed.
        If set to None, no whitelist is applied.
    """

    blacklist: list[str] = Field(
        default_factory=list, description="Blocked IP addresses or CIDR ranges"
    )
    """
    list[str]:
        A list of IP addresses or
        ranges that are always blocked.
    """

    whitelist_countries: list[str] = Field(
        default_factory=list,
        description="A list of country codes that are always allowed",
    )
    """
    list[str]:
        A list of country codes that are
        always allowed.
    """

    blocked_countries: list[str] = Field(
        default_factory=list,
        description="A list of country codes that are always blocked",
    )
    """
    list[str]:
        A list of country codes that are always blocked.
    """

    blocked_user_agents: list[str] = Field(
        default_factory=list, description="Blocked user agents"
    )
    """
    list[str]:
        A list of user agent strings or
        patterns that should be blocked.
    """

    auto_ban_threshold: int = Field(
        default=10, description="Number of suspicious requests before auto-ban"
    )
    """
    int:
        The threshold for auto-banning an IP
        address after a certain number of requests.
    """

    auto_ban_duration: int = Field(
        default=3600, description="Duration of auto-ban in seconds (default: 1 hour)"
    )
    """
    int:
        The duration in seconds for which
        an IP address should be banned after
        reaching the auto-ban threshold.
    """

    custom_log_file: str | None = Field(
        default=None,
        description="The path to a custom log file for logging security events",
    )
    """
    str | None:
        The path to a custom log file
        for logging security events.
    """

    log_suspicious_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default="WARNING", description="Log level for suspicious requests")
    """
    Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None:
        The logging level to use. If None, logging is disabled. Defaults to "WARNING".
    """

    log_request_level: (
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ) = Field(default=None, description="Log level for requests")
    """
    Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None:
        The logging level to use. If None, logging is disabled. Defaults to None.
    """

    custom_error_responses: dict[int, str] = Field(
        default_factory=dict, description="Custom error for specific HTTP status codes"
    )
    """
    dict[int, str]:
        A dictionary of custom error
        responses for specific HTTP status codes.
    """

    rate_limit: int = Field(
        default=10, description="Maximum requests per rate_limit_window"
    )
    """
    int:
        The maximum number of requests
        allowed per minute from a single IP.
    """

    rate_limit_window: int = Field(
        default=60, description="Rate limiting time window (seconds)"
    )
    """
    int:
        The time window in seconds for rate limiting.
    """

    enforce_https: bool = Field(
        default=False, description="Whether to enforce HTTPS connections"
    )
    """
    bool:
        Whether to enforce HTTPS connections.
        If True, all HTTP requests will be redirected to HTTPS.
    """

    custom_request_check: Callable[[Request], Awaitable[Response | None]] | None = (
        Field(default=None, description="Perform additional checks on the request")
    )
    """
    Callable[
        [Request],
        Awaitable[
            Response | None
        ]
    ] | None:
        A custom function to perform
        additional checks on the request.
        If it returns a Response, that response
        will be sent instead of continuing the middleware chain.
    """

    custom_response_modifier: Callable[[Response], Awaitable[Response]] | None = Field(
        default=None,
        description="A custom function to modify the response before it's sent",
    )
    """
    Callable[
        [Response],
        Awaitable[Response]
    ] | None:
        A custom function to modify
        the response before it's sent.
    """

    enable_cors: bool = Field(default=False, description="Enable/disable CORS")
    """
    bool:
        Whether to enable CORS.
    """

    cors_allow_origins: list[str] = Field(
        default_factory=lambda: ["*"], description="Origins allowed in CORS requests"
    )
    """
    list[str]:
        A list of origins that
        are allowed to access the API.
    """

    cors_allow_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        description="Methods allowed in CORS requests",
    )
    """
    list[str]:
        A list of methods that
        are allowed to access the API.
    """

    cors_allow_headers: list[str] = Field(
        default_factory=lambda: ["*"], description="Headers allowed in CORS requests"
    )
    """
    list[str]:
        A list of headers that are
        allowed in CORS requests.
    """

    cors_allow_credentials: bool = Field(
        default=False, description="Whether to allow credentials in CORS requests"
    )
    """
    bool:
        Whether to allow credentials
        in CORS requests.
    """

    cors_expose_headers: list[str] = Field(
        default_factory=list, description="Headers exposed in CORS responses"
    )
    """
    list[str]:
        A list of headers that
        are exposed in CORS responses.
    """

    cors_max_age: int = Field(
        default=600, description="Maximum age of CORS preflight results"
    )
    """
    int:
        The maximum age in seconds
        that the results of a preflight
        request can be cached.
    """

    block_cloud_providers: set[str] | None = Field(
        default=None, description="Set of cloud provider names to block"
    )
    """
    set[str] | None:
        A set of cloud provider names to block.
        Supported values: 'AWS', 'GCP', 'Azure'
    """

    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/openapi.yaml",
            "/favicon.ico",
            "/static",
        ],
        description="Paths to exclude from security checks",
    )
    """
    list[str]:
        A list of paths to exclude from security checks.
    """

    enable_ip_banning: bool = Field(
        default=True, description="Enable/disable IP banning functionality"
    )
    """
    bool:
        Whether to enable IP banning functionality.
    """

    enable_rate_limiting: bool = Field(
        default=True, description="Enable/disable rate limiting functionality"
    )
    """
    bool:
        Whether to enable rate limiting functionality.
    """

    enable_penetration_detection: bool = Field(
        default=True, description="Enable/disable penetration attempt detection"
    )
    """
    bool:
        Whether to enable penetration attempt detection.
    """

    regex_timeout: float = Field(
        default=2.0,
        description="Timeout for regex pattern matching to prevent ReDoS attacks",
        ge=0.1,
        le=30.0,
    )
    """
    float:
        Timeout in seconds for regex pattern matching.
        This prevents ReDoS (Regular Expression Denial of Service) attacks.
        Must be between 0.1 and 30.0 seconds. Default is 2.0 seconds.
    """

    ipinfo_token: str | None = Field(
        default=None,
        description="IPInfo API token for IP geolocation. Deprecated. "
        "Create a custom `geo_ip_handler` instead.",
        # TODO: deprecated=True,
    )
    """
    str | None:
        Deprecated. Create a custom `geo_ip_handler` instead.
        The IPInfo API token for IP geolocation.
        Must be provided if blocked_countries or whitelist_countries is set.
        Defaults to None.
    """

    ipinfo_db_path: Path | None = Field(
        default=Path("data/ipinfo/country_asn.mmdb"),
        description="Path to the IPInfo database file. Deprecated. "
        "Create a custom `geo_ip_handler` instead.",
        # TODO: deprecated=True,
    )
    """
    Path | None:
        Deprecated. Create a custom `geo_ip_handler` instead.
        The path to the IPInfo database file.
    """

    # TODO: Add type hints to the decorator
    @field_validator("whitelist", "blacklist")  # type: ignore
    def validate_ip_lists(cls, v: list[str] | None) -> list[str] | None:
        """Validate IP addresses and CIDR ranges in whitelist/blacklist."""
        if v is None:
            return None

        validated = []
        for entry in v:
            try:
                if "/" in entry:
                    network = ip_network(entry, strict=False)
                    validated.append(str(network))
                else:
                    addr = ip_address(entry)
                    validated.append(str(addr))
            except ValueError:
                raise ValueError(f"Invalid IP or CIDR range: {entry}") from None
        return validated

    # TODO: Add type hints to the decorator
    @field_validator("trusted_proxies")  # type: ignore
    def validate_trusted_proxies(cls, v: list[str]) -> list[str]:
        """Validate trusted proxy IPs and CIDR ranges."""
        if not v:
            return []

        validated = []
        for entry in v:
            try:
                if "/" in entry:
                    network = ip_network(entry, strict=False)
                    validated.append(str(network))
                else:
                    addr = ip_address(entry)
                    validated.append(str(addr))
            except ValueError:
                raise ValueError(f"Invalid proxy IP or CIDR range: {entry}") from None
        return validated

    # TODO: Add type hints to the decorator
    @field_validator("trusted_proxy_depth")  # type: ignore
    def validate_proxy_depth(cls, v: int) -> int:
        """Validate trusted proxy depth."""
        if v < 1:
            raise ValueError("trusted_proxy_depth must be at least 1")
        return v

    # TODO: Add type hints to the decorator
    @field_validator("block_cloud_providers", mode="before")  # type: ignore
    def validate_cloud_providers(cls, v: Any) -> set[str]:
        valid_providers = {"AWS", "GCP", "Azure"}
        if v is None:
            return set()
        return {p for p in v if p in valid_providers}

    # TODO: Add type hints to the decorator
    @model_validator(mode="after")  # type: ignore
    def validate_geo_ip_handler_exists(self) -> Self:
        if self.geo_ip_handler is None and (
            self.blocked_countries or self.whitelist_countries
        ):
            # Backwards compatibility with old config
            if self.ipinfo_token:
                from guard.handlers.ipinfo_handler import IPInfoManager

                self.geo_ip_handler = IPInfoManager(
                    token=self.ipinfo_token,
                    db_path=self.ipinfo_db_path,
                )
            else:
                raise ValueError(
                    "geo_ip_handler is required "
                    "if blocked_countries or whitelist_countries is set"
                )
        return self
