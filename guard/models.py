# fastapi_guard/models.py
from fastapi import (
    Request,
    Response
)
from ipaddress import (
    ip_network,
    IPv4Address
)
from pydantic import (
    BaseModel,
    field_validator,
    Field
)
from typing import (
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Set
)


class SecurityConfig(BaseModel):
    """
    Configuration model for security settings.

    This class defines the structure for security configuration,
    including IP whitelists and blacklists, blocked countries,
    blocked user agents, rate limiting, automatic IP banning,
    IP2Location settings, HTTPS enforcement, custom hooks, CORS settings,
    and blocking of cloud provider IPs.

    Whitelist takes precedence over all other rules.
    IP addresses can be specified as individual IPs or CIDR ranges.
    Country codes should be specified in ISO 3166-1 alpha-2 format.
    """

    ipinfo_token: str = Field(
        ...,
        description="IPInfo API token for IP geolocation"
    )
    """
    str:
        The IPInfo API token for IP geolocation.
    """

    whitelist: Optional[List[str]] = Field(
        default=None,
        description="Allowed IP addresses or CIDR ranges"
    )
    """
    Optional[List[str]]:
        A list of IP addresses or
        ranges that are always allowed.
        If set to None, no whitelist is applied.
    """

    blacklist: List[str] = Field(
        default=[],
        description="Blocked IP addresses or CIDR ranges"
    )
    """
    List[str]:
        A list of IP addresses or
        ranges that are always blocked.
    """

    whitelist_countries: List[str] = Field(
        default=[],
        description="A list of country codes that are always allowed"
    )
    """
    List[str]:
        A list of country codes that are
        always allowed.
    """

    blocked_countries: List[str] = Field(
        default=[],
        description="A list of country codes that are always blocked"
    )
    """
    List[str]:
        A list of country codes that are always blocked.
    """

    blocked_user_agents: List[str] = Field(
        default=[],
        description="Blocked user agents"
    )
    """
    List[str]:
        A list of user agent strings or
        patterns that should be blocked.
    """

    auto_ban_threshold: int = Field(
        default=20,
        description="Number of suspicious requests before auto-ban"
    )
    """
    int:
        The threshold for auto-banning an IP
        address after a certain number of requests.
    """

    auto_ban_duration: int = Field(
        default=3600,
        description="Duration of auto-ban in seconds (default: 1 hour)"
    )
    """
    int:
        The duration in seconds for which
        an IP address should be banned after
        reaching the auto-ban threshold.
    """

    custom_log_file: Optional[str] = Field(
        default=None,
        description="The path to a custom log file for logging security events"
    )
    """
    Optional[str]:
        The path to a custom log file
        for logging security events.
    """

    custom_error_responses: Dict[int, str] = Field(
        default={},
        description="Custom error for specific HTTP status codes"
    )
    """
    Dict[int, str]:
        A dictionary of custom error
        responses for specific HTTP status codes.
    """

    rate_limit: int = Field(
        default=10,
        description="Maximum requests per rate_limit_window"
    )
    """
    int:
        The maximum number of requests
        allowed per minute from a single IP.
    """

    rate_limit_window: int = Field(
        default=60,
        description="Rate limiting time window (seconds)"
    )
    """
    int:
        The time window in seconds for rate limiting.
    """

    enforce_https: bool = Field(
        default=False,
        description="Whether to enforce HTTPS connections"
    )
    """
    bool:
        Whether to enforce HTTPS connections.
        If True, all HTTP requests will be redirected to HTTPS.
    """

    custom_request_check: Optional[
        Callable[
            [Request],
            Awaitable[Optional[Response]]
        ]
    ] = Field(
        default=None,
        description="Perform additional checks on the request"
    )
    """
    Optional[
        Callable[[Request],
        Awaitable[
            Optional[
                Response
            ]
    ]]]:
        A custom function to perform
        additional checks on the request.
        If it returns a Response, that response
        will be sent instead of continuing the middleware chain.
    """

    custom_response_modifier: Optional[
        Callable[
            [Response],
            Awaitable[Response]
        ]
    ] = Field(
        default=None,
        description="A custom function to modify the response before it's sent"
    )
    """
    Optional[
        Callable[[Response],
        Awaitable[Response]
    ]]:
        A custom function to modify
        the response before it's sent.
    """

    enable_cors: bool = Field(
        default=False,
        description="Enable/disable CORS"
    )
    """
    bool:
        Whether to enable CORS.
    """

    cors_allow_origins: List[str] = Field(
        default=["*"],
        description="Origins allowed in CORS requests"
    )
    """
    List[str]:
        A list of origins that
        are allowed to access the API.
    """

    cors_allow_methods: List[str] = Field(
        default=[
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "OPTIONS"
        ],
        description="Methods allowed in CORS requests"
    )
    """
    List[str]:
        A list of methods that
        are allowed to access the API.
    """

    cors_allow_headers: List[str] = Field(
        default=["*"],
        description="Headers allowed in CORS requests"
    )
    """
    List[str]:
        A list of headers that are
        allowed in CORS requests.
    """

    cors_allow_credentials: bool = Field(
        default=False,
        description="Whether to allow credentials in CORS requests"
    )
    """
    bool:
        Whether to allow credentials
        in CORS requests.
    """

    cors_expose_headers: List[str] = Field(
        default=[],
        description="Headers exposed in CORS responses"
    )
    """
    List[str]:
        A list of headers that
        are exposed in CORS responses.
    """

    cors_max_age: int = Field(
        default=600,
        description="Maximum age of CORS preflight results"
    )
    """
    int:
        The maximum age in seconds
        that the results of a preflight
        request can be cached.
    """

    block_cloud_providers: Optional[Set[str]] = Field(
        default=None,
        description="Set of cloud provider names to block"
    )
    """
    Optional[Set[str]]:
        A set of cloud provider names to block.
        Supported values: 'AWS', 'GCP', 'Azure'
    """

    exclude_paths: List[str] = Field(
        default=[
            '/docs',
            '/redoc',
            '/openapi.json',
            '/openapi.yaml',
            '/favicon.ico',
            '/static',
        ],
        description="Paths to exclude from security checks"
    )
    """
    List[str]:
        A list of paths to exclude from security checks.
    """

    enable_ip_banning: bool = Field(
        default=False,
        description="Enable/disable IP banning functionality"
    )
    """
    bool:
        Whether to enable IP banning functionality.
    """

    enable_rate_limiting: bool = Field(
        default=True,
        description="Enable/disable rate limiting functionality"
    )
    """
    bool:
        Whether to enable rate limiting functionality.
    """

    enable_penetration_detection: bool = Field(
        default=False,
        description="Enable/disable penetration attempt detection"
    )
    """
    bool:
        Whether to enable penetration attempt detection.
    """

    @field_validator('whitelist', 'blacklist')
    def validate_ip_lists(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        """Validate IP addresses and CIDR ranges in whitelist/blacklist."""
        if v is None:
            return None

        validated = []
        for entry in v:
            try:
                if '/' in entry:
                    network = ip_network(entry, strict=False)
                    validated.append(str(network))
                else:
                    addr = IPv4Address(entry)
                    validated.append(str(addr))
            except ValueError:
                raise ValueError(f"Invalid IP or CIDR range: {entry}")
        return validated
