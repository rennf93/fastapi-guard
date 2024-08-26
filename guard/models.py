# fastapi_guard/models.py
from fastapi import Request, Response
from pydantic import BaseModel
from typing import Dict, List, Optional, Callable, Awaitable, Set


class SecurityConfig(BaseModel):
    """
    Configuration model for security settings.

    This class defines the structure for security configuration,
    including IP whitelists and blacklists, blocked countries,
    blocked user agents, rate limiting, automatic IP banning,
    IP2Location settings, HTTPS enforcement, custom hooks, CORS settings,
    and blocking of cloud provider IPs.
    """

    whitelist: Optional[List[str]] = None
    """
    Optional[List[str]]:
        A list of IP addresses or
        ranges that are always allowed.
        If set to None, no whitelist is applied.
    """

    blacklist: List[str] = []
    """
    List[str]:
        A list of IP addresses or
        ranges that are always blocked.
    """

    blocked_countries: List[str] = []
    """
    List[str]:
        A list of country codes whose
        IP addresses should be blocked.
    """

    blocked_user_agents: List[str] = []
    """
    List[str]:
        A list of user agent strings or
        patterns that should be blocked.
    """

    auto_ban_threshold: int = 5
    """
    int:
        The threshold for auto-banning an IP
        address after a certain number of requests.
    """

    auto_ban_duration: int = 86400
    """
    int:
        The duration in seconds for which
        an IP address should be banned after
        reaching the auto-ban threshold.
    """

    custom_log_file: Optional[str] = None
    """
    Optional[str]:
        The path to a custom log file
        for logging security events.
    """

    custom_error_responses: Dict[int, str] = {}
    """
    Dict[int, str]:
        A dictionary of custom error
        responses for specific HTTP status codes.
    """

    rate_limit: int = 100
    """
    int:
        The maximum number of requests
        allowed per minute from a single IP.
    """

    use_ip2location: bool = False
    """
    bool:
        Whether to use the IP2Location
        database for IP geolocation.
    """

    ip2location_db_path: Optional[str] = None
    """
    Optional[str]:
        The path to the IP2Location
        database file.
    """

    ip2location_auto_download: bool = False
    """
    bool:
        Whether to automatically download
        the IP2Location database if it's not found.
    """

    ip2location_auto_update: bool = False
    """
    bool:
        Whether to automatically update
        the IP2Location database periodically.
    """

    ip2location_update_interval: int = 24
    """
    int:
        The interval in hours for automatic
        IP2Location database updates.
    """

    use_ipinfo_fallback: bool = True
    """
    bool:
        Whether to use ipinfo.io as a fallback
        for IP geolocation when IP2Location fails.
    """

    enforce_https: bool = False
    """
    bool:
        Whether to enforce HTTPS connections.
        If True, all HTTP requests will be redirected to HTTPS.
    """

    custom_request_check: Optional[
        Callable[[Request], Awaitable[Optional[Response]]]
    ] = None
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

    custom_response_modifier: Optional[Callable[[Response], Awaitable[Response]]] = None
    """
    Optional[
        Callable[[Response],
        Awaitable[Response]
    ]]:
        A custom function to modify
        the response before it's sent.
    """

    enable_cors: bool = False
    """
    bool:
        Whether to enable CORS.
    """

    cors_allow_origins: List[str] = ["*"]
    """
    List[str]:
        A list of origins that
        are allowed to access the API.
    """

    cors_allow_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    """
    List[str]:
        A list of methods that
        are allowed to access the API.
    """

    cors_allow_headers: List[str] = ["*"]
    """
    List[str]:
        A list of headers that are
        allowed in CORS requests.
    """

    cors_allow_credentials: bool = False
    """
    bool:
        Whether to allow credentials
        in CORS requests.
    """

    cors_expose_headers: List[str] = []
    """
    List[str]:
        A list of headers that
        are exposed in CORS responses.
    """

    cors_max_age: int = 600
    """
    int:
        The maximum age in seconds
        that the results of a preflight
        request can be cached.
    """

    block_cloud_providers: Optional[Set[str]] = None
    """
    Optional[Set[str]]:
        A set of cloud provider names to block.
        Supported values: 'AWS', 'GCP', 'Azure'
    """
