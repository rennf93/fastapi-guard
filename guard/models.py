# fastapi_guard/models.py
from pydantic import BaseModel
from typing import Dict, List, Optional



class SecurityConfig(BaseModel):
    """
    Configuration model for security settings.

    This class defines the structure for security configuration,
    including IP whitelists and blacklists, blocked countries,
    blocked user agents, rate limiting, and automatic IP banning.
    """

    whitelist: Optional[List[str]] = None
    """
    Optional[List[str]]: A list of IP addresses or ranges that are always allowed.
    If set to None, no whitelist is applied.
    """

    blacklist: List[str] = []
    """
    List[str]: A list of IP addresses or ranges that are always blocked.
    """

    blocked_countries: List[str] = []
    """
    List[str]: A list of country codes whose IP addresses should be blocked.
    """

    blocked_user_agents: List[str] = []
    """
    List[str]: A list of user agent strings or patterns that should be blocked.
    """

    auto_ban_threshold: int = 5
    """
    int: The threshold for auto-banning an IP address after a certain number of requests.
    """

    auto_ban_duration: int = 86400
    """
    int: The duration in seconds for which an IP address should be banned after reaching the auto-ban threshold.
    """

    custom_log_file: Optional[str] = None
    """
    Optional[str]: The path to a custom log file for logging security events.
    """

    custom_error_responses: Dict[int, str] = {}
    """
    Dict[int, str]: A dictionary of custom error responses for specific HTTP status codes.
    """

    rate_limit: int = 100
    """
    int: The maximum number of requests allowed per minute from a single IP.
    """