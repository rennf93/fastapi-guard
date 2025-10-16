# guard/core/checks/helpers.py
import re
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import urlparse

from fastapi import Request

from guard.decorators.base import RouteConfig
from guard.models import SecurityConfig
from guard.utils import detect_penetration_attempt


def is_ip_in_blacklist(client_ip: str, ip_addr: object, blacklist: list[str]) -> bool:
    """
    Check if IP is in blacklist (supports CIDR and single IPs).

    Args:
        client_ip: IP address as string
        ip_addr: IP address object from ipaddress module
        blacklist: List of IPs or CIDR ranges to check

    Returns:
        True if IP is blacklisted, False otherwise
    """
    for blocked in blacklist:
        if "/" in blocked:
            if ip_addr in ip_network(blocked, strict=False):
                return True
        elif client_ip == blocked:
            return True
    return False


def is_ip_in_whitelist(
    client_ip: str, ip_addr: object, whitelist: list[str]
) -> bool | None:
    """
    Check if IP is in whitelist (supports CIDR and single IPs).

    Args:
        client_ip: IP address as string
        ip_addr: IP address object from ipaddress module
        whitelist: List of IPs or CIDR ranges to check

    Returns:
        True if IP is whitelisted
        False if whitelist exists but IP not in it
        None if no whitelist configured
    """
    if not whitelist:
        return None

    for allowed in whitelist:
        if "/" in allowed:
            if ip_addr in ip_network(allowed, strict=False):
                return True
        elif client_ip == allowed:
            return True
    return False  # Whitelist exists but IP not in it


def check_country_access(
    client_ip: str, route_config: RouteConfig, geo_ip_handler: Any
) -> bool | None:
    """
    Check country-based access control.

    Args:
        client_ip: IP address to check
        route_config: Route-specific configuration
        geo_ip_handler: GeoIP handler for country lookups

    Returns:
        False if blocked by country rules
        True if allowed by country whitelist
        None if no country rules apply
    """
    if not geo_ip_handler:
        return None

    country = None

    # Check blocked countries
    if route_config.blocked_countries:
        country = geo_ip_handler.get_country(client_ip)
        if country and country in route_config.blocked_countries:
            return False

    # Check whitelisted countries
    if route_config.whitelist_countries:
        if country is None:  # Get country if not already fetched
            country = geo_ip_handler.get_country(client_ip)

        if country:
            return country in route_config.whitelist_countries
        return False  # Whitelist exists but no country found

    return None


def _check_ip_blacklist(
    client_ip: str, ip_addr: object, route_config: RouteConfig
) -> bool:
    """Check if IP is in route blacklist. Returns True if blocked."""
    if not route_config.ip_blacklist:
        return False
    return is_ip_in_blacklist(client_ip, ip_addr, route_config.ip_blacklist)


def _check_ip_whitelist(
    client_ip: str, ip_addr: object, route_config: RouteConfig
) -> bool | None:
    """
    Check if IP is in route whitelist.

    Returns:
        True if whitelisted
        False if whitelist exists but IP not in it
        None if no whitelist configured
    """
    return is_ip_in_whitelist(client_ip, ip_addr, route_config.ip_whitelist or [])


async def check_route_ip_access(
    client_ip: str, route_config: RouteConfig, middleware: Any
) -> bool | None:
    """
    Check route-specific IP access rules.

    Args:
        client_ip: IP address to check
        route_config: Route-specific configuration
        middleware: Middleware instance for accessing geo_ip_handler

    Returns:
        True if IP is allowed
        False if IP is blocked
        None if no route-specific rules apply (fall back to global)
    """
    try:
        ip_addr = ip_address(client_ip)

        # Check IP blacklist
        if _check_ip_blacklist(client_ip, ip_addr, route_config):
            return False

        # Check IP whitelist
        whitelist_result = _check_ip_whitelist(client_ip, ip_addr, route_config)
        if whitelist_result is not None:
            return whitelist_result

        # Check country-based access
        country_result = check_country_access(
            client_ip, route_config, middleware.geo_ip_handler
        )
        if country_result is not None:
            return country_result

        return None  # No route-specific rules, fall back to global
    except ValueError:
        return False


async def check_user_agent_allowed(
    user_agent: str, route_config: RouteConfig | None, config: Any
) -> bool:
    """
    Check user agent against both route and global rules.

    Args:
        user_agent: User agent string from request
        route_config: Route-specific configuration (optional)
        config: Global security configuration

    Returns:
        True if user agent is allowed, False otherwise
    """
    from guard.utils import is_user_agent_allowed as global_user_agent_check

    # Check route-specific blocked user agents first
    if route_config and route_config.blocked_user_agents:
        for pattern in route_config.blocked_user_agents:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return False

    # Fall back to global check
    return await global_user_agent_check(user_agent, config)


# Authentication helpers


def validate_auth_header(auth_header: str, auth_type: str) -> tuple[bool, str]:
    """
    Validate authentication header against required type.

    This function checks if the provided authentication header matches the
    expected authentication type (bearer, basic, or custom).

    Args:
        auth_header: The Authorization header value from the request
        auth_type: Expected authentication type (e.g., 'bearer', 'basic')

    Returns:
        Tuple of (is_valid, failure_reason):
            - is_valid: True if header is valid, False otherwise
            - failure_reason: Empty string if valid, error message if invalid

    Examples:
        >>> validate_auth_header("Bearer abc123", "bearer")
        (True, "")
        >>> validate_auth_header("Basic xyz", "bearer")
        (False, "Missing or invalid Bearer token")
    """
    if auth_type == "bearer":
        if not auth_header.startswith("Bearer "):
            return False, "Missing or invalid Bearer token"
    elif auth_type == "basic":
        if not auth_header.startswith("Basic "):
            return False, "Missing or invalid Basic authentication"
    else:
        # Generic auth requirement
        if not auth_header:
            return False, f"Missing {auth_type} authentication"

    return True, ""


# Referrer helpers


def is_referrer_domain_allowed(referrer: str, allowed_domains: list[str]) -> bool:
    """
    Check if referrer domain matches allowed domains.

    This function extracts the domain from the referrer URL and checks if it
    matches any of the allowed domains. Supports exact matches and subdomain
    matching (e.g., 'sub.example.com' matches 'example.com').

    Args:
        referrer: The Referer header value from the request
        allowed_domains: List of allowed domain names

    Returns:
        True if referrer domain is in allowed list, False otherwise

    Examples:
        >>> is_referrer_domain_allowed("https://example.com/page", ["example.com"])
        True
        >>> is_referrer_domain_allowed("https://sub.example.com/page", ["example.com"])
        True
        >>> is_referrer_domain_allowed("https://evil.com/page", ["example.com"])
        False
    """
    try:
        referrer_domain = urlparse(referrer).netloc.lower()
        for allowed_domain in allowed_domains:
            if referrer_domain == allowed_domain.lower() or referrer_domain.endswith(
                f".{allowed_domain.lower()}"
            ):
                return True
        return False
    except Exception:
        return False


# Suspicious activity helpers


def _get_effective_penetration_setting(
    config: SecurityConfig, route_config: RouteConfig | None
) -> tuple[bool, bool | None]:
    """
    Get effective penetration detection setting.

    Args:
        config: Global security configuration
        route_config: Route-specific configuration

    Returns:
        Tuple of (penetration_enabled, route_specific_detection)
    """
    route_specific_detection = None
    penetration_enabled = config.enable_penetration_detection

    if route_config and hasattr(route_config, "enable_suspicious_detection"):
        route_specific_detection = route_config.enable_suspicious_detection
        penetration_enabled = route_specific_detection

    return penetration_enabled, route_specific_detection


def _get_detection_disabled_reason(
    config: SecurityConfig, route_specific_detection: bool | None
) -> str:
    """Get reason why detection is disabled."""
    if route_specific_detection is False and config.enable_penetration_detection:
        return "disabled_by_decorator"
    return "not_enabled"


async def detect_penetration_patterns(
    request: Request,
    route_config: RouteConfig | None,
    config: SecurityConfig,
    should_bypass_check_fn: Any,
) -> tuple[bool, str]:
    """
    Determine if penetration detection should run and execute if enabled.

    This function checks if penetration detection is enabled (globally or per-route),
    and if so, runs the detection logic. It handles both global and route-specific
    configuration, with route-specific settings taking precedence.

    Args:
        request: The FastAPI request object
        route_config: Route-specific security configuration (if any)
        config: Global security configuration
        should_bypass_check_fn: Function to check if check should be bypassed

    Returns:
        Tuple of (detection_result, trigger_info):
            - detection_result: True if suspicious patterns detected, False otherwise
            - trigger_info: Description of what triggered detection or why disabled

    Trigger info values:
        - Pattern description: When suspicious activity detected
        - "disabled_by_decorator": Route-specific detection disabled
        - "not_enabled": Detection not enabled globally or per-route

    Examples:
        Detection enabled and patterns found:
        >>> result, info = await detect_penetration_patterns(...)
        >>> (True, "SQL injection pattern in path")

        Detection disabled by decorator:
        >>> result, info = await detect_penetration_patterns(...)
        >>> (False, "disabled_by_decorator")
    """
    # Get effective penetration detection setting
    penetration_enabled, route_specific_detection = _get_effective_penetration_setting(
        config, route_config
    )

    # Run detection if enabled and not bypassed
    if penetration_enabled and not should_bypass_check_fn("penetration", route_config):
        return await detect_penetration_attempt(request)

    # Detection disabled - return reason
    reason = _get_detection_disabled_reason(config, route_specific_detection)
    return False, reason
