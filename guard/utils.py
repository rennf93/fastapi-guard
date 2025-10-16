# guard/utils.py
import logging
import re
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any, Literal

from fastapi import Request

from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.suspatterns_handler import sus_patterns_handler
from guard.models import GeoIPHandler, SecurityConfig
from guard.protocols.agent_protocol import AgentHandlerProtocol


def _sanitize_for_log(value: str) -> str:
    """
    Sanitize user-controlled values for safe logging.

    Removes or replaces newlines, carriage returns, and control characters
    that could be used for log injection attacks.

    Args:
        value: The string to sanitize

    Returns:
        Sanitized string safe for logging
    """
    if not value:
        return value
    # Replace newlines, carriage returns, and other control characters
    sanitized = value.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    # Remove other control characters (ASCII 0-31 except tab, newline, carriage return)
    sanitized = "".join(
        char if ord(char) >= 32 or char in "\t\n\r" else f"\\x{ord(char):02x}"
        for char in sanitized
    )
    return sanitized


async def send_agent_event(
    agent_handler: AgentHandlerProtocol | None,
    event_type: str,
    ip_address: str,
    action_taken: str,
    reason: str,
    request: Request | None = None,
    **kwargs: Any,
) -> None:
    """
    Helper function to send events to agent with proper error handling.

    NOTE: This is a utility helper function. Domain-specific events should be sent
    by their respective handlers (ipban_handler, cloud_handler, etc.) which have
    more detailed context about what actually happened.

    Args:
        agent_handler: The agent handler instance
        event_type: Type of security event
        ip_address: Client IP address
        action_taken: Action that was taken
        reason: Reason for the action
        request: Optional FastAPI request object
        **kwargs: Additional metadata
    """
    if not agent_handler:
        return

    try:
        # Extract request information if available
        endpoint = None
        method = None
        user_agent = None
        country = None

        if request:
            endpoint = str(request.url.path)
            method = request.method
            user_agent = request.headers.get("User-Agent")

        from guard_agent import SecurityEvent

        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            ip_address=ip_address,
            country=country,
            user_agent=user_agent,
            action_taken=action_taken,
            reason=reason,
            endpoint=endpoint,
            method=method,
            **kwargs,
        )

        await agent_handler.send_event(event)
    except Exception as e:
        # Don't let agent errors break the main functionality
        logging.getLogger(__name__).error(f"Failed to send agent event: {e}")


def setup_custom_logging(log_file: str | None = None) -> logging.Logger:
    """
    Setup custom logging for FastAPI Guard.

    Configures a hierarchical logger that outputs to both console and file.
    Console output is ALWAYS enabled for visibility.
    File output is optional for persistence.
    """
    logger = logging.getLogger("fastapi_guard")
    logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("[%(name)s] %(asctime)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(console_handler)

    # File handler
    if log_file:
        try:
            import os

            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
            )
            logger.addHandler(file_handler)
        except Exception as e:
            # Log to console if file handler fails
            logger.warning(f"Failed to create log file {log_file}: {e}")

    logger.setLevel(logging.INFO)
    # Allow propagation so tests can capture logs (pytest-cov)

    return logger


async def _check_ip_spoofing(
    connecting_ip: str,
    forwarded_for: str | None,
    config: SecurityConfig,
    request: Request,
    agent_handler: AgentHandlerProtocol | None,
) -> None:
    """Check and log potential IP spoofing attempts."""
    if forwarded_for and not config.trusted_proxies:
        # Sanitize user-controlled header value before logging to prevent log injection
        safe_forwarded_for = _sanitize_for_log(forwarded_for)
        logging.warning(
            f"Potential IP spoof attempt: X-Forwarded-For header "  # nosemgrep
            f"({safe_forwarded_for}) received from untrusted IP {connecting_ip}"
        )
        # Send agent event for IP spoofing attempt
        await send_agent_event(
            agent_handler,
            "suspicious_request",
            connecting_ip,
            "spoofing_detected",
            f"Potential IP spoof attempt: X-Forwarded-For header {forwarded_for}",
            request,
        )


def _is_trusted_proxy(connecting_ip: str, trusted_proxies: list[str]) -> bool:
    """Check if the connecting IP is from a trusted proxy."""
    try:
        connecting_ip_obj = ip_address(connecting_ip)

        for proxy in trusted_proxies:
            if "/" in proxy:  # CIDR notation
                if connecting_ip_obj in ip_network(proxy, strict=False):
                    return True
            elif connecting_ip == proxy:  # Direct IP match
                return True
        return False
    except ValueError:
        return False


def _extract_from_forwarded_header(forwarded_for: str, proxy_depth: int) -> str | None:
    """Extract client IP from X-Forwarded-For header."""
    if not forwarded_for:
        return None

    # Parse the header
    ips = [ip.strip() for ip in forwarded_for.split(",")]

    if len(ips) >= proxy_depth:
        client_ip_index = 0
        return ips[client_ip_index]

    return None


async def extract_client_ip(
    request: Request,
    config: SecurityConfig,
    agent_handler: AgentHandlerProtocol | None = None,
) -> str:
    """
    Securely extract the client IP address from the request,
    considering trusted proxies.

    This function implements a secure approach to IP extraction that protects against
    X-Forwarded-For header injection attacks:

    1. If no trusted proxies are defined, the connecting IP (request.client.host) is
       always used
    2. If trusted proxies are defined, X-Forwarded-For is only processed when
       the request originates from a trusted proxy IP
    3. When processing X-Forwarded-For from trusted proxies, the client's true IP
       is extracted based on the proxy depth configuration

    About proxy depth:
    - X-Forwarded-For format: client, proxy1, proxy2, ... (leftmost is the real client)
    - With depth=1 (default): Assumes one proxy in chain, uses leftmost IP as client
    - With depth=2: Assumes two proxies in chain, still uses leftmost IP
    - Higher depth values handle more complex proxy chains

    Args:
        request (Request):
            The FastAPI request object
        config (SecurityConfig):
            The security configuration containing trusted proxy settings

    Returns:
        str: The extracted client IP address
    """
    if not request.client:
        return "unknown"

    connecting_ip = request.client.host
    forwarded_for = request.headers.get("X-Forwarded-For")

    # Check for IP spoofing attempts
    await _check_ip_spoofing(
        connecting_ip, forwarded_for, config, request, agent_handler
    )

    # Don't trust X-Forwarded-For if no trusted proxies
    if not config.trusted_proxies:
        return connecting_ip

    # Check if connecting IP is trusted
    is_trusted = _is_trusted_proxy(connecting_ip, config.trusted_proxies)

    if not is_trusted:
        if forwarded_for:
            # Sanitize user-controlled header value
            # before logging to prevent log injection
            safe_forwarded_for = _sanitize_for_log(forwarded_for)
            logging.warning(
                f"Potential IP spoof attempt: X-Forwarded-For header "  # nosemgrep
                f"({safe_forwarded_for}) received from untrusted IP {connecting_ip}"
            )
            # Send agent event for IP spoofing attempt from untrusted proxy
            await send_agent_event(
                agent_handler,
                "suspicious_request",
                connecting_ip,
                "spoofing_detected",
                f"Potential IP spoof attempt: X-Forwarded-For header {forwarded_for}",
                request,
            )
        return connecting_ip

    # Process X-Forwarded-For from trusted proxy
    try:
        if not forwarded_for:
            return connecting_ip

        client_ip = _extract_from_forwarded_header(
            forwarded_for, config.trusted_proxy_depth
        )
        if client_ip:
            return client_ip
    except (ValueError, IndexError) as e:
        logging.warning(f"Error processing client IP: {str(e)}")

    # Fall back to connecting IP
    return connecting_ip


def _extract_request_context(request: Request) -> dict[str, Any]:
    """
    Extract basic context information from request.

    Returns:
        Dict with client_ip, method, url, and headers
    """
    client_ip = "unknown"
    if request.client:
        client_ip = request.client.host

    return {
        "client_ip": client_ip,
        "method": request.method,
        "url": str(request.url),
        "headers": dict(request.headers),
    }


def _build_log_message_for_request(context: dict[str, Any]) -> tuple[str, str]:
    """Build log message components for regular request logging."""
    message = "Request from"
    details = f"{message} {context['client_ip']}: {context['method']} {context['url']}"
    reason_message = f"Headers: {context['headers']}"
    return details, reason_message


def _build_log_message_for_suspicious(
    context: dict[str, Any], reason: str, passive_mode: bool, trigger_info: str
) -> tuple[str, str]:
    """Build log message components for suspicious activity logging."""
    if passive_mode:
        message = "[PASSIVE MODE] Penetration attempt detected from"
        details = (
            f"{message} {context['client_ip']}: {context['method']} {context['url']}"
        )

        trigger_message = f"Trigger: {trigger_info}" if trigger_info else ""
        reason_message = f"Headers: {context['headers']}"
        if trigger_message:
            reason_message = f"{trigger_message} - {reason_message}"
    else:
        message = "Suspicious activity detected from"
        details = (
            f"{message} {context['client_ip']}: {context['method']} {context['url']}"
        )
        reason_message = f"Reason: {reason} - Headers: {context['headers']}"

    return details, reason_message


def _build_log_message_generic(
    context: dict[str, Any], log_type: str, reason: str
) -> tuple[str, str]:
    """Build log message components for generic log types."""
    message = f"{log_type.capitalize()} from"
    details = f"{message} {context['client_ip']}: {context['method']} {context['url']}"
    reason_message = f"Details: {reason} - Headers: {context['headers']}"
    return details, reason_message


def _log_at_level(logger: logging.Logger, level: str, msg: str) -> None:
    """Execute logging at the specified level."""
    if level == "INFO":
        logger.info(msg)
    elif level == "DEBUG":
        logger.debug(msg)
    elif level == "WARNING":
        logger.warning(msg)
    elif level == "ERROR":
        logger.error(msg)
    elif level == "CRITICAL":
        logger.critical(msg)


async def log_activity(
    request: Request,
    logger: logging.Logger,
    log_type: str = "request",
    reason: str = "",
    passive_mode: bool = False,
    trigger_info: str = "",
    level: Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None = "WARNING",
) -> None:
    """
    Universal logging function for all types of requests and activities.

    Args:
        request (Request):
            The FastAPI request object.
        logger (logging.Logger):
            The logger instance to use.
        log_type (str, optional):
            Type of log entry: "request" or "suspicious".
            Defaults to "request".
        reason (str, optional):
            The reason for flagging activity (for suspicious activity).
        passive_mode (bool, optional):
            Whether this is being logged in passive mode.
            If True, adds "[PASSIVE MODE]" prefix to the log.
        trigger_info (str, optional):
            Additional information about what triggered the detection.
        level (Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"], optional):
            The log level to use. If None, logging is disabled.
            Defaults to "WARNING".
    """
    if level is None:
        return

    # Extract request context
    context = _extract_request_context(request)

    # Build message based on log type
    if log_type == "request":
        details, reason_message = _build_log_message_for_request(context)
    elif log_type == "suspicious":
        details, reason_message = _build_log_message_for_suspicious(
            context, reason, passive_mode, trigger_info
        )
    else:
        details, reason_message = _build_log_message_generic(context, log_type, reason)

    # Combine and log
    msg = f"{details} - {reason_message}"
    _log_at_level(logger, level, msg)


async def is_user_agent_allowed(user_agent: str, config: SecurityConfig) -> bool:
    """
    Check if the user agent is allowed
    based on the security configuration.

    Args:
        user_agent (str):
            The user agent string to check.
        config (SecurityConfig):
            The security configuration object.

    Returns:
        bool: True if the user agent
              is allowed, False otherwise.
    """
    for pattern in config.blocked_user_agents:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return False
    return True


def _extract_ip_from_request(request: str | Request) -> str:
    """Extract IP address from request object or string."""
    if isinstance(request, str):
        return request
    return request.client.host if request.client else "unknown"


def _has_country_rules(config: SecurityConfig) -> bool:
    """Check if any country-based rules are configured."""
    return bool(config.blocked_countries or config.whitelist_countries)


def _log_country_check_result(ip: str, country: str | None, result_type: str) -> None:
    """Log the result of a country check."""
    if result_type == "no_rules":
        logging.warning(
            f"No countries blocked or whitelisted {ip} - "
            "No countries blocked or whitelisted"
        )
    elif result_type == "no_geolocation":
        logging.warning(f"IP not geolocated {ip} - IP geolocation failed")
    elif result_type == "whitelisted":
        logging.info(
            f"IP from whitelisted country {ip} - {country} - "
            "IP from whitelisted country"
        )
    elif result_type == "blocked":
        logging.warning(
            f"IP from blocked country {ip} - {country} - IP from blocked country"
        )
    elif result_type == "not_affected":
        logging.info(
            f"IP not from blocked or whitelisted country {ip} - {country} - "
            "IP not from blocked or whitelisted country"
        )


def _evaluate_country_access(country: str, config: SecurityConfig) -> tuple[bool, str]:
    """
    Evaluate if IP should be blocked based on country.

    Returns:
        Tuple of (is_blocked, result_type)
    """
    # Whitelist takes precedence
    if config.whitelist_countries and country in config.whitelist_countries:
        return False, "whitelisted"

    # Then check blocklist
    if config.blocked_countries and country in config.blocked_countries:
        return True, "blocked"

    # Not affected by rules
    return False, "not_affected"


async def check_ip_country(
    request: str | Request,
    config: SecurityConfig,
    geo_ip_handler: GeoIPHandler,
) -> bool:
    """
    Check if IP is from a blocked country
    or in the whitelist.

    Args:
        request (str | Request):
            The FastAPI request object or IP string.
        config (SecurityConfig):
            The security configuration object.
        geo_ip_handler (GeoIPHandler):
            The IPInfo database handler.

    Returns:
        bool:
            True if the IP is from a blocked
            country or in the whitelist,
            False otherwise.
    """
    # Early return if no country rules configured
    if not _has_country_rules(config):
        ip = _extract_ip_from_request(request)
        _log_country_check_result(ip, None, "no_rules")
        return False

    # Ensure GeoIP handler is initialized
    if not geo_ip_handler.is_initialized:
        await geo_ip_handler.initialize()

    # Extract IP and get country
    ip = _extract_ip_from_request(request)
    country = geo_ip_handler.get_country(ip)

    # Handle geolocation failure
    if not country:
        _log_country_check_result(ip, None, "no_geolocation")
        return False

    # Evaluate access based on country
    is_blocked, result_type = _evaluate_country_access(country, config)
    _log_country_check_result(ip, country, result_type)

    return is_blocked


async def _check_blacklist(ip_addr: Any, ip: str, config: SecurityConfig) -> bool:
    if config.blacklist:
        for blocked in config.blacklist:
            if "/" in blocked:  # CIDR
                if ip_addr in ip_network(blocked, strict=False):
                    return False
            elif ip == blocked:  # Direct match
                return False
    return True


async def _check_whitelist(ip_addr: Any, ip: str, config: SecurityConfig) -> bool:
    if config.whitelist:
        for allowed in config.whitelist:
            if "/" in allowed:  # CIDR
                if ip_addr in ip_network(allowed, strict=False):
                    return True
            elif ip == allowed:  # Direct match
                return True
        return False  # If whitelist exists but IP not in it
    return True


async def _check_blocked_countries(
    ip: str, config: SecurityConfig, geo_ip_handler: GeoIPHandler | None
) -> bool:
    if config.blocked_countries and geo_ip_handler:
        country_blocked = await check_ip_country(ip, config, geo_ip_handler)
        if country_blocked:
            return False
    return True


async def _check_cloud_providers(ip: str, config: SecurityConfig) -> bool:
    if config.block_cloud_providers and cloud_handler.is_cloud_ip(
        ip, config.block_cloud_providers
    ):
        return False
    return True


async def is_ip_allowed(
    ip: str,
    config: SecurityConfig,
    geo_ip_handler: GeoIPHandler | None = None,
) -> bool:
    """
    Check if the IP address is allowed
    based on the security configuration.

    Args:
        ip (str):
            The IP address to check.
        config (SecurityConfig):
            The security configuration object.
        geo_ip_handler (GeoIPHandler | None):
            The IPInfo database handler.

    Returns:
        bool:
            True if the IP is allowed, False otherwise.
    """
    try:
        ip_addr = ip_address(ip)

        if not await _check_blacklist(ip_addr, ip, config):
            return False

        if not await _check_whitelist(ip_addr, ip, config):
            return False

        if not await _check_blocked_countries(ip, config, geo_ip_handler):
            return False

        if not await _check_cloud_providers(ip, config):
            return False

        return True
    except ValueError:
        return False  # Invalid IP
    except Exception as e:
        logging.error(f"Error checking IP {ip}: {str(e)}")
        return True


async def _check_json_fields(
    data: dict,
    context: str,
    client_ip: str,
    correlation_id: str,
) -> tuple[bool, str]:
    """Check JSON fields for penetration attempts."""
    for k, v in data.items():
        if isinstance(v, str):
            result = await sus_patterns_handler.detect(
                content=v,
                ip_address=client_ip,
                context=f"{context}.{k}",
                correlation_id=correlation_id,
            )
            if result["is_threat"]:
                if result["threats"]:
                    threat = result["threats"][0]
                    if threat["type"] == "regex":
                        pattern = threat["pattern"]
                        return True, f"JSON field '{k}' matched pattern '{pattern}'"
                    else:
                        threat_type = threat["type"]
                        return True, f"JSON field '{k}' contains: {threat_type}"
                return True, f"JSON field '{k}' contains threat"
    return False, ""


async def _try_check_json_value(
    value: str, context: str, client_ip: str, correlation_id: str
) -> tuple[bool, str] | None:
    """
    Try to parse value as JSON and check fields.

    Returns:
        Detection result tuple if value is JSON dict, None otherwise
    """
    try:
        import json

        data = json.loads(value)
        if isinstance(data, dict):
            return await _check_json_fields(data, context, client_ip, correlation_id)
    except json.JSONDecodeError:
        pass  # Not JSON, caller will check as plain string
    return None


def _build_threat_message(threat: dict[str, Any]) -> str:
    """Build informative message from threat detection result."""
    if threat["type"] == "regex":
        return f"Value matched pattern '{threat['pattern']}'"
    elif threat["type"] == "semantic":
        attack_type = threat.get("attack_type", "suspicious")
        score = threat.get("probability", threat.get("threat_score", 0))
        return f"Semantic attack: {attack_type} (score: {score:.2f})"
    return "Threat detected"


async def _fallback_pattern_check(value: str) -> tuple[bool, str]:
    """Fallback to basic pattern matching if enhanced detection fails."""
    for pattern in await sus_patterns_handler.get_all_compiled_patterns():
        try:
            if pattern.search(value):
                return True, "Value matched pattern (fallback)"
        except Exception:
            continue
    return False, ""


async def _check_value_enhanced(
    value: str,
    context: str,
    client_ip: str,
    correlation_id: str,
) -> tuple[bool, str]:
    """Enhanced threat detection for a single value."""
    # First check if value looks like JSON
    json_result = await _try_check_json_value(value, context, client_ip, correlation_id)
    if json_result is not None:
        return json_result

    # Use enhanced detection engine
    try:
        result = await sus_patterns_handler.detect(
            content=value,
            ip_address=client_ip,
            context=context,
            correlation_id=correlation_id,
        )

        if not result["is_threat"]:
            return False, ""

        # Build informative trigger message from threats
        if result["threats"]:
            threat = result["threats"][0]
            return True, _build_threat_message(threat)

        return True, "Threat detected"

    except Exception as e:
        # Log error but fall back to basic detection
        logging.error(f"Enhanced detection failed: {e}, falling back to basic check")
        return await _fallback_pattern_check(value)


async def _check_request_component(
    value: str,
    context: str,
    component_name: str,
    client_ip: str,
    correlation_id: str,
) -> tuple[bool, str]:
    """Check a specific request component for threats."""
    detected, trigger = await _check_value_enhanced(
        value, context, client_ip, correlation_id
    )
    if detected:
        message = "Potential attack detected from"
        details = (
            f"{client_ip}: {value[:100]}..."
            if len(value) > 100
            else f"{client_ip}: {value}"
        )
        reason_message = f"Suspicious pattern in {component_name}"
        logging.warning(f"{message} {details} - {reason_message}")
    return detected, trigger


async def detect_penetration_attempt(request: Request) -> tuple[bool, str]:
    """
    Detect potential penetration
    attempts in the request.

    This function checks various
    parts of the request
    (query params, body, path, headers)
    against a list of suspicious
    patterns to identify potential security threats.

    Args:
        request (Request):
            The FastAPI request object to analyze.

    Returns:
        tuple[bool, str]:
            First element is True if a potential attack is detected, False otherwise.
            Second element is trigger information if detected, empty string otherwise.
    """
    import uuid

    # Extract client IP for tracking
    client_ip = "unknown"
    if request.client:
        client_ip = request.client.host

    # Generate correlation ID for this request
    correlation_id = str(uuid.uuid4())

    # Check query params
    for key, value in request.query_params.items():
        detected, trigger = await _check_request_component(
            value,
            f"query_param:{key}",
            f"query param '{key}'",
            client_ip,
            correlation_id,
        )
        if detected:
            return True, f"Query param '{key}': {trigger}"

    # Check path
    detected, trigger = await _check_request_component(
        request.url.path, "url_path", "URL path", client_ip, correlation_id
    )
    if detected:
        return True, f"URL path: {trigger}"

    # Check headers
    excluded_headers = {
        "host",
        "user-agent",
        "accept",
        "accept-encoding",
        "connection",
        "origin",
        "referer",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "sec-ch-ua",
        "sec-ch-ua-mobile",
        "sec-ch-ua-platform",
    }
    for key, value in request.headers.items():
        if key.lower() not in excluded_headers:
            detected, trigger = await _check_request_component(
                value, f"header:{key}", f"header '{key}'", client_ip, correlation_id
            )
            if detected:
                return True, f"Header '{key}': {trigger}"

    # Check body
    try:
        body = (await request.body()).decode()
        detected, trigger = await _check_request_component(
            body, "request_body", "request body", client_ip, correlation_id
        )
        if detected:
            return True, f"Request body: {trigger}"
    except Exception:
        pass

    return False, ""
