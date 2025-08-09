# fastapi_guard/utils.py
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
    # Allow propagation so tests can capture logs
    # Users won't see duplicates because we use a specific namespace

    return logger


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

    # Check if there's an X-Forwarded-For header from an untrusted source
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for and not config.trusted_proxies:
        logging.warning(
            f"Potential IP spoof attempt: X-Forwarded-For header "
            f"({forwarded_for}) received from untrusted IP {connecting_ip}"
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
        return connecting_ip

    # Don't trust X-Forwarded-For
    if not config.trusted_proxies:
        return connecting_ip

    # Check trusted proxy
    try:
        connecting_ip_obj = ip_address(connecting_ip)
        is_trusted = False

        for proxy in config.trusted_proxies:
            if "/" in proxy:  # CIDR notation
                if connecting_ip_obj in ip_network(proxy, strict=False):
                    is_trusted = True
                    break
            elif connecting_ip == proxy:  # Direct IP match
                is_trusted = True
                break

        if not is_trusted and forwarded_for:
            logging.warning(
                f"Potential IP spoof attempt: X-Forwarded-For header "
                f"({forwarded_for}) received from untrusted IP {connecting_ip}"
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

        if not is_trusted:
            return connecting_ip

        # Process X-Forwarded-For
        if forwarded_for:
            # Parse the header
            ips = [ip.strip() for ip in forwarded_for.split(",")]

            if len(ips) >= config.trusted_proxy_depth:
                client_ip_index = 0
                return ips[client_ip_index]

        # Fall back to connecting IP
        return connecting_ip

    except (ValueError, IndexError) as e:
        logging.warning(f"Error processing client IP: {str(e)}")
        return connecting_ip


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

    client_ip = "unknown"
    if request.client:
        client_ip = request.client.host

    method = request.method
    url = str(request.url)
    headers = dict(request.headers)

    if log_type == "request":
        message = "Request from"
        details = f"{message} {client_ip}: {method} {url}"
        reason_message = f"Headers: {headers}"
    elif log_type == "suspicious":
        if passive_mode:
            message = "[PASSIVE MODE] Penetration attempt detected from"
            details = f"{message} {client_ip}: {method} {url}"

            trigger_message = f"Trigger: {trigger_info}" if trigger_info else ""
            reason_message = f"Headers: {headers}"
            if trigger_message:
                reason_message = f"{trigger_message} - {reason_message}"
        else:
            message = "Suspicious activity detected from"
            details = f"{message} {client_ip}: {method} {url}"
            reason_message = f"Reason: {reason} - Headers: {headers}"
    else:
        message = f"{log_type.capitalize()} from"
        details = f"{message} {client_ip}: {method} {url}"
        reason_message = f"Details: {reason} - Headers: {headers}"

    msg = f"{details} - {reason_message}"

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
    if not config.blocked_countries and not config.whitelist_countries:
        message = "No countries blocked or whitelisted"
        host = ""
        if isinstance(request, str):
            host = request
        elif request.client:
            host = request.client.host
        details = f"{host}"
        reason_message = "No countries blocked or whitelisted"
        logging.warning(f"{message} {details} - {reason_message}")
        return False

    if not geo_ip_handler.is_initialized:
        await geo_ip_handler.initialize()

    ip = (
        request
        if isinstance(request, str)
        else (request.client.host if request.client else "unknown")
    )
    country = geo_ip_handler.get_country(ip)

    if not country:
        message = "IP not geolocated"
        details = f"{ip}"
        reason_message = "IP geolocation failed"
        logging.warning(f"{message} {details} - {reason_message}")
        return False

    if config.whitelist_countries and country in config.whitelist_countries:
        message = "IP from whitelisted country"
        details = f"{ip} - {country}"
        reason_message = "IP from whitelisted country"
        logging.info(f"{message} {details} - {reason_message}")
        return False

    if config.blocked_countries and country in config.blocked_countries:
        message = "IP from blocked country"
        details = f"{ip} - {country}"
        reason_message = "IP from blocked country"
        logging.warning(f"{message} {details} - {reason_message}")
        return True

    message = "IP not from blocked or whitelisted country"
    details = f"{ip} - {country}"
    reason_message = "IP not from blocked or whitelisted country"
    logging.info(f"{message} {details} - {reason_message}")
    return False


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

        # Blacklist
        if config.blacklist:
            for blocked in config.blacklist:
                if "/" in blocked:  # CIDR
                    if ip_addr in ip_network(blocked, strict=False):
                        return False
                elif ip == blocked:  # Direct match
                    return False

        # Whitelist
        if config.whitelist:
            for allowed in config.whitelist:
                if "/" in allowed:  # CIDR
                    if ip_addr in ip_network(allowed, strict=False):
                        return True
                elif ip == allowed:  # Direct match
                    return True
            return False  # If whitelist exists but IP not in it

        # Blocked countries
        if config.blocked_countries and geo_ip_handler:
            country = await check_ip_country(ip, config, geo_ip_handler)
            if country:
                return False

        # Cloud providers
        if config.block_cloud_providers and cloud_handler.is_cloud_ip(
            ip, config.block_cloud_providers
        ):
            return False
        return True
    except ValueError:
        return False  # Invalid IP
    except Exception as e:
        logging.error(f"Error checking IP {ip}: {str(e)}")
        return True


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

    # Extract client IP for tracking
    client_ip = "unknown"
    if request.client:
        client_ip = request.client.host

    # Generate correlation ID for this request
    import uuid

    correlation_id = str(uuid.uuid4())

    async def check_value(value: str, context: str) -> tuple[bool, str]:
        """
        Check a value using the enhanced detection engine.

        Args:
            value: The value to check
            context: Context information (e.g., "query_param:id")

        Returns:
            Tuple of (detected, trigger_info)
        """
        # First check if value looks like JSON
        try:
            import json

            data = json.loads(value)
            if isinstance(data, dict):
                # Check each JSON field
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
                                    return (
                                        True,
                                        f"JSON field '{k}' matched pattern '{pattern}'",
                                    )
                                else:
                                    threat_type = threat["type"]
                                    return (
                                        True,
                                        f"JSON field '{k}' contains: {threat_type}",
                                    )
                            return True, f"JSON field '{k}' contains threat"
                return False, ""
        except json.JSONDecodeError:
            # Not JSON, check as plain string
            pass

        # Use enhanced detection engine
        try:
            # Use the new detect() method for richer results
            result = await sus_patterns_handler.detect(
                content=value,
                ip_address=client_ip,
                context=context,
                correlation_id=correlation_id,
            )

            if result["is_threat"]:
                # Build informative trigger message from threats
                if result["threats"]:
                    threat = result["threats"][0]
                    if threat["type"] == "regex":
                        return True, f"Value matched pattern '{threat['pattern']}'"
                    elif threat["type"] == "semantic":
                        attack_type = threat.get("attack_type", "suspicious")
                        score = threat.get("probability", threat.get("threat_score", 0))
                        msg = f"Semantic attack: {attack_type} (score: {score:.2f})"
                        return True, msg
                return True, "Threat detected"
            return False, ""
        except Exception as e:
            # Log error but fall back to basic detection
            logging.error(
                f"Enhanced detection failed: {e}, falling back to basic check"
            )
            # Fall back to basic pattern check
            for pattern in await sus_patterns_handler.get_all_compiled_patterns():
                try:
                    if pattern.search(value):
                        return True, "Value matched pattern (fallback)"
                except Exception:
                    continue
            return False, ""

    # Query params
    for key, value in request.query_params.items():
        detected, trigger = await check_value(value, f"query_param:{key}")
        if detected:
            message = "Potential attack detected from"
            details = f"{client_ip}: {value}"
            reason_message = f"Suspicious pattern in query param '{key}'"
            logging.warning(f"{message} {details} - {reason_message}")
            return True, f"Query param '{key}': {trigger}"

    # Path
    detected, trigger = await check_value(request.url.path, "url_path")
    if detected:
        message = "Potential attack detected from"
        details = f"{client_ip}: {request.url.path}"
        reason_message = "Suspicious pattern: path"
        logging.warning(f"{message} {details} - {reason_message}")
        return True, f"URL path: {trigger}"

    # Headers
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
            detected, trigger = await check_value(value, f"header:{key}")
            if detected:
                message = "Potential attack detected from"
                details = f"{client_ip}: {key}={value}"
                reason_message = "Suspicious pattern: header"
                logging.warning(f"{message} {details} - {reason_message}")
                return True, f"Header '{key}': {trigger}"

    # Body
    try:
        body = (await request.body()).decode()
        detected, trigger = await check_value(body, "request_body")
        if detected:
            message = "Potential attack detected from"
            if len(body) > 100:
                details = f"{client_ip}: {body[:100]}..."
            else:
                details = f"{client_ip}: {body}"
            reason_message = "Suspicious pattern: body"
            logging.warning(f"{message} {details} - {reason_message}")
            return True, f"Request body: {trigger}"
    except Exception:
        pass

    return False, ""
