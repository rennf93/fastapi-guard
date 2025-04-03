# fastapi_guard/utils.py
import logging
import re
from ipaddress import IPv4Address, ip_network
from typing import Any

from fastapi import Request

from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ipinfo_handler import IPInfoManager
from guard.handlers.suspatterns_handler import sus_patterns_handler
from guard.models import SecurityConfig


async def setup_custom_logging(log_file: str) -> logging.Logger:
    """
    Setup custom logging
    for the application.
    """
    logger = logging.getLogger(__name__)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)
    return logger


async def log_request(request: Request, logger: logging.Logger) -> None:
    """
    Log the details of
    an incoming request.

    Args:
        request (Request):
            The FastAPI request object.
        logger (logging.Logger):
            The logger instance to use.
    """
    client_ip = "unknown"
    if request.client:
        client_ip = request.client.host

    method = request.method
    url = str(request.url)
    headers: dict[str, Any] = dict(request.headers)
    message = "Request from"
    details = f"{message} {client_ip}: {method} {url}"
    reason_message = f"Headers: {headers}"
    logger.info(f"{details} - {reason_message}")


async def log_suspicious_activity(
    request: Request, reason: str, logger: logging.Logger
) -> None:
    """
    Log suspicious activity
    detected in a request.

    Args:
        request (Request):
            The FastAPI request object.
        reason (str):
            The reason for flagging
            the activity as suspicious.
        logger (logging.Logger):
            The logger instance to use.
    """
    client_ip = "unknown"
    if request.client:
        client_ip = request.client.host

    method = request.method
    url = str(request.url)
    headers = dict(request.headers)
    message = "Suspicious activity detected from "
    details = f"{message} {client_ip}: {method} {url}"
    reason_message = f"Reason: {reason} - Headers: {headers}"
    logger.warning(f"{details} - {reason_message}")


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
    request: str | Request, config: SecurityConfig, ipinfo_db: IPInfoManager
) -> bool:
    """
    Check if IP is from a blocked country
    or in the whitelist.

    Args:
        request (Union[str, Request]):
            The FastAPI request object or IP string.
        config (SecurityConfig):
            The security configuration object.
        ipinfo_db (IPInfoManager):
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

    if not ipinfo_db.reader:
        await ipinfo_db.initialize()

    ip = (
        request
        if isinstance(request, str)
        else (request.client.host if request.client else "unknown")
    )
    country = ipinfo_db.get_country(ip)

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
    ip: str, config: SecurityConfig, ipinfo_db: IPInfoManager | None = None
) -> bool:
    """
    Check if the IP address is allowed
    based on the security configuration.

    Args:
        ip (str):
            The IP address to check.
        config (SecurityConfig):
            The security configuration object.
        ipinfo_db (Optional[IPInfoManager]):
            The IPInfo database handler.

    Returns:
        bool:
            True if the IP is allowed, False otherwise.
    """
    try:
        ip_addr = IPv4Address(ip)

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
        if config.blocked_countries and ipinfo_db:
            country = await check_ip_country(ip, config, ipinfo_db)
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


async def detect_penetration_attempt(request: Request) -> bool:
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
        bool:
            True if a potential attack is
            detected, False otherwise.
    """

    suspicious_patterns = await sus_patterns_handler.get_all_compiled_patterns()

    async def check_value(value: str) -> bool:
        try:
            import json

            data = json.loads(value)
            if isinstance(data, dict):
                return any(
                    pattern.search(str(v))
                    for v in data.values()
                    if isinstance(v, str)
                    for pattern in suspicious_patterns
                )
        except json.JSONDecodeError:
            return any(pattern.search(value) for pattern in suspicious_patterns)
        return False

    # Query params
    for value in request.query_params.values():
        if await check_value(value):
            message = "Potential attack detected from"
            client_ip = "unknown"
            if request.client:
                client_ip = request.client.host
            details = f"{client_ip}: {value}"
            reason_message = "Suspicious pattern: query param"
            logging.warning(f"{message} {details} - {reason_message}")
            return True

    # Path
    if await check_value(request.url.path):
        message = "Potential attack detected from"
        client_ip = "unknown"
        if request.client:
            client_ip = request.client.host
        details = f"{client_ip}: {request.url.path}"
        reason_message = "Suspicious pattern: path"
        logging.warning(f"{message} {details} - {reason_message}")
        return True

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
    }
    for key, value in request.headers.items():
        if key.lower() not in excluded_headers and await check_value(value):
            message = "Potential attack detected from"
            client_ip = "unknown"
            if request.client:
                client_ip = request.client.host
            details = f"{client_ip}: {key}={value}"
            reason_message = "Suspicious pattern: header"
            logging.warning(f"{message} {details} - {reason_message}")
            return True

    # Body
    try:
        body = (await request.body()).decode()
        if await check_value(body):
            message = "Potential attack detected from"
            client_ip = "unknown"
            if request.client:
                client_ip = request.client.host
            details = f"{client_ip}: {body}"
            reason_message = "Suspicious pattern: body"
            logging.warning(f"{message} {details} - {reason_message}")
            return True
    except Exception:
        pass

    return False
