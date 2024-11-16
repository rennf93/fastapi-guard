# fastapi_guard/utils.py
import aiohttp
from cachetools import TTLCache
from config.ip2.ip2location_config import get_ip2location_database
from config.sus_patterns import SusPatterns
from fastapi import Request
from guard.cloud_ips import cloud_ip_ranges
from guard.models import SecurityConfig
from ipaddress import (
    IPv4Address,
    ip_network
)
import logging
import re
import time
from typing import (
    Any,
    Dict
)


class IPBanManager:
    """
    A class for managing IP bans.
    """

    def __init__(self):
        """
        Initialize the IPBanManager.
        """
        self.banned_ips = TTLCache(
            maxsize=10000,
            ttl=3600
        )

    async def ban_ip(
        self,
        ip: str,
        duration: int
    ):
        """
        Ban an IP address for
        a specified duration.
        """
        self.banned_ips[ip] = time.time() + duration

    async def is_ip_banned(
        self,
        ip: str
    ) -> bool:
        """
        Check if an IP
        address is banned.
        """
        if ip in self.banned_ips:
            if time.time() > self.banned_ips[ip]:
                del self.banned_ips[ip]
                return False
            return True
        return False

    async def reset(self):
        """
        Reset the banned IPs.
        """
        self.banned_ips.clear()


ip_ban_manager = IPBanManager()


async def reset_global_state():
    """
    Reset all global state.
    """
    global ip_ban_manager
    ip_ban_manager = IPBanManager()


async def setup_custom_logging(
    log_file: str
) -> logging.Logger:
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


async def log_request(
    request: Request,
    logger: logging.Logger
):
    """
    Log the details of
    an incoming request.

    Args:
        request (Request):
            The FastAPI request object.
        logger (logging.Logger):
            The logger instance to use.
    """
    client_ip = request.client.host
    method = request.method
    url = str(request.url)
    headers: Dict[str, Any] = dict(request.headers)
    message = "Request from"
    details = f"{message} {client_ip}: {method} {url}"
    reason_message = f"Headers: {headers}"
    logger.info(f"{details} - {reason_message}")


async def log_suspicious_activity(
    request: Request,
    reason: str,
    logger: logging.Logger
):
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
    client_ip = request.client.host
    method = request.method
    url = str(request.url)
    headers = dict(request.headers)
    message = "Suspicious activity detected from "
    details = f"{message} {client_ip}: {method} {url}"
    reason_message = f"Reason: {reason} - Headers: {headers}"
    logger.warning(f"{details} - {reason_message}")


async def is_user_agent_allowed(
    user_agent: str,
    config: SecurityConfig
) -> bool:
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


async def get_ip_country(
    ip: str,
    config: SecurityConfig
) -> str:
    """
    Get the country associated with the given
    IP address using IP2Location database
    or ipinfo.io as a fallback.

    Args:
        ip (str):
            The IP address to look up.
        config (SecurityConfig):
            The security configuration.

    Returns:
        str:
            The country code associated
            with the IP address.
    """
    if config.use_ip2location:
        ip2location = get_ip2location_database(config)
        if ip2location is not None:
            try:
                result = ip2location.get_country_short(ip)
                if result and result != "-":
                    return result
            except Exception as e:
                type = "IP2Location"
                message = f"Error getting country for IP {ip}"
                reason_message = f"Reason: {str(e)}"
                logging.error(f"{type} - {message} - {reason_message}")

    if config.use_ipinfo_fallback:
        try:
            session = aiohttp.ClientSession()
            try:
                response = await session.get(f"https://ipinfo.io/{ip}/json")
                if response.status == 200:
                    data = await response.json()
                    return data.get("country", "")
            finally:
                await session.close()
        except Exception as e:
            type = "ipinfo.io"
            message = f"Error getting country for IP {ip}"
            reason_message = f"Reason: {str(e)}"
            logging.error(f"{type} - {message} - {reason_message}")

    return ""


async def is_ip_allowed(
    ip: str,
    config: SecurityConfig
) -> bool:
    """
    Check if the IP address is allowed
    based on the security configuration.

    Args:
        ip (str):
            The IP address to check.
        config (SecurityConfig):
            The security configuration object.

    Returns:
        bool:
            True if the IP is allowed, False otherwise.
    """
    try:
        ip_addr = IPv4Address(ip)

        # Blacklist
        if config.blacklist:
            for blocked in config.blacklist:
                if '/' in blocked:  # CIDR
                    if ip_addr in ip_network(blocked, strict=False):
                        return False
                elif ip == blocked:  # Direct match
                    return False

        # Whitelist
        if config.whitelist:
            for allowed in config.whitelist:
                if '/' in allowed:  # CIDR
                    if ip_addr in ip_network(allowed, strict=False):
                        return True
                elif ip == allowed:  # Direct match
                    return True
            return False  # If whitelist exists but IP not in it

        # Blocked countries
        if config.blocked_countries:
            country = await get_ip_country(ip, config)
            if country in config.blocked_countries:
                return False

        # Cloud providers
        if config.block_cloud_providers and cloud_ip_ranges.is_cloud_ip(
            ip, config.block_cloud_providers
        ):
            return False
        return True
    except ValueError:
        return False  # Invalid IP


async def detect_penetration_attempt(
    request: Request
) -> bool:
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

    suspicious_patterns = await SusPatterns().get_all_compiled_patterns()

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
            return any(
                pattern.search(value)
                for pattern in suspicious_patterns
            )
        return False

    # Query params
    for value in request.query_params.values():
        if await check_value(value):
            message = "Potential attack detected from"
            details = f"{request.client.host}: {value}"
            reason_message = "Suspicious pattern: query param"
            logging.warning(f"{message} {details} - {reason_message}")
            return True

    # Path
    if await check_value(request.url.path):
        message = "Potential attack detected from"
        details = f"{request.client.host}: {request.url.path}"
        reason_message = "Suspicious pattern: path"
        logging.warning(f"{message} {details} - {reason_message}")
        return True

    # Headers
    excluded_headers = {
        'host',
        'user-agent',
        'accept',
        'accept-encoding',
        'connection'
    }
    for key, value in request.headers.items():
        if key.lower() not in excluded_headers and await check_value(value):
            message = "Potential attack detected from"
            details = f"{request.client.host}: {key}={value}"
            reason_message = "Suspicious pattern: header"
            logging.warning(f"{message} {details} - {reason_message}")
            return True

    # Body
    try:
        body = (await request.body()).decode()
        if await check_value(body):
            message = "Potential attack detected from"
            details = f"{request.client.host}: {body}"
            reason_message = "Suspicious pattern: body"
            logging.warning(f"{message} {details} - {reason_message}")
            return True
    except Exception:
        pass

    return False
