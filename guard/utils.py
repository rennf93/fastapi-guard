# fastapi_guard/utils.py
from cachetools import TTLCache
from config.ip2.ip2location_config import get_ip2location_database
from config.sus_patterns import SusPatterns
from fastapi import Request
from guard.models import SecurityConfig
import logging
import re
import time
from typing import Dict, Any



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



async def setup_custom_logging(log_file: str):
    """
    Setup custom logging
    for the application.
    """
    logger = logging.getLogger(__name__)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(
        logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
    )
    logger.addHandler(file_handler)
    logger.setLevel(logging.INFO)
    return logger



async def log_request(
    request: Request,
    logger
):
    """
    Log the details of
    an incoming request.

    Args:
        request (Request):
            The FastAPI request object.
    """
    client_ip = request.client.host
    method = request.method
    url = str(request.url)
    headers: Dict[str, Any] = dict(request.headers)
    logger.info(f"Request from {client_ip}: {method} {url} - Headers: {headers}")



async def log_suspicious_activity(
    request: Request,
    reason: str,
    logger
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
    """
    client_ip = request.client.host
    method = request.method
    url = str(request.url)
    headers = dict(request.headers)
    logger.warning(f"Suspicious activity detected from {client_ip}: {method} {url} - Reason: {reason} - Headers: {headers}")



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
        if re.search(
            pattern,
            user_agent,
            re.IGNORECASE
        ):
            return False
    return True



async def get_ip_country(ip: str) -> str:
    """
    Get the country associated with the given IP address using IP2Location database.

    Args:
        ip (str): The IP address to look up.

    Returns:
        str: The country code associated with the IP address.
    """
    ip2location = get_ip2location_database()
    try:
        result = ip2location.get_country_short(ip)
        return result if result != "-" else ""
    except Exception as e:
        logging.error(f"Error getting country for IP {ip}: {str(e)}")
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
    if config.blacklist and ip in config.blacklist:
        return False
    if config.whitelist:
        return ip in config.whitelist
    if config.blocked_countries:
        country = await get_ip_country(ip)
        if country in config.blocked_countries:
            return False
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

    suspicious_patterns = await SusPatterns().get_all_compiled_patterns()

    # Query params
    query_params = request.query_params
    for key, value in query_params.items():
        for pattern in suspicious_patterns:
            if pattern.search(value):
                logging.warning(f"Potential attack detected from {request.client.host}: {key}={value}")
                return True

    # Body
    body = await request.body()
    body_str = body.decode('utf-8')
    for pattern in suspicious_patterns:
        if pattern.search(body_str):
            logging.warning(f"Potential attack detected from {request.client.host}: {body_str}")
            return True

    # Path
    path = request.url.path
    for pattern in suspicious_patterns:
        if pattern.search(path):
            logging.warning(f"Potential attack detected from {request.client.host}: {path}")
            return True

    # Headers
    headers = request.headers
    for key, value in headers.items():
        for pattern in suspicious_patterns:
            if pattern.search(value):
                logging.warning(f"Potential attack detected from {request.client.host}: {key}={value}")
                return True

    return False