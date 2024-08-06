# fastapi_guard/utils.py
import aiohttp
from config.sus_patterns import SusPatterns
from fastapi import Request
from guard.models import SecurityConfig
import logging
import re
from typing import Dict, Any



logging.basicConfig(
    filename='requests_digest.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
logger = logging.getLogger(__name__)



async def is_user_agent_allowed(user_agent: str, config: SecurityConfig) -> bool:
    for pattern in config.blocked_user_agents:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return False
    return True



async def get_ip_country(ip: str) -> str:
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://ipinfo.io/{ip}/country") as response:
            return (await response.text()).strip()



async def is_ip_allowed(ip: str, config: SecurityConfig) -> bool:
    if ip in config.blacklist:
        return False
    if isinstance(config.whitelist, list) and config.whitelist:
        if ip in config.whitelist:
            return True
        else:
            return False
    if config.blocked_countries:
        country = await get_ip_country(ip)
        if country in config.blocked_countries:
            return False
    return True



async def log_request(request: Request) -> None:
    client_ip = request.client.host
    method = request.method
    url = str(request.url)
    headers: Dict[str, Any] = dict(request.headers)
    logger.info(f"Request from {client_ip}: {method} {url} - Headers: {headers}")



async def log_suspicious_activity(request: Request, reason: str):
    client_ip = request.client.host
    method = request.method
    url = str(request.url)
    headers = dict(request.headers)
    logger.warning(f"Suspicious activity detected from {client_ip}: {method} {url} - Reason: {reason} - Headers: {headers}")



async def detect_penetration_attempt(request: Request) -> bool:
    suspicious_patterns = SusPatterns().patterns

    # Query params
    query_params = request.query_params
    for key, value in query_params.items():
        for pattern in suspicious_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Potential attack detected from {request.client.host}: {key}={value}")
                return True

    # Body
    body = await request.body()
    body_str = body.decode('utf-8')
    for pattern in suspicious_patterns:
        if re.search(pattern, body_str, re.IGNORECASE):
            logger.warning(f"Potential attack detected from {request.client.host}: {body_str}")
            return True

    # Path
    path = request.url.path
    for pattern in suspicious_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            logger.warning(f"Potential attack detected from {request.client.host}: {path}")
            return True

    # Headers
    headers = request.headers
    for key, value in headers.items():
        for pattern in suspicious_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"Potential attack detected from {request.client.host}: {key}={value}")
                return True

    return False