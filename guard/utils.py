# fastapi_guard/utils.py
import logging
import re
from fastapi import Request
from guard.models import SecurityConfig
from config.sus_patterns import SusPatterns



logging.basicConfig(
    filename='requests_digest.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
logger = logging.getLogger(__name__)



def is_ip_allowed(
    ip: str,
    config: SecurityConfig
) -> bool:
    if ip in config.blacklist:
        return False
    if config.whitelist and ip not in config.whitelist:
        return False
    return True



def log_request(request: Request):
    client_ip = request.client.host
    method = request.method
    url = str(request.url)
    headers = dict(request.headers)
    logger.info(f"Request from {client_ip}: {method} {url} - Headers: {headers}")



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