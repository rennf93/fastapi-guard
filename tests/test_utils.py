from config.sus_patterns import SusPatterns
from fastapi import Request, FastAPI, status
from fastapi.testclient import TestClient
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.utils import (
    detect_penetration_attempt,
    IPBanManager,
    is_ip_allowed,
    is_user_agent_allowed,
    log_request,
    log_suspicious_activity,
    setup_custom_logging
)
import logging
import pytest
import time
import os



@pytest.fixture
def security_config():
    """
    Fixture to create a SecurityConfig object for testing.

    Returns:
        SecurityConfig: A configured SecurityConfig object.
    """
    return SecurityConfig(
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_countries=["CN"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests"
        }
    )



# Utility Function Tests
@pytest.mark.asyncio
async def test_ip_ban_manager():
    """
    Test the IPBanManager.
    """
    manager = IPBanManager()
    ip = "192.168.1.1"

    assert await manager.is_ip_banned(ip) == False

    await manager.ban_ip(ip, 1)
    assert await manager.is_ip_banned(ip) == True

    time.sleep(1.1)
    assert await manager.is_ip_banned(ip) == False



@pytest.mark.asyncio
async def test_custom_logging(security_config, tmp_path):
    """
    Test the custom logging.
    """
    log_file = tmp_path / "test_log.log"
    logger = setup_custom_logging(str(log_file))

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"user-agent", b"test-agent")],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)

    await log_request(request, logger)
    await log_suspicious_activity(request, "Test suspicious activity", logger)

    with open(log_file, "r") as f:
        log_content = f.read()
        assert "Request from 127.0.0.1: GET /" in log_content
        assert "Test suspicious activity" in log_content



@pytest.mark.asyncio
async def test_automatic_ip_ban():
    """
    Test the automatic IP banning.
    """
    app = FastAPI()
    config = SecurityConfig(auto_ban_threshold=3, auto_ban_duration=300)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    client = TestClient(app)

    for _ in range(3):
        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.2"})
        assert response.status_code == status.HTTP_200_OK

    # This should trigger the automatic ban
    response = client.get("/", headers={"X-Forwarded-For": "192.168.1.2"})
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.text == "IP address banned"

    # Verify that the IP is still banned
    response = client.get("/", headers={"X-Forwarded-For": "192.168.1.2"})
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.text == "IP address banned"



@pytest.mark.asyncio
async def test_custom_error_responses():
    """
    Test the custom error responses.
    """
    app = FastAPI()
    config = SecurityConfig(
        blacklist=["192.168.1.3"],
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests"
        },
        rate_limit=5,
        auto_ban_threshold=10
    )
    app.add_middleware(SecurityMiddleware, config=config, rate_limit=5, rate_limit_window=1)

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    client = TestClient(app)

    # Test blacklisted IP
    response = client.get("/", headers={"X-Forwarded-For": "192.168.1.3"})
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.text == "Custom Forbidden"

    # Test rate limiting
    for _ in range(5):
        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
        assert response.status_code == status.HTTP_200_OK

    response = client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert response.text == "Custom Too Many Requests"



@pytest.mark.asyncio
async def test_is_ip_allowed(security_config, mocker):
    """
    Test the is_ip_allowed function with various IP addresses.
    """
    mocker.patch('guard.utils.get_ip_country', return_value='CN')
    assert await is_ip_allowed("127.0.0.1", security_config) == True
    assert await is_ip_allowed("192.168.1.1", security_config) == False
    assert await is_ip_allowed("10.0.0.1", security_config) == False
    assert await is_ip_allowed("8.8.8.8", security_config) == False



@pytest.mark.asyncio
async def test_is_user_agent_allowed(security_config):
    """
    Test the is_user_agent_allowed function with allowed and blocked user agents.
    """
    assert await is_user_agent_allowed("goodbot", security_config) == True
    assert await is_user_agent_allowed("badbot", security_config) == False



@pytest.mark.asyncio
async def test_log_request(caplog):
    """
    Test the log_request function to ensure it logs the request details correctly.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"user-agent", b"test-agent")],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        await log_request(request, logger)

    assert "Request from 127.0.0.1: GET /" in caplog.text
    assert "Headers: {'user-agent': 'test-agent'}" in caplog.text



# Penetration Attempt Detection Tests
@pytest.mark.asyncio
async def test_detect_penetration_attempt():
    """
    Test the detect_penetration_attempt function with a normal request.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == False



@pytest.mark.asyncio
async def test_detect_penetration_attempt_xss():
    """
    Test the detect_penetration_attempt function with an XSS attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"param=<script>alert('xss')</script>",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_sql_injection():
    """
    Test the detect_penetration_attempt function with a SQL injection attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"param=' OR '1'='1",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_directory_traversal():
    """
    Test the detect_penetration_attempt function with a directory traversal attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/../../etc/passwd",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_command_injection():
    """
    Test the detect_penetration_attempt function with a command injection attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"param=; ls -la",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_ssrf():
    """
    Test the detect_penetration_attempt function with an SSRF attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"param=http://169.254.169.254/latest/meta-data/",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_open_redirect():
    """
    Test the detect_penetration_attempt function with an open redirect attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"param=//evil.com",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_crlf_injection():
    """
    Test the detect_penetration_attempt function with a CRLF injection attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"param=%0d%0aSet-Cookie:%20mycookie=myvalue",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_path_manipulation():
    """
    Test the detect_penetration_attempt function with a path manipulation attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/../../../../etc/passwd",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_shell_injection():
    """
    Test the detect_penetration_attempt function with a shell injection attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"param=`rm -rf /`",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_nosql_injection():
    """
    Test the detect_penetration_attempt function with a NoSQL injection attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"param={ '$ne': '' }",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



@pytest.mark.asyncio
async def test_detect_penetration_attempt_json_injection():
    """
    Test the detect_penetration_attempt function with a JSON injection attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b'{"key": "value"}'}

    request = Request(scope={
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-type", b"application/json")],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == False



@pytest.mark.asyncio
async def test_detect_penetration_attempt_http_header_injection():
    """
    Test the detect_penetration_attempt function with an HTTP header injection attempt.
    """
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"X-Forwarded-For", b"127.0.0.1\r\nSet-Cookie: mycookie=myvalue")],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)
    assert await detect_penetration_attempt(request) == True



# Custom Pattern Tests
@pytest.mark.asyncio
async def test_add_pattern():
    """
    Test adding a custom pattern to SusPatterns.
    """
    sus_patterns = SusPatterns()
    new_pattern = r"new_pattern"
    await sus_patterns.add_pattern(new_pattern, custom=True)
    assert new_pattern in sus_patterns.custom_patterns



@pytest.mark.asyncio
async def test_remove_pattern():
    """
    Test removing a custom pattern from SusPatterns.
    """
    sus_patterns = SusPatterns()
    pattern_to_remove = r"new_pattern"
    await sus_patterns.add_pattern(pattern_to_remove, custom=True)
    await sus_patterns.remove_pattern(pattern_to_remove, custom=True)
    assert pattern_to_remove not in sus_patterns.custom_patterns



@pytest.mark.asyncio
async def test_get_all_patterns():
    """
    Test retrieving all patterns (default and custom) from SusPatterns.
    """
    sus_patterns = SusPatterns()
    default_patterns = sus_patterns.patterns
    custom_pattern = r"custom_pattern"
    await sus_patterns.add_pattern(custom_pattern, custom=True)
    all_patterns = await sus_patterns.get_all_patterns()
    assert custom_pattern in all_patterns
    assert all(pattern in all_patterns for pattern in default_patterns)



# Middleware Tests
@pytest.mark.asyncio
async def test_rate_limiting():
    """
    Test the rate limiting functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig()
    app.add_middleware(SecurityMiddleware, config=config, rate_limit=2, rate_limit_window=1)

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK

    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK

    response = client.get("/")
    assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    time.sleep(1)

    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK



@pytest.mark.asyncio
async def test_ip_whitelist_blacklist(mocker):
    """
    Test the IP whitelist and blacklist functionality of the SecurityMiddleware.
    """
    mocker.patch('guard.utils.get_ip_country', return_value='CN')
    mocker.patch('guard.utils.is_ip_allowed', side_effect=[True, False, False, False])
    app = FastAPI()
    config = SecurityConfig(whitelist=["127.0.0.1"], blacklist=["192.168.1.1"], blocked_countries=["CN"])
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    client = TestClient(app)

    response = client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
    assert response.status_code == status.HTTP_200_OK

    response = client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client.get("/", headers={"X-Forwarded-For": "10.0.0.1"})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client.get("/", headers={"X-Forwarded-For": "8.8.8.8"})
    assert response.status_code == status.HTTP_403_FORBIDDEN



@pytest.mark.asyncio
async def test_user_agent_filtering():
    """
    Test the user agent filtering functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(blocked_user_agents=[r"badbot"])
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    client = TestClient(app)

    response = client.get("/", headers={"User-Agent": "goodbot"})
    assert response.status_code == status.HTTP_200_OK

    response = client.get("/", headers={"User-Agent": "badbot"})
    assert response.status_code == status.HTTP_403_FORBIDDEN