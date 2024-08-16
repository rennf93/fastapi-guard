import asyncio
from config.sus_patterns import SusPatterns
from fastapi import Request, FastAPI, status, Response
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.utils import (
    detect_penetration_attempt,
    get_ip_country,
    IPBanManager,
    is_ip_allowed,
    is_user_agent_allowed,
    log_request,
    log_suspicious_activity,
    setup_custom_logging,
    reset_global_state
)
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
import logging
import pytest



@pytest.fixture(autouse=True)
async def reset_state():
    await reset_global_state()
    SusPatterns._instance = None
    yield



@pytest.fixture
def security_config():
    """
    Fixture to create a
    SecurityConfig object for testing.

    Returns:
        SecurityConfig:
            A configured SecurityConfig object.
    """
    return SecurityConfig(
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_countries=["CN"],
        blocked_user_agents=[
            r"badbot"
        ],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests"
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600
    )



@pytest.fixture
async def security_middleware():
    config = SecurityConfig(
        whitelist=[],
        blacklist=[],
        auto_ban_threshold=10,
        auto_ban_duration=300
    )
    middleware = SecurityMiddleware(
        app=None,
        config=config
    )
    await middleware.setup_logger()
    yield middleware
    await middleware.reset()



# Utility Function Tests
@pytest.mark.asyncio
async def test_ip_ban_manager(reset_state):
    """
    Test the IPBanManager.
    """
    manager = IPBanManager()
    ip = "192.168.1.1"

    assert await manager.is_ip_banned(ip) == False

    await manager.ban_ip(ip, 1)
    assert await manager.is_ip_banned(ip) == True

    await asyncio.sleep(1.1)
    assert await manager.is_ip_banned(ip) == False



@pytest.mark.asyncio
async def test_custom_logging(
    reset_state,
    security_config,
    tmp_path
):
    """
    Test the custom logging.
    """
    log_file = tmp_path / "test_log.log"
    logger = await setup_custom_logging(
        str(log_file)
    )

    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (
                b"user-agent",
                b"test-agent"
            )
        ],
        "query_string": b"",
        "client": (
            "127.0.0.1",
            12345
        ),
    }, receive=receive)

    await log_request(
        request,
        logger
    )
    await log_suspicious_activity(
        request,
        "Test suspicious activity",
        logger
    )

    with open(log_file, "r") as f:
        log_content = f.read()
        assert "Request from 127.0.0.1: GET /" in log_content
        assert "Test suspicious activity" in log_content



@pytest.mark.asyncio
async def test_automatic_ip_ban(reset_state):
    """
    Test the automatic IP banning.
    """
    app = FastAPI()
    config = SecurityConfig(
        auto_ban_threshold=3,
        auto_ban_duration=300
    )
    app.add_middleware(
        SecurityMiddleware,
        config=config
    )

    @app.get("/")
    async def read_root():
        return {
            "message": "Hello World"
        }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        for _ in range(config.auto_ban_threshold):
            response = await client.get(
                "/",
                headers={
                    "X-Forwarded-For": "192.168.1.2"
                }
            )
            assert response.status_code == status.HTTP_200_OK

        # This should trigger the automatic ban
        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "192.168.1.2"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Ensure the IP remains banned
        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "192.168.1.2"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Ensure other IPs are not affected
        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "192.168.1.3"
                }
        )
        assert response.status_code == status.HTTP_200_OK



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
    app.add_middleware(
        SecurityMiddleware,
        config=config,
        rate_limit=5,
        rate_limit_window=1
    )

    @app.get("/")
    async def read_root():
        return {
            "message": "Hello World"
        }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # Test blacklisted IP
        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "192.168.1.3"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.text == "Custom Forbidden"

        # Test rate limiting
        for _ in range(5):
            response = await client.get(
                "/",
                headers={
                    "X-Forwarded-For": "192.168.1.4"
                }
            )
            assert response.status_code == status.HTTP_200_OK

        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "192.168.1.4"
            }
        )
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert response.text == "Custom Too Many Requests"



@pytest.mark.asyncio
async def test_is_ip_allowed(
    security_config,
    mocker
):
    """
    Test the is_ip_allowed function
    with various IP addresses.
    """
    mocker.patch(
        'guard.utils.get_ip_country',
        return_value='CN'
    )

    # Test with default config
    assert await is_ip_allowed(
        "127.0.0.1",
        security_config
    ) == True
    assert await is_ip_allowed(
        "192.168.1.1",
        security_config
    ) == False

    # Test with empty whitelist and blacklist
    empty_config = SecurityConfig(
        whitelist=[],
        blacklist=[]
    )
    assert await is_ip_allowed(
        "127.0.0.1",
        empty_config
    ) == True
    assert await is_ip_allowed(
        "192.168.1.1",
    empty_config
    ) == True

    # Test with only whitelist
    whitelist_config = SecurityConfig(
        whitelist=["127.0.0.1"]
    )
    assert await is_ip_allowed(
        "127.0.0.1",
        whitelist_config
    ) == True
    assert await is_ip_allowed(
        "192.168.1.1",
        whitelist_config
    ) == False

    # Test with only blacklist
    blacklist_config = SecurityConfig(
        blacklist=["192.168.1.1"]
    )
    assert await is_ip_allowed(
        "127.0.0.1",
        blacklist_config
    ) == True
    assert await is_ip_allowed(
        "192.168.1.1",
        blacklist_config
    ) == False



@pytest.mark.asyncio
async def test_is_user_agent_allowed(security_config):
    """
    Test the is_user_agent_allowed function
    with allowed and blocked user agents.
    """
    assert await is_user_agent_allowed(
        "goodbot",
        security_config
    ) == True
    assert await is_user_agent_allowed(
        "badbot",
        security_config
    ) == False



@pytest.mark.asyncio
async def test_log_request(caplog):
    """
    Test the log_request function to ensure
    it logs the request details correctly.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (
                b"user-agent",
                b"test-agent"
            )
        ],
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
    Test the detect_penetration_attempt
    function with a normal request.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with an XSS attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with a SQL injection attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with a directory traversal attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with a command injection attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with an SSRF attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with an open redirect attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with a CRLF injection attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with a path manipulation attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with a shell injection attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with a NoSQL injection attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

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
    Test the detect_penetration_attempt
    function with a JSON injection attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b'{"key": "value"}'
        }

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
    Test the detect_penetration_attempt
    function with an HTTP header injection attempt.
    """
    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (
                b"X-Forwarded-For",
                b"127.0.0.1\r\nSet-Cookie: mycookie=myvalue"
            )
        ],
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
    await sus_patterns.add_pattern(
        new_pattern,
        custom=True
    )
    assert new_pattern in sus_patterns.custom_patterns
    all_patterns = await sus_patterns.get_all_patterns()
    assert new_pattern in all_patterns



@pytest.mark.asyncio
async def test_remove_pattern():
    """
    Test removing a custom pattern from SusPatterns.
    """
    sus_patterns = SusPatterns()
    pattern_to_remove = r"new_pattern"
    await sus_patterns.add_pattern(
        pattern_to_remove,
        custom=True
    )
    await sus_patterns.remove_pattern(
        pattern_to_remove,
        custom=True
    )
    assert pattern_to_remove not in sus_patterns.custom_patterns



@pytest.mark.asyncio
async def test_get_all_patterns():
    """
    Test retrieving all patterns
    (default and custom) from SusPatterns.
    """
    sus_patterns = SusPatterns()
    default_patterns = sus_patterns.patterns
    custom_pattern = r"custom_pattern"
    await sus_patterns.add_pattern(
        custom_pattern,
        custom=True
    )
    all_patterns = await sus_patterns.get_all_patterns()
    assert custom_pattern in all_patterns
    assert all(
        pattern in all_patterns
        for pattern in default_patterns
    )



# Middleware Tests
@pytest.mark.asyncio
async def test_rate_limiting():
    """
    Test the rate limiting functionality
    of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig()
    app.add_middleware(
        SecurityMiddleware,
        config=config,
        rate_limit=2,
        rate_limit_window=1
    )

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

        response = await client.get("/")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        await asyncio.sleep(1)

        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK



@pytest.mark.asyncio
async def test_ip_whitelist_blacklist():
    app = FastAPI()
    config = SecurityConfig(
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"]
    )
    app.add_middleware(
        SecurityMiddleware,
        config=config
    )

    @app.get("/")
    async def read_root():
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "127.0.0.1"
            }
        )
        assert response.status_code == status.HTTP_200_OK

        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "192.168.1.1"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "10.0.0.1"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN



@pytest.mark.asyncio
async def test_user_agent_filtering():
    """
    Test the user agent filtering
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(
        blocked_user_agents=[
            r"badbot"
        ]
    )
    app.add_middleware(
        SecurityMiddleware,
        config=config
    )

    @app.get("/")
    async def read_root():
        return {
            "message": "Hello World"
        }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        response = await client.get(
            "/",
            headers={
                "User-Agent": "goodbot"
            }
        )
        assert response.status_code == status.HTTP_200_OK

        response = await client.get(
            "/",
            headers={
                "User-Agent": "badbot"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN



@pytest.mark.asyncio
async def test_ip_ban_manager_multiple_ips():
    """
    Test the IPBanManager with multiple IPs.
    """
    manager = IPBanManager()
    ip1 = "192.168.1.1"
    ip2 = "192.168.1.2"

    await manager.ban_ip(ip1, 1)
    assert await manager.is_ip_banned(ip1) == True
    assert await manager.is_ip_banned(ip2) == False

    await asyncio.sleep(1.1)
    assert await manager.is_ip_banned(ip1) == False
    assert await manager.is_ip_banned(ip2) == False



@pytest.mark.asyncio
async def test_rate_limiting_multiple_ips(
    reset_state,
    security_middleware
):
    app = FastAPI()
    config = SecurityConfig(
        whitelist=[],
        blacklist=[]
    )
    app.add_middleware(
        SecurityMiddleware,
        config=config,
        rate_limit=2,
        rate_limit_window=1
    )

    @app.get("/")
    async def read_root():
        return {
            "message": "Hello World"
        }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # IP 1
        for i in range(1, 4):
            response = await client.get(
                "/",
                headers={
                    "X-Forwarded-For": "192.168.1.1"
                }
            )
            logging.info(f"IP 1, Request {i}: {response.status_code}")
            assert response.status_code == (
                status.HTTP_200_OK
                if i <= 2
                else status.HTTP_429_TOO_MANY_REQUESTS
            )

        # IP 2
        for i in range(1, 4):
            response = await client.get(
                "/",
                headers={
                    "X-Forwarded-For": "192.168.1.5"
                }
            )
            logging.info(f"IP 2, Request {i}: {response.status_code}")
            assert response.status_code == (
                status.HTTP_200_OK
                if i <= 2
                else status.HTTP_429_TOO_MANY_REQUESTS
            )

        # Ensure IP 1 is still rate limited
        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "192.168.1.1"
            }
        )
        logging.info(f"IP 1, Request 4: {response.status_code}")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS

        # Ensure IP 2 is still rate limited
        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "192.168.1.5"
            }
        )
        logging.info(f"IP 2, Request 4: {response.status_code}")
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS



@pytest.mark.asyncio
async def test_user_agent_filtering_edge_cases():
    """
    Test the user agent filtering
    functionality with edge cases.
    """
    app = FastAPI()
    config = SecurityConfig(
        blocked_user_agents=[
            r"badbot"
        ]
    )
    app.add_middleware(
        SecurityMiddleware,
        config=config
    )

    @app.get("/")
    async def read_root():
        return {
            "message": "Hello World"
        }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # Case insensitive match
        response = await client.get(
            "/",
            headers={
                "User-Agent": "BadBot"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Partial match
        response = await client.get(
            "/",
            headers={
                "User-Agent": "badbot123"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # No match
        response = await client.get(
            "/",
            headers={
                "User-Agent": "goodbot"
            }
        )
        assert response.status_code == status.HTTP_200_OK



@pytest.mark.asyncio
async def test_ip_geolocation(mocker):
    """
    Test the IP geolocation
    functionality with mocked responses.
    """
    mock_response = mocker.Mock()
    mock_response.__aenter__ = mocker.AsyncMock(
        return_value=mock_response
    )
    mock_response.__aexit__ = mocker.AsyncMock(
        return_value=None
    )
    mock_response.text = mocker.AsyncMock(
        return_value="US"
    )

    mocker.patch(
        "aiohttp.ClientSession.get",
        return_value=mock_response
    )

    config = SecurityConfig(
        use_ip2location=True,
        use_ipinfo_fallback=True
    )

    country = await get_ip_country(
        ip="8.8.8.8",
        config=config
    )
    assert country == "US"



@pytest.mark.asyncio
async def test_logging_levels(
    security_config,
    tmp_path
):
    """
    Test the logging functionality
    with different log levels.
    """
    log_file = tmp_path / "test_log.log"
    logger = await setup_custom_logging(
        str(log_file)
    )

    async def receive():
        return {
            "type": "http.request",
            "body": b""
        }

    request = Request(scope={
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [
            (
                b"user-agent",
                b"test-agent"
            )
        ],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
    }, receive=receive)

    logger.setLevel(logging.DEBUG)
    await log_request(
        request,
        logger
    )
    await log_suspicious_activity(
        request,
        "Test suspicious activity",
        logger
    )

    with open(log_file, "r") as f:
        log_content = f.read()
        assert "Request from 127.0.0.1: GET /" in log_content
        assert "Test suspicious activity" in log_content



@pytest.mark.asyncio
async def test_middleware_multiple_configs():
    """
    Test the SecurityMiddleware
    with multiple configurations.
    """
    app = FastAPI()
    config1 = SecurityConfig(
        blocked_user_agents=[
            r"badbot"
        ]
    )
    config2 = SecurityConfig(
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"]
    )

    app.add_middleware(
        SecurityMiddleware,
        config=config1
    )
    app.add_middleware(
        SecurityMiddleware,
        config=config2
    )

    @app.get("/")
    async def read_root():
        return {
            "message": "Hello World"
        }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        # Test user agent filtering
        response = await client.get(
            "/",
            headers={
                "User-Agent": "badbot"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

        # Test IP whitelist/blacklist
        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "127.0.0.1"
            }
        )
        assert response.status_code == status.HTTP_200_OK
        response = await client.get(
            "/",
            headers={
                "X-Forwarded-For": "192.168.1.1"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN



@pytest.mark.asyncio
async def test_https_enforcement():
    """
    Test the HTTPS enforcement
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()
    config = SecurityConfig(enforce_https=True)
    app.add_middleware(
        SecurityMiddleware,
        config=config
    )

    @app.get("/")
    async def read_root():
        return {
            "message": "Hello World"
        }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_301_MOVED_PERMANENTLY
        assert response.headers[
            "location"
        ].startswith("https://")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="https://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK



@pytest.mark.asyncio
async def test_custom_request_check():
    """
    Test the custom request check
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()

    async def custom_check(
        request: Request
    ):
        if request.headers.get(
            "X-Custom-Header"
        ) == "block":
            return Response(
                "Custom block",
                status_code=status.HTTP_403_FORBIDDEN
            )
        return None

    config = SecurityConfig(
        custom_request_check=custom_check
    )
    app.add_middleware(
        SecurityMiddleware,
        config=config
    )

    @app.get("/")
    async def read_root():
        return {
            "message": "Hello World"
        }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        response = await client.get(
            "/",
            headers={
                "X-Custom-Header": "block"
            }
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.text == "Custom block"

        response = await client.get(
            "/",
            headers={
                "X-Custom-Header": "allow"
            }
        )
        assert response.status_code == status.HTTP_200_OK



@pytest.mark.asyncio
async def test_custom_response_modifier():
    """
    Test the custom response modifier
    functionality of the SecurityMiddleware.
    """
    app = FastAPI()

    async def custom_modifier(
        response: Response
    ):
        response.headers[
            "X-Custom-Header"
        ] = "modified"
        return response

    config = SecurityConfig(
        custom_response_modifier=custom_modifier
    )
    app.add_middleware(
        SecurityMiddleware,
        config=config
    )

    @app.get("/")
    async def read_root():
        return {
            "message": "Hello World"
        }

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK
        assert response.headers[
            "X-Custom-Header"
        ] == "modified"



@pytest.mark.asyncio
async def test_cors_configuration():
    app = FastAPI()
    config = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom-Header"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600
    )

    cors_added = SecurityMiddleware.configure_cors(
        app,
        config
    )
    assert cors_added, "CORS middleware was not added"

    client = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    )
    response = await client.options(
        "/",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Custom-Header"
        }
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.headers["access-control-allow-origin"] == "https://example.com"
    assert "GET" in response.headers["access-control-allow-methods"]
    assert "X-Custom-Header" in response.headers["access-control-allow-headers"]

    if "access-control-expose-headers" in response.headers:
        assert "X-Custom-Header" in response.headers["access-control-expose-headers"]
    else:
        logging.warning("Warning: access-control-expose-headers not present in response")

    assert response.headers["access-control-max-age"] == "600"



@pytest.mark.asyncio
async def test_cors_disabled():
    """
    Test that CORS is not configured
    when disabled in SecurityConfig.
    """
    app = FastAPI()
    config = SecurityConfig(enable_cors=False)

    disabled_cors = SecurityMiddleware.configure_cors(
        app,
        config
    )

    assert not disabled_cors, "CORS middleware was added"



@pytest.mark.asyncio
async def test_cors_default_settings():
    """
    Test CORS configuration
    with default settings.
    """
    app = FastAPI()
    config = SecurityConfig(enable_cors=True)

    SecurityMiddleware.configure_cors(
        app,
        config
    )

    # Create a test client
    client = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    )

    # Deafault CORS preflight request
    response = await client.options(
        "/",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Custom-Header"
        }
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.headers["access-control-allow-origin"] == "*"
    assert "GET" in response.headers["access-control-allow-methods"]
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "PUT" in response.headers["access-control-allow-methods"]
    assert "DELETE" in response.headers["access-control-allow-methods"]
    assert response.headers["access-control-allow-headers"] == "X-Custom-Header"
