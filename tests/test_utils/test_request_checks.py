from fastapi import Request
from guard.utils import cloud_ip_ranges
from guard.models import SecurityConfig
from guard.utils import (
    is_ip_allowed,
    is_user_agent_allowed,
    detect_penetration_attempt,
    get_ip_country,
)
import pytest


@pytest.mark.asyncio
async def test_is_ip_allowed(security_config, mocker):
    """
    Test the is_ip_allowed function with various IP addresses.
    """
    mocker.patch("guard.utils.get_ip_country", return_value="CN")

    # Test with default config
    assert await is_ip_allowed("127.0.0.1", security_config) == True
    assert await is_ip_allowed("192.168.1.1", security_config) == False

    # Test with empty whitelist and blacklist
    empty_config = SecurityConfig(whitelist=[], blacklist=[])
    assert await is_ip_allowed("127.0.0.1", empty_config) == True
    assert await is_ip_allowed("192.168.1.1", empty_config) == True

    # Test with only whitelist
    whitelist_config = SecurityConfig(whitelist=["127.0.0.1"])
    assert await is_ip_allowed("127.0.0.1", whitelist_config) == True
    assert await is_ip_allowed("192.168.1.1", whitelist_config) == False

    # Test with only blacklist
    blacklist_config = SecurityConfig(blacklist=["192.168.1.1"])
    assert await is_ip_allowed("127.0.0.1", blacklist_config) == True
    assert await is_ip_allowed("192.168.1.1", blacklist_config) == False


@pytest.mark.asyncio
async def test_is_user_agent_allowed(security_config):
    """
    Test the is_user_agent_allowed function with allowed and blocked user agents.
    """
    assert await is_user_agent_allowed("goodbot", security_config) == True
    assert await is_user_agent_allowed("badbot", security_config) == False


@pytest.mark.asyncio
async def test_detect_penetration_attempt():
    """
    Test the detect_penetration_attempt
    function with a normal request.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == False


@pytest.mark.asyncio
async def test_detect_penetration_attempt_xss():
    """
    Test the detect_penetration_attempt
    function with an XSS attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"param=<script>alert('xss')</script>",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_sql_injection():
    """
    Test the detect_penetration_attempt
    function with a SQL injection attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"param=' OR '1'='1",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_directory_traversal():
    """
    Test the detect_penetration_attempt
    function with a directory traversal attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/../../etc/passwd",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_command_injection():
    """
    Test the detect_penetration_attempt
    function with a command injection attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"param=; ls -la",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_ssrf():
    """
    Test the detect_penetration_attempt
    function with an SSRF attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"param=http://169.254.169.254/latest/meta-data/",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_open_redirect():
    """
    Test the detect_penetration_attempt
    function with an open redirect attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"param=//evil.com",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_crlf_injection():
    """
    Test the detect_penetration_attempt
    function with a CRLF injection attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"param=%0d%0aSet-Cookie:%20mycookie=myvalue",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_path_manipulation():
    """
    Test the detect_penetration_attempt
    function with a path manipulation attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/../../../../etc/passwd",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_shell_injection():
    """
    Test the detect_penetration_attempt
    function with a shell injection attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"param=`rm -rf /`",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_nosql_injection():
    """
    Test the detect_penetration_attempt
    function with a NoSQL injection attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"param={ '$ne': '' }",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_detect_penetration_attempt_json_injection():
    """
    Test the detect_penetration_attempt
    function with a JSON injection attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b'{"key": "value"}'}

    request = Request(
        scope={
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [(b"content-type", b"application/json")],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == False


@pytest.mark.asyncio
async def test_detect_penetration_attempt_http_header_injection():
    """
    Test the detect_penetration_attempt
    function with an HTTP header injection attempt.
    """

    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [
                (b"X-Forwarded-For", b"127.0.0.1\r\nSet-Cookie: mycookie=myvalue")
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True


@pytest.mark.asyncio
async def test_get_ip_country(mocker):
    """
    Test the get_ip_country function.
    """
    mock_ip2location = mocker.Mock()
    mock_ip2location.get_country_short.return_value = "US"

    mocker.patch("guard.utils.get_ip2location_database", return_value=mock_ip2location)

    config = SecurityConfig(use_ip2location=True)
    country = await get_ip_country("1.1.1.1", config)
    assert country == "US"

    mock_ip2location.get_country_short.return_value = ""
    country = await get_ip_country("0.0.0.0", config)
    assert country == ""

    # Test fallback to ipinfo.io
    config = SecurityConfig(use_ip2location=False, use_ipinfo_fallback=True)
    mock_response = mocker.Mock()
    mock_response.status = 200
    mock_response.json.return_value = {"country": "CA"}
    mock_session = mocker.AsyncMock()
    mock_session.get.return_value.__aenter__.return_value = mock_response
    mocker.patch("aiohttp.ClientSession", return_value=mock_session)

    country = await get_ip_country("2.2.2.2", config)
    assert country == ""


@pytest.mark.asyncio
async def test_is_ip_allowed_cloud_providers(security_config, mocker):
    """
    Test the is_ip_allowed function with cloud provider IP blocking.
    """
    mocker.patch("guard.utils.get_ip_country", return_value="US")
    mocker.patch.object(
        cloud_ip_ranges,
        "is_cloud_ip",
        side_effect=lambda ip, providers: ip.startswith("13."),
    )

    config = SecurityConfig(block_cloud_providers={"AWS"})

    assert await is_ip_allowed("127.0.0.1", config) == True
    assert await is_ip_allowed("13.59.255.255", config) == False  # AWS IP
    assert await is_ip_allowed("8.8.8.8", config) == True  # Non-cloud IP
