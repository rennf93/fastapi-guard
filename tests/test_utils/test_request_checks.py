from fastapi import Request
from guard.models import SecurityConfig
from guard.utils import (
    is_ip_allowed,
    is_user_agent_allowed,
    detect_penetration_attempt,
    check_ip_country,
)
from guard.handlers.cloud_handler import cloud_handler
import os
import pytest
from unittest.mock import patch


IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")


@pytest.mark.asyncio
async def test_is_ip_allowed(security_config, mocker):
    """
    Test the is_ip_allowed function with various IP addresses.
    """
    mocker.patch("guard.utils.check_ip_country", return_value=False)

    assert await is_ip_allowed("127.0.0.1", security_config) == True
    assert await is_ip_allowed("192.168.1.1", security_config) == False

    empty_config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        whitelist=[],
        blacklist=[]
    )
    assert await is_ip_allowed("127.0.0.1", empty_config) == True
    assert await is_ip_allowed("192.168.1.1", empty_config) == True

    whitelist_config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        whitelist=["127.0.0.1"]
    )
    assert await is_ip_allowed("127.0.0.1", whitelist_config) == True
    assert await is_ip_allowed("192.168.1.1", whitelist_config) == False

    blacklist_config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        blacklist=["192.168.1.1"]
    )
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
    """Test SQL injection detection."""
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"query=UNION+SELECT+NULL--",
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
            "query_string": b"cmd=|cat+/etc/passwd",
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
    """Test shell injection detection."""
    async def receive():
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"cmd=;ls%20-la%20/",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(request) == True

    legitimate_request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"cmd=echo%20hello",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    assert await detect_penetration_attempt(legitimate_request) == False


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
    """Test JSON content detection."""
    async def receive_malicious():
        return {"type": "http.request", "body": b'''
            {
                "script": "<script>alert(1)</script>",
                "sql": "UNION SELECT * FROM users",
                "cmd": ";cat /etc/passwd",
                "path": "../../../etc/shadow"
            }
        '''}

    request = Request(
        scope={
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", b"150")
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive_malicious,
    )
    assert await detect_penetration_attempt(request) == True

    async def receive_legitimate():
        return {"type": "http.request", "body": b'''
            {
                "user_id": 123,
                "name": "John Doe",
                "email": "john@example.com",
                "preferences": {
                    "theme": "dark",
                    "notifications": true
                }
            }
        '''}

    legitimate_request = Request(
        scope={
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", b"160")
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive_legitimate,
    )
    assert await detect_penetration_attempt(legitimate_request) == False


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
    """Test the get_ip_country function."""
    mock_ipinfo = mocker.patch("guard.handlers.ipinfo_handler.IPInfoManager")
    mock_db = mock_ipinfo.return_value
    mock_db.get_country.return_value = "US"
    mock_db.reader = True  # Mock initialized reader

    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        blocked_countries=["CN"]
    )

    country = await check_ip_country(
        "1.1.1.1",
        config,
        mock_db
    )
    assert country == False  # Not blocked

    mock_db.get_country.return_value = "CN"
    country = await check_ip_country(
        "1.1.1.1",
        config,
        mock_db
    )
    assert country == True  # Blocked


@pytest.mark.asyncio
async def test_is_ip_allowed_cloud_providers(
    security_config,
    mocker
):
    """
    Test the is_ip_allowed function with cloud provider IP blocking.
    """
    mocker.patch(
        "guard.utils.check_ip_country",
        return_value=True
    )
    mocker.patch.object(
        cloud_handler,
        "is_cloud_ip",
        side_effect=lambda ip,
        providers: ip.startswith("13."),
    )

    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        block_cloud_providers={"AWS"}
    )

    assert await is_ip_allowed(
        "127.0.0.1",
        config
    ) == True
    assert await is_ip_allowed(
        "13.59.255.255",
        config
    ) == False
    assert await is_ip_allowed(
        "8.8.8.8",
        config
    ) == True


@pytest.mark.asyncio
async def test_check_ip_country():
    """Test country checking functionality."""
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        blocked_countries=["CN"],
        whitelist_countries=["US"]
    )

    # Mock IPInfoManager
    with patch("guard.handlers.ipinfo_handler.IPInfoManager") as MockIPInfoManager:
        mock_db = MockIPInfoManager.return_value
        mock_db.get_country.return_value = "CN"

        request = Request(
            scope={
                "type": "http",
                "method": "GET",
                "path": "/",
                "headers": [],
                "query_string": b"",
                "client": ("127.0.0.1", 12345),
            },
            receive=lambda: {"type": "http.request"}
        )

        assert await check_ip_country(
            request,
            config,
            mock_db
        ) == True

        mock_db.get_country.return_value = "US"
        assert await check_ip_country(
            request,
            config,
            mock_db
        ) == False


@pytest.mark.asyncio
async def test_whitelisted_country(security_config, mocker, ipinfo_db):
    mocker.patch.object(ipinfo_db, "get_country", return_value="US")
    security_config.whitelist_countries = ["US"]

    assert await check_ip_country("8.8.8.8", security_config, ipinfo_db) is False


@pytest.mark.asyncio
async def test_cloud_provider_blocking(security_config, mocker):
    mocker.patch(
        "guard.utils.cloud_handler.is_cloud_ip",
        return_value=True
    )
    security_config.block_cloud_providers = {"AWS"}

    assert await is_ip_allowed("8.8.8.8", security_config) is False
