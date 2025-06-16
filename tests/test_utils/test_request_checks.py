import logging
import os
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request
from pytest_mock import MockerFixture

from guard.handlers.cloud_handler import cloud_handler
from guard.models import SecurityConfig
from guard.utils import (
    check_ip_country,
    detect_penetration_attempt,
    is_ip_allowed,
    is_user_agent_allowed,
)

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


@pytest.mark.asyncio
async def test_is_ip_allowed(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    """
    Test the is_ip_allowed function with various IP addresses.
    """
    mocker.patch("guard.utils.check_ip_country", return_value=False)

    assert await is_ip_allowed("127.0.0.1", security_config)
    assert not await is_ip_allowed("192.168.1.1", security_config)

    empty_config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, whitelist=[], blacklist=[])
    assert await is_ip_allowed("127.0.0.1", empty_config)
    assert await is_ip_allowed("192.168.1.1", empty_config)

    whitelist_config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, whitelist=["127.0.0.1"]
    )
    assert await is_ip_allowed("127.0.0.1", whitelist_config)
    assert not await is_ip_allowed("192.168.1.1", whitelist_config)

    blacklist_config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, blacklist=["192.168.1.1"]
    )
    assert await is_ip_allowed("127.0.0.1", blacklist_config)
    assert not await is_ip_allowed("192.168.1.1", blacklist_config)


@pytest.mark.asyncio
async def test_is_user_agent_allowed(security_config: SecurityConfig) -> None:
    """
    Test the is_user_agent_allowed function with allowed and blocked user agents.
    """
    assert await is_user_agent_allowed("goodbot", security_config)
    assert not await is_user_agent_allowed("badbot", security_config)


@pytest.mark.asyncio
async def test_detect_penetration_attempt() -> None:
    """
    Test the detect_penetration_attempt
    function with a normal request.
    """

    async def receive() -> dict[str, str | bytes]:
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
    result, _ = await detect_penetration_attempt(request)
    assert not result


@pytest.mark.asyncio
async def test_detect_penetration_attempt_xss() -> None:
    """
    Test the detect_penetration_attempt
    function with an XSS attempt.
    """

    async def receive() -> dict[str, str | bytes]:
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
    result, _ = await detect_penetration_attempt(request)
    assert result
    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_detect_penetration_attempt_sql_injection() -> None:
    """Test SQL injection detection."""

    async def receive() -> dict[str, str | bytes]:
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
    result, _ = await detect_penetration_attempt(request)
    assert result
    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_detect_penetration_attempt_directory_traversal() -> None:
    """
    Test the detect_penetration_attempt
    function with a directory traversal attempt.
    """

    async def receive() -> dict[str, str | bytes]:
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
    result, _ = await detect_penetration_attempt(request)
    assert result
    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_detect_penetration_attempt_command_injection() -> None:
    """
    Test the detect_penetration_attempt
    function with a command injection attempt.
    """

    async def receive() -> dict[str, str | bytes]:
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
    result, _ = await detect_penetration_attempt(request)
    assert result
    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_detect_penetration_attempt_ssrf() -> None:
    """
    Test the detect_penetration_attempt
    function with an SSRF attempt.
    """

    async def receive() -> dict[str, str | bytes]:
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
    assert await detect_penetration_attempt(request)
    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_detect_penetration_attempt_open_redirect() -> None:
    """
    Test the detect_penetration_attempt
    function with an open redirect attempt.
    """

    async def receive() -> dict[str, str | bytes]:
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
    assert await detect_penetration_attempt(request)
    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_detect_penetration_attempt_crlf_injection() -> None:
    """
    Test the detect_penetration_attempt
    function with a CRLF injection attempt.
    """

    async def receive() -> dict[str, str | bytes]:
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
    assert await detect_penetration_attempt(request)
    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_detect_penetration_attempt_path_manipulation() -> None:
    """
    Test the detect_penetration_attempt
    function with a path manipulation attempt.
    """

    async def receive() -> dict[str, str | bytes]:
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
    assert await detect_penetration_attempt(request)
    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_detect_penetration_attempt_shell_injection() -> None:
    """Test shell injection detection."""

    async def receive() -> dict[str, str | bytes]:
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
    result, _ = await detect_penetration_attempt(request)
    assert result

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
    result, _ = await detect_penetration_attempt(legitimate_request)
    assert not result


@pytest.mark.asyncio
async def test_detect_penetration_attempt_nosql_injection() -> None:
    """
    Test the detect_penetration_attempt
    function with a NoSQL injection attempt.
    """

    async def receive() -> dict[str, str | bytes]:
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
    assert await detect_penetration_attempt(request)
    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_detect_penetration_attempt_json_injection() -> None:
    """Test JSON content detection."""

    async def receive_malicious() -> dict[str, str | bytes]:
        return {
            "type": "http.request",
            "body": b"""
            {
                "script": "<script>alert(1)</script>",
                "sql": "UNION SELECT * FROM users",
                "cmd": ";cat /etc/passwd",
                "path": "../../../etc/shadow"
            }
        """,
        }

    request = Request(
        scope={
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", b"150"),
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive_malicious,
    )
    result, _ = await detect_penetration_attempt(request)
    assert result

    async def receive_legitimate() -> dict[str, str | bytes]:
        return {
            "type": "http.request",
            "body": b"""
            {
                "user_id": 123,
                "name": "John Doe",
                "email": "john@example.com",
                "preferences": {
                    "theme": "dark",
                    "notifications": true
                }
            }
        """,
        }

    legitimate_request = Request(
        scope={
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", b"160"),
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive_legitimate,
    )
    result, _ = await detect_penetration_attempt(legitimate_request)
    assert not result


@pytest.mark.asyncio
async def test_detect_penetration_attempt_http_header_injection() -> None:
    """
    Test the detect_penetration_attempt
    function with an HTTP header injection attempt.
    """

    async def receive() -> dict[str, str | bytes]:
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
    result, _ = await detect_penetration_attempt(request)
    assert result

    body = await request.body()
    assert body == b""


@pytest.mark.asyncio
async def test_get_ip_country(mocker: MockerFixture) -> None:
    """Test the get_ip_country function."""
    mock_ipinfo = mocker.patch("guard.handlers.ipinfo_handler.IPInfoManager")
    mock_db = mock_ipinfo.return_value
    mock_db.get_country.return_value = "US"
    mock_db.reader = True

    config = SecurityConfig(ipinfo_token=IPINFO_TOKEN, blocked_countries=["CN"])

    country = await check_ip_country("1.1.1.1", config, mock_db)
    assert not country  # Not blocked

    mock_db.get_country.return_value = "CN"
    country = await check_ip_country("1.1.1.1", config, mock_db)
    assert country  # Blocked


@pytest.mark.asyncio
async def test_is_ip_allowed_cloud_providers(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    """
    Test the is_ip_allowed function with cloud provider IP blocking.
    """
    mocker.patch("guard.utils.check_ip_country", return_value=True)
    mocker.patch.object(
        cloud_handler,
        "is_cloud_ip",
        side_effect=lambda ip, *_: ip.startswith("13."),
    )

    config = SecurityConfig(block_cloud_providers={"AWS"})

    assert await is_ip_allowed("127.0.0.1", config)
    assert not await is_ip_allowed("13.59.255.255", config)
    assert await is_ip_allowed("8.8.8.8", config)


@pytest.mark.asyncio
async def test_check_ip_country() -> None:
    """Test country checking functionality."""
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, blocked_countries=["CN"], whitelist_countries=["US"]
    )

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

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
            receive=receive,
        )

        body = await request.body()
        assert body == b""

        assert await check_ip_country(request, config, mock_db)

        mock_db.get_country.return_value = "US"
        assert not await check_ip_country(request, config, mock_db)


@pytest.mark.asyncio
async def test_whitelisted_country(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    """Test country whitelist functionality"""
    mock_ipinfo = mocker.Mock()
    mock_ipinfo.get_country.return_value = "US"
    mock_ipinfo.reader = True

    security_config.whitelist_countries = ["US"]

    assert not await check_ip_country("8.8.8.8", security_config, mock_ipinfo)


@pytest.mark.asyncio
async def test_cloud_provider_blocking(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    mocker.patch("guard.utils.cloud_handler.is_cloud_ip", return_value=True)
    security_config.block_cloud_providers = {"AWS"}

    assert not await is_ip_allowed("8.8.8.8", security_config)


@pytest.mark.asyncio
async def test_check_ip_country_not_initialized(
    security_config: SecurityConfig,
) -> None:
    """Test check_ip_country when IPInfo reader is not initialized."""
    mock_ipinfo = Mock()
    mock_ipinfo.is_initialized = False
    mock_ipinfo.initialize = AsyncMock()
    mock_ipinfo.get_country.return_value = "US"

    result = await check_ip_country("1.1.1.1", security_config, mock_ipinfo)
    assert not result
    mock_ipinfo.initialize.assert_called_once()


@pytest.mark.asyncio
async def test_check_ip_country_no_country_found(
    security_config: SecurityConfig,
) -> None:
    """Test check_ip_country when country lookup fails."""
    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = None

    result = await check_ip_country("1.1.1.1", security_config, mock_ipinfo)
    assert not result


@pytest.mark.asyncio
async def test_check_ip_country_no_countries_configured(
    caplog: Any,
) -> None:
    """Test check_ip_country when no countries are blocked or whitelisted."""
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, blocked_countries=[], whitelist_countries=[]
    )

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = "US"

    with caplog.at_level(logging.WARNING):
        result = await check_ip_country("1.1.1.1", config, mock_ipinfo)
        assert not result
        assert "No countries blocked or whitelisted" in caplog.text
        assert "1.1.1.1" in caplog.text

    caplog.clear()

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "client": ("2.2.2.2", 12345),
        },
        receive=receive,
    )
    body = await request.body()
    assert body == b""

    with caplog.at_level(logging.WARNING):
        result = await check_ip_country(request, config, mock_ipinfo)
        assert not result
        assert "No countries blocked or whitelisted" in caplog.text
        assert "2.2.2.2" in caplog.text


@pytest.mark.asyncio
async def test_is_ip_allowed_cidr_blacklist() -> None:
    """Test the is_ip_allowed function with CIDR notation in blacklist."""
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, blacklist=["192.168.1.0/24"], whitelist=[]
    )

    assert not await is_ip_allowed("192.168.1.100", config)
    assert not await is_ip_allowed("192.168.1.1", config)
    assert not await is_ip_allowed("192.168.1.254", config)

    assert await is_ip_allowed("192.168.2.1", config)
    assert await is_ip_allowed("192.168.0.1", config)
    assert await is_ip_allowed("10.0.0.1", config)

    config_multiple = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        blacklist=["192.168.1.0/24", "10.0.0.0/8"],
        whitelist=[],
    )

    assert not await is_ip_allowed("192.168.1.100", config_multiple)
    assert not await is_ip_allowed("10.10.10.10", config_multiple)
    assert await is_ip_allowed("172.16.0.1", config_multiple)


@pytest.mark.asyncio
async def test_is_ip_allowed_cidr_whitelist() -> None:
    """Test the is_ip_allowed function with CIDR notation in whitelist."""
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN, whitelist=["192.168.1.0/24"], blacklist=[]
    )

    assert await is_ip_allowed("192.168.1.100", config)
    assert await is_ip_allowed("192.168.1.1", config)
    assert await is_ip_allowed("192.168.1.254", config)

    assert not await is_ip_allowed("192.168.2.1", config)
    assert not await is_ip_allowed("192.168.0.1", config)
    assert not await is_ip_allowed("10.0.0.1", config)

    config_multiple = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        whitelist=["192.168.1.0/24", "10.0.0.0/8"],
        blacklist=[],
    )

    assert await is_ip_allowed("192.168.1.100", config_multiple)
    assert await is_ip_allowed("10.10.10.10", config_multiple)
    assert not await is_ip_allowed("172.16.0.1", config_multiple)


@pytest.mark.asyncio
async def test_is_ip_allowed_invalid_ip(caplog: Any) -> None:
    """Test is_ip_allowed with invalid IP address."""
    config = SecurityConfig(ipinfo_token="test")

    with caplog.at_level(logging.ERROR):
        result = await is_ip_allowed("invalid-ip", config)
        assert not result


@pytest.mark.asyncio
async def test_is_ip_allowed_general_exception(
    caplog: Any, mocker: MockerFixture
) -> None:
    """Test is_ip_allowed with unexpected exception."""
    config = SecurityConfig(ipinfo_token="test")

    mock_error = Exception("Unexpected error")
    mocker.patch("guard.utils.ip_address", side_effect=mock_error)

    with caplog.at_level(logging.ERROR):
        result = await is_ip_allowed("192.168.1.1", config)
        assert result
        assert "Error checking IP 192.168.1.1" in caplog.text
        assert "Unexpected error" in caplog.text


@pytest.mark.asyncio
async def test_detect_penetration_attempt_body_error() -> None:
    """Test penetration detection with body reading error."""

    async def receive() -> dict[str, str | bytes]:
        raise Exception("Body read error")

    request = Request(
        scope={
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", b"10"),
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )

    result, _ = await detect_penetration_attempt(request)
    assert not result


@pytest.mark.asyncio
async def test_is_ip_allowed_blocked_country(mocker: MockerFixture) -> None:
    """Test is_ip_allowed with blocked country."""
    config = SecurityConfig(ipinfo_token="test", blocked_countries=["CN"])

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = "CN"

    mocker.patch("guard.utils.check_ip_country", return_value=True)

    result = await is_ip_allowed("192.168.1.1", config, mock_ipinfo)
    assert not result
