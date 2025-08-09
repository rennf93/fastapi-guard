import logging
from unittest.mock import patch

import pytest
from fastapi import Request

from guard.models import SecurityConfig
from guard.utils import extract_client_ip


@pytest.mark.asyncio
async def test_extract_client_ip_without_trusted_proxies() -> None:
    """Test extracting client IP without trusted proxies."""
    config = SecurityConfig()

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"1.2.3.4")],
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_extract_client_ip_with_trusted_proxies() -> None:
    """Test extracting client IP with trusted proxies."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"1.2.3.4")],
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    ip = await extract_client_ip(request, config)
    assert ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_extract_client_ip_with_cidr_trusted_proxies() -> None:
    """Test extracting client IP with CIDR notation in trusted proxies."""
    config = SecurityConfig(trusted_proxies=["127.0.0.0/8"])

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"1.2.3.4")],
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    ip = await extract_client_ip(request, config)
    assert ip == "1.2.3.4"


@pytest.mark.asyncio
async def test_extract_client_ip_with_proxy_depth() -> None:
    """Test extracting client IP with proxy depth."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=2)

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"5.6.7.8, 1.2.3.4")],
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    ip = await extract_client_ip(request, config)
    assert ip == "5.6.7.8"


@pytest.mark.asyncio
async def test_extract_client_ip_without_xforwarded() -> None:
    """Test extracting client IP from trusted proxy but without X-Forwarded-For."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],  # No X-Forwarded-For
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    # Should fall back to client IP
    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_extract_client_ip_with_untrusted_proxy() -> None:
    """Test extracting client IP from untrusted proxy."""
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"1.2.3.4")],
            "client": ("127.0.0.1", 12345),  # Not in trusted proxies
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_extract_client_ip_error_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test error handling in extract_client_ip."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"invalid-ip")],
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    with caplog.at_level(logging.WARNING):
        with patch("guard.utils.ip_address", side_effect=ValueError("Invalid IP")):
            ip = await extract_client_ip(request, config)
            assert ip == "127.0.0.1"
            assert "Error processing client IP" in caplog.text


@pytest.mark.asyncio
async def test_extract_client_ip_no_client() -> None:
    """Test extracting client IP when request has no client."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"1.2.3.4")],
            # No 'client' key in scope
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    ip = await extract_client_ip(request, config)
    assert ip == "unknown"


@pytest.mark.asyncio
async def test_extract_client_ip_fallback_to_connecting_ip() -> None:
    """Test falling back to connecting IP when forwarded chain is too short."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=3)

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"1.2.3.4")],
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_extract_client_ip_untrusted_without_forwarded() -> None:
    """Test extracting client IP from untrusted proxy without X-Forwarded-For."""
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    async def receive() -> dict[str, str | bytes]:
        return {"type": "http.request", "body": b""}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [],  # No X-Forwarded-For header
            "client": ("127.0.0.1", 12345),  # Not in trusted proxies
        },
        receive=receive,
    )

    body = await request.body()
    assert body == b""

    ip = await extract_client_ip(request, config)
    assert ip == "127.0.0.1"
