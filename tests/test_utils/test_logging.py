import logging
import os

import pytest
from fastapi import Request

from guard.models import SecurityConfig
from guard.utils import (
    is_ip_allowed,
    is_user_agent_allowed,
    log_request,
    log_suspicious_activity,
    setup_custom_logging,
)

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")


@pytest.mark.asyncio
async def test_is_ip_allowed(security_config, mocker):
    """
    Test the is_ip_allowed function
    with various IP addresses.
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
async def test_is_user_agent_allowed(security_config):
    """
    Test the is_user_agent_allowed function
    with allowed and blocked user agents.
    """
    assert await is_user_agent_allowed("goodbot", security_config)
    assert not await is_user_agent_allowed("badbot", security_config)


@pytest.mark.asyncio
async def test_custom_logging(reset_state, security_config, tmp_path):
    """
    Test the custom logging.
    """
    log_file = tmp_path / "test_log.log"
    logger = await setup_custom_logging(str(log_file))

    async def receive():
        return {"type": "http.request", "body": b"test_body"}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"user-agent", b"test-agent")],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    body = await request.body()
    assert body == b"test_body"

    await log_request(request, logger)

    with open(log_file) as f:
        log_content = f.read()
        assert "Request from 127.0.0.1: GET /" in log_content


@pytest.mark.asyncio
async def test_log_request(caplog):
    """
    Test the log_request function to ensure
    it logs the request details correctly.
    """

    async def receive():
        return {"type": "http.request", "body": b"test_body"}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"user-agent", b"test-agent")],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    body = await request.body()
    assert body == b"test_body"

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.INFO):
        await log_request(request, logger)

    assert "Request from 127.0.0.1: GET /" in caplog.text
    assert "Headers: {'user-agent': 'test-agent'}" in caplog.text


@pytest.mark.asyncio
async def test_log_suspicious_activity(caplog):
    """
    Test the log_suspicious_activity function.
    """

    async def receive():
        return {"type": "http.request", "body": b"test_body"}

    request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"user-agent", b"test-agent")],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
        },
        receive=receive,
    )
    body = await request.body()
    assert body == b"test_body"

    logger = logging.getLogger(__name__)
    with caplog.at_level(logging.WARNING):
        await log_suspicious_activity(request, "Suspicious activity detected", logger)

    assert "Suspicious activity detected" in caplog.text
    assert "127.0.0.1" in caplog.text
    assert "GET /" in caplog.text


@pytest.mark.asyncio
async def test_setup_custom_logging():
    """
    Test the setup_custom_logging function.
    """
    log_file = os.path.join(os.getcwd(), "security.log")
    logger = await setup_custom_logging(log_file)

    handler_count = sum(
        1
        for h in logger.handlers
        if isinstance(h, logging.FileHandler | logging.StreamHandler)
    )
    assert handler_count >= 2
