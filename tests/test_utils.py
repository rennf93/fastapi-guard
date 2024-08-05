import pytest
from fastapi import Request
from guard.utils import is_ip_allowed, log_request, detect_penetration_attempt
from guard.models import SecurityConfig
import logging
from config.sus_patterns import SusPatterns


@pytest.fixture
def security_config():
    return SecurityConfig(whitelist=["127.0.0.1"], blacklist=["192.168.1.1"])


def test_is_ip_allowed(security_config):
    assert is_ip_allowed("127.0.0.1", security_config) == True
    assert is_ip_allowed("192.168.1.1", security_config) == False
    assert is_ip_allowed("10.0.0.1", security_config) == False


@pytest.mark.asyncio
async def test_detect_penetration_attempt():
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


@pytest.mark.asyncio
async def test_log_request(caplog):
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
    with caplog.at_level(logging.INFO):
        log_request(request)
        assert "Request from 127.0.0.1: GET / - Headers: {'user-agent': 'test-agent'}" in caplog.text


def test_add_pattern():
    sus_patterns = SusPatterns()
    new_pattern = r"new_pattern"
    sus_patterns.add_pattern(new_pattern)
    assert new_pattern in sus_patterns.patterns


def test_remove_pattern():
    sus_patterns = SusPatterns()
    pattern_to_remove = r"new_pattern"
    sus_patterns.add_pattern(pattern_to_remove)
    sus_patterns.remove_pattern(pattern_to_remove)
    assert pattern_to_remove not in sus_patterns.patterns
    