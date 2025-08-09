import logging
import os
from typing import Any, Literal
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request, Response
from pytest_mock import MockerFixture

from guard.decorators.base import RouteConfig
from guard.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.utils import (
    is_ip_allowed,
    is_user_agent_allowed,
    log_activity,
    setup_custom_logging,
)

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


@pytest.mark.asyncio
async def test_is_ip_allowed(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
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
async def test_is_user_agent_allowed(security_config: SecurityConfig) -> None:
    """
    Test the is_user_agent_allowed function
    with allowed and blocked user agents.
    """
    assert await is_user_agent_allowed("goodbot", security_config)
    assert not await is_user_agent_allowed("badbot", security_config)


@pytest.mark.asyncio
async def test_custom_logging(
    reset_state: None, security_config: SecurityConfig, tmp_path: Any
) -> None:
    """
    Test the custom logging.
    """
    log_file = tmp_path / "test_log.log"
    logger = setup_custom_logging(str(log_file))

    async def receive() -> dict[str, bytes | str]:
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

    await log_activity(request, logger)

    with open(log_file) as f:
        log_content = f.read()
        assert "Request from 127.0.0.1: GET /" in log_content


@pytest.mark.asyncio
async def test_log_request(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test the log_request function to ensure
    it logs the request details correctly.
    """

    async def receive() -> dict[str, bytes | str]:
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
        await log_activity(request, logger)

    assert "Request from 127.0.0.1: GET /" in caplog.text
    assert "Headers: {'user-agent': 'test-agent'}" in caplog.text


@pytest.mark.asyncio
async def test_log_suspicious_activity(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test the log_activity function with suspicious activity.
    """

    async def receive() -> dict[str, bytes | str]:
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
        await log_activity(
            request,
            logger,
            log_type="suspicious",
            reason="Suspicious activity detected",
        )

    assert "Suspicious activity detected" in caplog.text
    assert "127.0.0.1" in caplog.text
    assert "GET /" in caplog.text


@pytest.mark.asyncio
async def test_log_suspicious_activity_passive_mode(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Test the log_activity function with suspicious activity in passive mode.
    """

    async def receive() -> dict[str, bytes | str]:
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
        await log_activity(
            request,
            logger,
            log_type="suspicious",
            reason="Suspicious activity detected",
            passive_mode=True,
            trigger_info="SQL injection attempt",
        )

    assert "[PASSIVE MODE] Penetration attempt detected from" in caplog.text
    assert "127.0.0.1" in caplog.text
    assert "GET /" in caplog.text
    assert "Trigger: SQL injection attempt" in caplog.text


@pytest.mark.asyncio
async def test_log_custom_type(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test the log_activity function with a custom log type.
    """

    async def receive() -> dict[str, bytes | str]:
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
        await log_activity(
            request, logger, log_type="custom_event", reason="Custom event reason"
        )

    assert "Custom_event from 127.0.0.1: GET /" in caplog.text
    assert "Details: Custom event reason" in caplog.text
    assert "Headers: {'user-agent': 'test-agent'}" in caplog.text


def test_setup_custom_logging() -> None:
    """
    Test the setup_custom_logging function.
    """
    log_file = os.path.join(os.getcwd(), "security.log")
    logger = setup_custom_logging(log_file)

    handler_count = sum(
        1
        for h in logger.handlers
        if isinstance(h, logging.FileHandler | logging.StreamHandler)
    )
    assert handler_count >= 2


def test_no_duplicate_logs(caplog: pytest.LogCaptureFixture, tmp_path: Any) -> None:
    """
    Test that our logging setup doesn't cause duplicate log messages.

    This verifies that even though we allow propagation, the hierarchical
    namespace prevents duplicate console output.
    """
    # Create a custom log file
    log_file = tmp_path / "test_no_duplicates.log"

    # Setup custom logging
    guard_logger = setup_custom_logging(str(log_file))

    # Simulate user's logging config
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers.copy()
    original_level = root_logger.level

    # Simulate user's setup
    root_handler = logging.StreamHandler()
    root_handler.setFormatter(logging.Formatter("ROOT: %(message)s"))
    root_logger.addHandler(root_handler)
    root_logger.setLevel(logging.INFO)

    try:
        # Clear caplog and set level
        caplog.clear()
        caplog.set_level(logging.INFO)

        # Log a test message to guard_logger
        test_message = "Test message for duplicate check"
        guard_logger.info(test_message)

        # Check the message
        matching_records = [r for r in caplog.records if test_message in r.message]

        # We should see the message only once per handler, not duplicated
        # With propagation, it might appear in both fastapi_guard and root logger
        # but shouldn't be duplicated within the same logger
        assert len(matching_records) > 0, "Message should be logged"

        # Check that we don't have exact duplicates (same logger, same message)
        seen = set()
        for record in matching_records:
            key = (record.name, record.message, record.levelname)
            assert key not in seen, f"Duplicate log found: {key}"
            seen.add(key)

        # Verify the log file has the message
        with open(log_file) as f:
            file_content = f.read()
            assert test_message in file_content
            # Count occurrences in file - should be exactly once
            assert file_content.count(test_message) == 1, (
                "Message should appear once in log file"
            )

    finally:
        # Restore root logger state
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


def test_hierarchical_namespace_isolation() -> None:
    """
    Test that our hierarchical namespace properly isolates FastAPI Guard logs.

    This ensures that fastapi_guard.* loggers are separate from user loggers.
    """
    # Get different loggers
    guard_logger = logging.getLogger("fastapi_guard")
    guard_handler_logger = logging.getLogger("fastapi_guard.handlers.redis")
    user_logger = logging.getLogger("myapp")

    # Check namespace hierarchy
    assert guard_handler_logger.parent == guard_logger
    assert guard_logger.parent == logging.getLogger()  # root logger
    assert user_logger.parent == logging.getLogger()  # root logger

    # Verify they're different instances
    assert guard_logger is not user_logger
    assert guard_handler_logger is not user_logger

    # Verify the namespace
    assert guard_logger.name == "fastapi_guard"
    assert guard_handler_logger.name == "fastapi_guard.handlers.redis"
    assert user_logger.name == "myapp"


def test_custom_log_file_configuration(tmp_path: Any) -> None:
    """
    Test that custom_log_file configuration is properly used.
    """
    # Test with custom log file
    custom_log_path = tmp_path / "my_custom_security.log"
    logger = setup_custom_logging(str(custom_log_path))

    # Log a test message
    test_message = "Custom log file test"
    logger.info(test_message)

    # Verify the custom log file was created and contains the message
    assert custom_log_path.exists(), "Custom log file should be created"
    with open(custom_log_path) as f:
        content = f.read()
        assert test_message in content

    # Test with None (no file logging)
    logger_no_file = setup_custom_logging(None)

    # Should still have console handler but no file handler
    file_handlers = [
        h for h in logger_no_file.handlers if isinstance(h, logging.FileHandler)
    ]
    stream_handlers = [
        h for h in logger_no_file.handlers if isinstance(h, logging.StreamHandler)
    ]

    assert len(file_handlers) == 0, "Should have no file handlers when log_file is None"
    assert len(stream_handlers) >= 1, (
        "Should have at least one stream handler for console"
    )


def test_console_always_enabled(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test that console output is ALWAYS enabled regardless of file configuration.
    """
    # Setup without file
    logger_no_file = setup_custom_logging(None)

    caplog.clear()
    caplog.set_level(logging.INFO)

    test_message = "Console output test - no file"
    logger_no_file.info(test_message)

    # Message should appear in console (caplog)
    assert test_message in caplog.text, "Console output should work without file"

    # Setup with file
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp_file:
        logger_with_file = setup_custom_logging(tmp_file.name)

        caplog.clear()
        test_message_2 = "Console output test - with file"
        logger_with_file.info(test_message_2)

        # Message should appear in console (caplog) even with file
        assert test_message_2 in caplog.text, "Console output should work with file"

        # Clean up
        os.unlink(tmp_file.name)


def test_setup_custom_logging_creates_directory(tmp_path: Any) -> None:
    """
    Test that setup_custom_logging creates directory if it doesn't exist.
    """
    # Create a path with a non-existent subdirectory
    non_existent_dir = tmp_path / "logs" / "subdirectory" / "deep"
    log_file_path = non_existent_dir / "test.log"

    # Ensure the directory doesn't exist
    assert not non_existent_dir.exists(), "Directory should not exist initially"

    # Setup logging with file in non-existent directory
    logger = setup_custom_logging(str(log_file_path))

    # Directory should have been created
    assert non_existent_dir.exists(), "Directory should be created"

    # Verify file handler was added successfully
    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 1, "Should have exactly one file handler"

    # Test that logging works
    test_message = "Directory creation test"
    logger.info(test_message)

    # Verify the log file was created and contains the message
    assert log_file_path.exists(), "Log file should be created"
    with open(log_file_path) as f:
        content = f.read()
        assert test_message in content


def test_setup_custom_logging_file_handler_exception(
    caplog: pytest.LogCaptureFixture, mocker: MockerFixture
) -> None:
    """
    Test that setup_custom_logging handles exceptions when creating file handler.
    """
    # Mock FileHandler to raise an exception
    mocker.patch(
        "guard.utils.logging.FileHandler",
        side_effect=PermissionError("Permission denied: cannot create log file"),
    )

    # Clear existing logs
    caplog.clear()
    caplog.set_level(logging.WARNING, logger="fastapi_guard")

    # Try to setup logging with a file that will fail
    logger = setup_custom_logging("/invalid/path/test.log")

    # Should have logged a warning about the failure
    assert "Failed to create log file /invalid/path/test.log" in caplog.text
    assert "Permission denied: cannot create log file" in caplog.text

    # Logger should still work (console only)
    assert logger is not None

    # Should have only stream handler (console), no file handler
    # Since FileHandler was mocked and failed, we should only have StreamHandler
    assert len(logger.handlers) == 1, "Should have exactly one handler"
    assert isinstance(logger.handlers[0], logging.StreamHandler), (
        "Should have console handler"
    )

    # Test that console logging still works
    caplog.clear()
    caplog.set_level(logging.INFO, logger="fastapi_guard")
    test_message = "Console still works after file handler failure"
    logger.info(test_message)
    assert test_message in caplog.text


@pytest.mark.asyncio
async def test_log_level(caplog: pytest.LogCaptureFixture) -> None:
    async def receive() -> dict[str, bytes | str]:
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

    LOG_LEVELS: list[
        Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
    ] = [
        "INFO",
        "DEBUG",
        "WARNING",
        "ERROR",
        "CRITICAL",
        None,
    ]

    for level in LOG_LEVELS:
        caplog.clear()

        with caplog.at_level(logging.DEBUG):
            await log_activity(request, logger, level=level)

        if level is not None:
            assert len(caplog.records) == 1
            assert caplog.records[0].levelname == level
        else:
            assert len(caplog.records) == 0


@pytest.mark.asyncio
async def test_passive_mode_rate_limiting_scenarios(
    security_config_redis: SecurityConfig,
) -> None:
    """
    Test passive mode rate limiting.
    """
    # Endpoint-specific rate limit in passive mode
    security_config_redis.passive_mode = True
    security_config_redis.endpoint_rate_limits = {"/api/test": (1, 60)}

    app = Mock()
    middleware = SecurityMiddleware(app, config=security_config_redis)
    middleware.redis_handler = AsyncMock()

    # Mock rate handler that would return rate limit exceeded
    mock_rate_handler = AsyncMock()
    mock_rate_handler.check_rate_limit = AsyncMock(
        return_value=Response("Rate limited", status_code=429)
    )
    mock_rate_handler.initialize_redis = AsyncMock()

    with patch("guard.middleware.RateLimitManager", return_value=mock_rate_handler):
        request = Mock()
        request.url.path = "/api/test"

        # Should return None in passive mode
        result = await middleware._check_rate_limit(request, "127.0.0.1", None)
        assert result is None

    # Route-specific rate limit in passive mode
    route_config = RouteConfig()
    route_config.rate_limit = 5
    route_config.rate_limit_window = 30

    with patch("guard.middleware.RateLimitManager", return_value=mock_rate_handler):
        request = Mock()
        request.url.path = "/test"

        # Should return None in passive mode
        result = await middleware._check_rate_limit(request, "127.0.0.1", route_config)
        assert result is None

    # Global rate limit in passive mode
    with patch.object(
        middleware.rate_limit_handler,
        "check_rate_limit",
        AsyncMock(return_value=Response("Rate limited", status_code=429)),
    ):
        request = Mock()
        request.url.path = "/global"

        # Should return None in passive mode
        result = await middleware._check_rate_limit(request, "127.0.0.1", None)
        assert result is None


@pytest.mark.asyncio
async def test_behavior_tracker_passive_mode_logging(
    security_config: SecurityConfig,
) -> None:
    """
    Test for behavior handler passive mode.
    """
    security_config.passive_mode = True
    tracker = BehaviorTracker(security_config)

    test_cases: list[tuple[Literal["ban", "log", "throttle", "alert"], str, str]] = [
        (
            "ban",
            "warning",
            "[PASSIVE MODE] Would ban IP 192.168.1.1 for behavioral "
            "violation: Test details",
        ),
        (
            "log",
            "warning",
            "[PASSIVE MODE] Behavioral anomaly detected: Test details",
        ),
        (
            "throttle",
            "warning",
            "[PASSIVE MODE] Would throttle IP 192.168.1.1: Test details",
        ),
        (
            "alert",
            "critical",
            "[PASSIVE MODE] ALERT - Behavioral anomaly: Test details",
        ),
    ]

    for action, log_level, expected_message in test_cases:
        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            action=action,
        )

        with patch.object(tracker.logger, log_level) as mock_logger:
            await tracker.apply_action(
                rule=rule,
                client_ip="192.168.1.1",
                endpoint_id="/api/test",
                details="Test details",
            )

            mock_logger.assert_called_once_with(expected_message)
