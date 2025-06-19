import time
from typing import Any, Literal
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import Response

from guard.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard.handlers.redis_handler import redis_handler
from guard.models import SecurityConfig


def test_behavior_rule_creation() -> None:
    """Test creating a BehaviorRule with different parameters."""
    # Basic rule
    rule = BehaviorRule(
        rule_type="usage",
        threshold=10,
    )
    assert rule.rule_type == "usage"
    assert rule.threshold == 10
    assert rule.window == 3600  # default
    assert rule.pattern is None
    assert rule.action == "log"  # default
    assert rule.custom_action is None

    # Rule with all parameters
    custom_action = AsyncMock()
    rule = BehaviorRule(
        rule_type="return_pattern",
        threshold=5,
        window=1800,
        pattern="json:status==success",
        action="ban",
        custom_action=custom_action,
    )
    assert rule.rule_type == "return_pattern"
    assert rule.threshold == 5
    assert rule.window == 1800
    assert rule.pattern == "json:status==success"
    assert rule.action == "ban"
    assert rule.custom_action == custom_action


@pytest.mark.parametrize(
    "rule_type,threshold,window,pattern,action",
    [
        ("usage", 10, 3600, None, "log"),
        ("return_pattern", 5, 1800, "status:200", "ban"),
        ("frequency", 20, 300, "regex:error", "throttle"),
    ],
)
def test_behavior_rule_parameterized(
    rule_type: Literal["usage", "return_pattern", "frequency"],
    threshold: int,
    window: int,
    pattern: str | None,
    action: Literal["ban", "log", "throttle", "alert"],
) -> None:
    """Test BehaviorRule creation with various parameter combinations."""
    rule = BehaviorRule(
        rule_type=rule_type,
        threshold=threshold,
        window=window,
        pattern=pattern,
        action=action,
    )
    assert rule.rule_type == rule_type
    assert rule.threshold == threshold
    assert rule.window == window
    assert rule.pattern == pattern
    assert rule.action == action


def test_behavior_tracker_initialization(security_config: SecurityConfig) -> None:
    """Test BehaviorTracker initialization."""
    tracker = BehaviorTracker(security_config)
    assert tracker.config == security_config
    assert tracker.logger is not None
    assert tracker.usage_counts is not None
    assert tracker.return_patterns is not None
    assert tracker.redis_handler is None


@pytest.mark.asyncio
async def test_initialize_redis(security_config_redis: SecurityConfig) -> None:
    """Test Redis initialization."""
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    await redis_mgr.initialize()

    await tracker.initialize_redis(redis_mgr)
    assert tracker.redis_handler == redis_mgr

    await redis_mgr.close()


@pytest.mark.asyncio
async def test_track_endpoint_usage_in_memory(security_config: SecurityConfig) -> None:
    """Test endpoint usage tracking with in-memory storage."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=3, window=1)

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"

    # First few requests should not exceed threshold
    assert not await tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
    assert not await tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
    assert not await tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    # Fourth request should exceed threshold
    assert await tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    # Verify data structure
    assert len(tracker.usage_counts[endpoint_id][client_ip]) == 4


@pytest.mark.asyncio
async def test_track_endpoint_usage_with_window_cleanup(
    security_config: SecurityConfig,
) -> None:
    """Test endpoint usage tracking with time window cleanup."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=2, window=1)

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"

    # Add old timestamp manually
    current_time = time.time()
    old_time = current_time - 2  # 2 seconds ago, outside 1-second window
    tracker.usage_counts[endpoint_id][client_ip].append(old_time)
    tracker.usage_counts[endpoint_id][client_ip].append(old_time)

    # New request should clean old timestamps and not exceed threshold
    assert not await tracker.track_endpoint_usage(endpoint_id, client_ip, rule)

    # Only the new timestamp should remain
    assert len(tracker.usage_counts[endpoint_id][client_ip]) == 1


@pytest.mark.asyncio
async def test_track_endpoint_usage_with_redis(
    security_config_redis: SecurityConfig,
) -> None:
    """Test endpoint usage tracking with Redis."""
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    await redis_mgr.initialize()
    await tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=2, window=60)
    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"
    current_time = time.time()

    # Mock Redis operations
    with (
        patch.object(redis_mgr, "keys") as mock_keys,
        patch.object(redis_mgr, "set_key") as mock_set_key,
    ):
        # First request - should not exceed threshold (1 key)
        mock_keys.return_value = [
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time}"
        ]
        mock_set_key.return_value = None
        result = await tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert not result

        # Second request - should not exceed threshold (2 keys)
        mock_keys.return_value = [
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time}",
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time + 1}",
        ]
        result = await tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert not result

        # Third request - should exceed threshold (3 keys > threshold 2)
        mock_keys.return_value = [
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time}",
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time + 1}",
            f"behavior_usage:behavior:usage:/api/test:192.168.1.1:{current_time + 2}",
        ]
        result = await tracker.track_endpoint_usage(endpoint_id, client_ip, rule)
        assert result

    await redis_mgr.close()


@pytest.mark.asyncio
async def test_track_return_pattern_no_pattern(security_config: SecurityConfig) -> None:
    """Test return pattern tracking with no pattern specified."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="return_pattern", threshold=5)  # No pattern

    response = Response("test", status_code=200)
    result = await tracker.track_return_pattern(
        "/api/test", "192.168.1.1", response, rule
    )
    assert not result


@pytest.mark.asyncio
async def test_track_return_pattern_in_memory(security_config: SecurityConfig) -> None:
    """Test return pattern tracking with in-memory storage."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="return_pattern", threshold=2, pattern="status:200")

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"
    response = Response("success", status_code=200)

    # First few matches should not exceed threshold
    assert not await tracker.track_return_pattern(
        endpoint_id, client_ip, response, rule
    )
    assert not await tracker.track_return_pattern(
        endpoint_id, client_ip, response, rule
    )

    # Third match should exceed threshold
    assert await tracker.track_return_pattern(endpoint_id, client_ip, response, rule)


@pytest.mark.asyncio
async def test_track_return_pattern_with_redis(
    security_config_redis: SecurityConfig,
) -> None:
    """Test return pattern tracking with Redis."""
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    await redis_mgr.initialize()
    await tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="return_pattern", threshold=1, pattern="status:200")
    response = Response("success", status_code=200)
    current_time = time.time()

    with (
        patch.object(redis_mgr, "keys") as mock_keys,
        patch.object(redis_mgr, "set_key") as mock_set_key,
    ):
        key = "behavior_returns:behavior:return:/api/test:192.168.1.1:status:200"
        mock_keys.return_value = [
            f"{key}:{current_time}",
            f"{key}:{current_time + 1}",
        ]
        mock_set_key.return_value = None

        result = await tracker.track_return_pattern(
            "/api/test", "192.168.1.1", response, rule
        )
        assert result

    await redis_mgr.close()


@pytest.mark.parametrize(
    "response_data,pattern,expected",
    [
        # Status code patterns
        ({"status_code": 200}, "status:200", True),
        ({"status_code": 404}, "status:200", False),
        # JSON patterns
        (
            {"body": '{"status": "success"}', "status_code": 200},
            "json:status==success",
            True,
        ),
        (
            {"body": '{"status": "error"}', "status_code": 200},
            "json:status==success",
            False,
        ),
        (
            {"body": '{"result": {"status": "win"}}', "status_code": 200},
            "json:result.status==win",
            True,
        ),
        # Regex patterns
        (
            {"body": "Error: Database connection failed", "status_code": 500},
            "regex:database.*failed",
            True,
        ),
        (
            {"body": "Success: Operation completed", "status_code": 200},
            "regex:database.*failed",
            False,
        ),
        # String patterns
        ({"body": "Internal Server Error", "status_code": 500}, "server error", True),
        ({"body": "Success", "status_code": 200}, "server error", False),
    ],
)
@pytest.mark.asyncio
async def test_check_response_pattern(
    security_config: SecurityConfig,
    response_data: dict[str, Any],
    pattern: str,
    expected: bool,
) -> None:
    """Test response pattern checking with various patterns."""
    tracker = BehaviorTracker(security_config)

    # Create response with mock data
    response = Response(
        response_data.get("body", ""), status_code=response_data.get("status_code", 200)
    )

    result = await tracker._check_response_pattern(response, pattern)
    assert result == expected


@pytest.mark.asyncio
async def test_check_response_pattern_json_invalid(
    security_config: SecurityConfig,
) -> None:
    """Test response pattern checking with invalid JSON."""
    tracker = BehaviorTracker(security_config)
    response = Response("invalid json {", status_code=200)

    result = await tracker._check_response_pattern(response, "json:status==success")
    assert not result


@pytest.mark.asyncio
async def test_check_response_pattern_no_body(security_config: SecurityConfig) -> None:
    """Test response pattern checking with no response body."""
    tracker = BehaviorTracker(security_config)
    response = Response(status_code=200)
    response.body = b""

    result = await tracker._check_response_pattern(response, "test pattern")
    assert not result


@pytest.mark.asyncio
async def test_check_response_pattern_bytes_body(
    security_config: SecurityConfig,
) -> None:
    """Test response pattern checking with bytes body."""
    tracker = BehaviorTracker(security_config)
    response = Response(status_code=200)
    response.body = b"test content"

    result = await tracker._check_response_pattern(response, "test content")
    assert result


@pytest.mark.asyncio
async def test_check_response_pattern_exception(
    security_config: SecurityConfig,
) -> None:
    """Test response pattern checking with exception."""
    tracker = BehaviorTracker(security_config)

    with patch.object(tracker.logger, "error") as mock_logger:
        # Create a response that will cause an exception in pattern checking
        response = Response("test", status_code=200)

        # Patch json.loads to raise an exception for JSON pattern testing
        with patch("json.loads", side_effect=Exception("Test error")):
            result = await tracker._check_response_pattern(response, "json:test==value")
            assert not result
            mock_logger.assert_called_once()


@pytest.mark.asyncio
async def test_check_response_pattern_non_bytes_body(
    security_config: SecurityConfig,
) -> None:
    """Test response pattern checking with non-bytes body."""
    tracker = BehaviorTracker(security_config)
    response = Response(status_code=200)

    response.body = b"12345"

    result = await tracker._check_response_pattern(response, "12345")
    assert result

    response.body = "12345"  # type: ignore

    result2 = await tracker._check_response_pattern(response, "12345")
    assert result2


@pytest.mark.asyncio
async def test_match_json_pattern_exception(security_config: SecurityConfig) -> None:
    """Test JSON pattern matching with exception"""
    tracker = BehaviorTracker(security_config)

    class ProblematicData:
        def __str__(self) -> str:
            raise Exception("Test exception in str conversion")

    problematic_data = {"nested": {"value": ProblematicData()}}

    result = tracker._match_json_pattern(problematic_data, "nested.value==test")
    assert not result


@pytest.mark.parametrize(
    "data,pattern,expected",
    [
        # Simple dot notation
        ({"status": "success"}, "status==success", True),
        ({"status": "error"}, "status==success", False),
        # Nested objects
        ({"result": {"status": "win"}}, "result.status==win", True),
        ({"result": {"status": "lose"}}, "result.status==win", False),
        # Array handling
        ({"items": ["rare", "common"]}, "items[]==rare", True),
        ({"items": ["common", "uncommon"]}, "items[]==rare", False),
        # Missing keys
        ({"other": "value"}, "status==success", False),
        ({"result": {}}, "result.status==win", False),
    ],
)
def test_match_json_pattern(
    security_config: SecurityConfig, data: dict[str, Any], pattern: str, expected: bool
) -> None:
    """Test JSON pattern matching with various patterns."""
    tracker = BehaviorTracker(security_config)
    result = tracker._match_json_pattern(data, pattern)
    assert result == expected


def test_match_json_pattern_invalid(security_config: SecurityConfig) -> None:
    """Test JSON pattern matching with invalid patterns."""
    tracker = BehaviorTracker(security_config)

    # Pattern without ==
    result = tracker._match_json_pattern({"status": "success"}, "status")
    assert not result

    # Exception during processing
    result = tracker._match_json_pattern(
        {"status": "success"}, "invalid..pattern==test"
    )
    assert not result


@pytest.mark.asyncio
async def test_apply_action_custom(security_config: SecurityConfig) -> None:
    """Test applying custom action."""
    tracker = BehaviorTracker(security_config)
    custom_action = AsyncMock()
    rule = BehaviorRule(rule_type="usage", threshold=5, custom_action=custom_action)

    await tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
    custom_action.assert_awaited_once_with("192.168.1.1", "/api/test", "Test violation")


@pytest.mark.asyncio
async def test_apply_action_ban(security_config: SecurityConfig) -> None:
    """Test applying ban action."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="ban")

    with (
        patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ban_manager,
        patch.object(tracker.logger, "warning") as mock_logger,
    ):
        mock_ban_manager.ban_ip = AsyncMock()

        await tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")

        mock_ban_manager.ban_ip.assert_awaited_once_with("192.168.1.1", 3600)
        mock_logger.assert_called_once()


@pytest.mark.asyncio
async def test_apply_action_log(security_config: SecurityConfig) -> None:
    """Test applying log action."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="log")

    with patch.object(tracker.logger, "warning") as mock_logger:
        await tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "Behavioral anomaly detected: Test violation"
        )


@pytest.mark.asyncio
async def test_apply_action_throttle(security_config: SecurityConfig) -> None:
    """Test applying throttle action."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="throttle")

    with patch.object(tracker.logger, "warning") as mock_logger:
        await tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with("Throttling IP 192.168.1.1: Test violation")


@pytest.mark.asyncio
async def test_apply_action_alert(security_config: SecurityConfig) -> None:
    """Test applying alert action."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="usage", threshold=5, action="alert")

    with patch.object(tracker.logger, "critical") as mock_logger:
        await tracker.apply_action(rule, "192.168.1.1", "/api/test", "Test violation")
        mock_logger.assert_called_once_with(
            "ALERT - Behavioral anomaly: Test violation"
        )


@pytest.mark.asyncio
async def test_redis_key_timestamp_filtering(
    security_config_redis: SecurityConfig,
) -> None:
    """Test Redis key filtering by timestamp."""
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    await redis_mgr.initialize()
    await tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(rule_type="usage", threshold=2, window=60)
    current_time = time.time()

    with (
        patch.object(redis_mgr, "keys") as mock_keys,
        patch.object(redis_mgr, "set_key") as mock_set_key,
    ):
        # Mix of valid and invalid timestamps
        mock_keys.return_value = [
            f"behavior_usage:test:key:{current_time}",  # Valid - current
            f"behavior_usage:test:key:{current_time - 30}",  # Valid - within window
            f"behavior_usage:test:key:{current_time - 120}",  # Invalid - outside window
            "behavior_usage:test:key:invalid_timestamp",  # Invalid - bad format
            "behavior_usage:test:key:",  # Invalid - empty timestamp
        ]
        mock_set_key.return_value = None

        result = await tracker.track_endpoint_usage("/api/test", "192.168.1.1", rule)
        # Should count 2 valid timestamps, which equals threshold, so not exceeded
        assert not result


@pytest.mark.asyncio
async def test_track_return_pattern_no_match(security_config: SecurityConfig) -> None:
    """Test return pattern tracking when pattern doesn't match."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(rule_type="return_pattern", threshold=1, pattern="status:404")

    response = Response("success", status_code=200)  # Won't match 404 pattern
    result = await tracker.track_return_pattern(
        "/api/test", "192.168.1.1", response, rule
    )
    assert not result


@pytest.mark.asyncio
async def test_track_return_pattern_window_cleanup(
    security_config: SecurityConfig,
) -> None:
    """Test return pattern tracking with time window cleanup."""
    tracker = BehaviorTracker(security_config)
    rule = BehaviorRule(
        rule_type="return_pattern", threshold=2, window=1, pattern="status:200"
    )

    endpoint_id = "/api/test"
    client_ip = "192.168.1.1"
    pattern_key = f"{endpoint_id}:{rule.pattern}"

    # Add old timestamps manually
    current_time = time.time()
    old_time = current_time - 2  # Outside 1-second window
    tracker.return_patterns[pattern_key][client_ip].extend([old_time, old_time])

    response = Response("success", status_code=200)

    # Should clean old timestamps and not exceed threshold
    result = await tracker.track_return_pattern(endpoint_id, client_ip, response, rule)
    assert not result

    # Only the new timestamp should remain
    assert len(tracker.return_patterns[pattern_key][client_ip]) == 1


@pytest.mark.asyncio
async def test_redis_return_pattern_timestamp_filtering(
    security_config_redis: SecurityConfig,
) -> None:
    """Test Redis return pattern timestamp filtering."""
    tracker = BehaviorTracker(security_config_redis)
    redis_mgr = redis_handler(security_config_redis)
    await redis_mgr.initialize()
    await tracker.initialize_redis(redis_mgr)

    rule = BehaviorRule(
        rule_type="return_pattern", threshold=1, window=60, pattern="status:200"
    )
    current_time = time.time()
    response = Response("success", status_code=200)

    with (
        patch.object(redis_mgr, "keys") as mock_keys,
        patch.object(redis_mgr, "set_key") as mock_set_key,
    ):
        # Mix of valid and invalid timestamps
        mock_keys.return_value = [
            f"behavior_returns:test:key:{current_time}",  # Valid
            f"behavior_returns:test:key:{current_time - 120}",  # Outside window
            "behavior_returns:test:key:invalid",  # Invalid format
        ]
        mock_set_key.return_value = None

        result = await tracker.track_return_pattern(
            "/api/test", "192.168.1.1", response, rule
        )
        # Should count 1 valid timestamp, which equals threshold, so not exceeded
        assert not result
