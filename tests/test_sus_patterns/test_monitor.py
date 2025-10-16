import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard.detection_engine.monitor import (
    PatternStats,
    PerformanceMetric,
    PerformanceMonitor,
)


def test_initialization() -> None:
    """Test PerformanceMonitor initialization."""
    # Test with default values
    monitor = PerformanceMonitor()
    assert monitor.anomaly_threshold == 3.0
    assert monitor.slow_pattern_threshold == 0.1
    assert monitor.history_size == 1000
    assert monitor.max_tracked_patterns == 1000
    assert len(monitor.pattern_stats) == 0
    assert len(monitor.recent_metrics) == 0
    assert len(monitor.anomaly_callbacks) == 0

    # Test with custom values
    monitor = PerformanceMonitor(
        anomaly_threshold=5.0,
        slow_pattern_threshold=0.5,
        history_size=500,
        max_tracked_patterns=200,
    )
    assert monitor.anomaly_threshold == 5.0
    assert monitor.slow_pattern_threshold == 0.5
    assert monitor.history_size == 500
    assert monitor.max_tracked_patterns == 200


def test_initialization_bounds() -> None:
    """Test PerformanceMonitor initialization with boundary values."""
    # Test lower bounds
    monitor = PerformanceMonitor(
        anomaly_threshold=0.5,  # Below minimum
        slow_pattern_threshold=0.001,  # Below minimum
        history_size=50,  # Below minimum
        max_tracked_patterns=50,  # Below minimum
    )
    assert monitor.anomaly_threshold == 1.0  # Clamped to minimum
    assert monitor.slow_pattern_threshold == 0.01  # Clamped to minimum
    assert monitor.history_size == 100  # Clamped to minimum
    assert monitor.max_tracked_patterns == 100  # Clamped to minimum

    # Test upper bounds
    monitor = PerformanceMonitor(
        anomaly_threshold=20.0,  # Above maximum
        slow_pattern_threshold=20.0,  # Above maximum
        history_size=20000,  # Above maximum
        max_tracked_patterns=10000,  # Above maximum
    )
    assert monitor.anomaly_threshold == 10.0  # Clamped to maximum
    assert monitor.slow_pattern_threshold == 10.0  # Clamped to maximum
    assert monitor.history_size == 10000  # Clamped to maximum
    assert monitor.max_tracked_patterns == 5000  # Clamped to maximum


@pytest.mark.asyncio
async def test_record_metric_pattern_truncation() -> None:
    """Test that long patterns are truncated."""
    monitor = PerformanceMonitor()

    # Create a pattern longer than 100 characters
    long_pattern = "a" * 150
    await monitor.record_metric(
        pattern=long_pattern,
        execution_time=0.05,
        content_length=100,
        matched=True,
    )

    # Check that pattern was truncated
    stored_pattern = list(monitor.pattern_stats.keys())[0]
    assert len(stored_pattern) == 114  # 100 + len("...[truncated]")
    assert stored_pattern.endswith("...[truncated]")


@pytest.mark.asyncio
async def test_record_metric_max_patterns_limit() -> None:
    """Test pattern limit enforcement."""
    # Note: PerformanceMonitor enforces a minimum of 100 for max_tracked_patterns
    # So we'll use 100 (the minimum) and add 101 patterns to trigger eviction
    monitor = PerformanceMonitor(max_tracked_patterns=100)

    # Add patterns up to the limit
    patterns = [f"pattern_{i:03d}" for i in range(100)]
    for pattern in patterns:
        await monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    # Verify we're at the limit
    assert len(monitor.pattern_stats) == 100

    # Now add a new pattern that should trigger eviction
    await monitor.record_metric(
        pattern="pattern_100",
        execution_time=0.01,
        content_length=100,
        matched=False,
    )

    # Check that limit is enforced - should still have max_tracked_patterns
    assert len(monitor.pattern_stats) == 100

    # The oldest pattern should have been removed (FIFO)
    # Python dicts maintain insertion order, so pattern_000 should be removed
    assert "pattern_000" not in monitor.pattern_stats
    assert "pattern_100" in monitor.pattern_stats


@pytest.mark.asyncio
async def test_record_metric_with_timeout() -> None:
    """Test recording metrics with timeout."""
    monitor = PerformanceMonitor()

    await monitor.record_metric(
        pattern="timeout_pattern",
        execution_time=1.0,
        content_length=1000,
        matched=False,
        timeout=True,
    )

    stats = monitor.pattern_stats["timeout_pattern"]
    assert stats.total_executions == 1
    assert stats.total_timeouts == 1
    assert stats.total_matches == 0
    # Timeout metrics should not affect average time
    assert len(stats.recent_times) == 0


@pytest.mark.asyncio
async def test_check_anomalies_timeout() -> None:
    """Test anomaly detection for timeouts."""
    monitor = PerformanceMonitor()

    # Create a list to capture anomaly callbacks
    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    # Record a timeout metric
    await monitor.record_metric(
        pattern="timeout_test",
        execution_time=5.0,
        content_length=1000,
        matched=False,
        timeout=True,
    )

    # Check that timeout anomaly was detected
    assert len(anomalies_detected) == 1
    assert anomalies_detected[0]["type"] == "timeout"
    assert "timeout_test" in anomalies_detected[0]["pattern"]


@pytest.mark.asyncio
async def test_check_anomalies_statistical() -> None:
    """Test statistical anomaly detection."""
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)

    monitor.register_anomaly_callback(anomaly_callback)

    # Record normal execution times
    pattern = "stat_pattern"
    for _ in range(20):
        await monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,  # Normal time
            content_length=100,
            matched=False,
        )

    # Clear any anomalies from setup
    anomalies_detected.clear()

    # Record an anomalous execution time
    await monitor.record_metric(
        pattern=pattern,
        execution_time=0.1,  # 10x normal - should trigger anomaly
        content_length=100,
        matched=False,
    )

    # Check that statistical anomaly was detected
    assert len(anomalies_detected) == 1
    assert anomalies_detected[0]["type"] == "statistical_anomaly"
    assert anomalies_detected[0]["z_score"] > 2.0


@pytest.mark.asyncio
async def test_statistical_anomaly_insufficient_data() -> None:
    """Test statistical anomaly when there's insufficient data (< 10 recent times)."""
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)  # pragma: no cover

    monitor.register_anomaly_callback(anomaly_callback)

    # Record only 8 metrics (less than 10 required)
    pattern = "insufficient_pattern"
    for _ in range(8):
        await monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,
            content_length=100,
            matched=False,
        )

    # No anomalies should be detected due to insufficient data
    assert len(anomalies_detected) == 0


@pytest.mark.asyncio
async def test_statistical_anomaly_zero_std_dev() -> None:
    """Test statistical anomaly when std deviation is zero (all same values)."""
    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    anomalies_detected = []

    def anomaly_callback(anomaly: dict[str, Any]) -> None:
        anomalies_detected.append(anomaly)  # pragma: no cover

    monitor.register_anomaly_callback(anomaly_callback)

    # Record 15 identical execution times
    pattern = "zero_std_pattern"
    for _ in range(15):
        await monitor.record_metric(
            pattern=pattern,
            execution_time=0.01,  # Same value every time
            content_length=100,
            matched=False,
        )

    # No statistical anomaly should be detected (std dev is 0)
    assert len(anomalies_detected) == 0


@pytest.mark.asyncio
async def test_statistical_anomaly_single_data_point() -> None:
    """Test statistical anomaly when there's only 1 data point."""
    from guard.detection_engine.monitor import PatternStats

    monitor = PerformanceMonitor(anomaly_threshold=2.0)

    # Create a pattern with exactly 1 recent_time to trigger
    pattern = "single_point_pattern"
    stats = PatternStats(pattern=pattern)
    stats.recent_times.append(0.01)
    monitor.pattern_stats[pattern] = stats

    # Create a mock metric
    from datetime import datetime, timezone

    from guard.detection_engine.monitor import PerformanceMetric

    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.5,
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    # Call _detect_statistical_anomaly directly
    result = monitor._detect_statistical_anomaly(metric)

    # Should return None because len(recent_times) <= 1
    assert result is None


@pytest.mark.asyncio
async def test_statistical_anomaly_within_threshold() -> None:
    """Test statistical anomaly when z-score is within threshold."""
    from collections import deque
    from datetime import datetime, timezone

    from guard.detection_engine.monitor import PatternStats, PerformanceMetric

    monitor = PerformanceMonitor(anomaly_threshold=3.0)  # Higher threshold

    # Create pattern stats with data that will produce low z-score
    pattern = "within_threshold_pattern"
    stats = PatternStats(pattern=pattern)

    # Create times with some variance: mean ~0.01, but with enough variance
    # that a small deviation won't exceed 3 std devs
    times = [
        0.008,
        0.009,
        0.010,
        0.011,
        0.012,
        0.009,
        0.010,
        0.011,
        0.010,
        0.009,
        0.010,
        0.011,
        0.012,
        0.009,
        0.010,
        0.011,
        0.010,
        0.009,
        0.010,
        0.011,
    ]
    stats.recent_times = deque(times, maxlen=100)
    monitor.pattern_stats[pattern] = stats

    # Create a metric with a value slightly above mean but within 3 std devs
    metric = PerformanceMetric(
        pattern=pattern,
        execution_time=0.012,  # Within normal range
        content_length=100,
        timestamp=datetime.now(timezone.utc),
        matched=False,
        timeout=False,
    )

    # Call _detect_statistical_anomaly directly
    result = monitor._detect_statistical_anomaly(metric)

    # Should return None because z-score is below threshold
    assert result is None


@pytest.mark.asyncio
async def test_check_anomalies_with_agent() -> None:
    """Test anomaly event sending to agent."""
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock()

    # Record a slow execution to trigger anomaly
    await monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,  # Above slow threshold
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
        correlation_id="test-123",
    )

    # Check that event was sent to agent
    agent_handler.send_event.assert_called_once()
    event = agent_handler.send_event.call_args[0][0]
    assert event.event_type == "pattern_anomaly_slow_execution"
    assert event.action_taken == "anomaly_detected"
    assert event.metadata["correlation_id"] == "test-123"


@pytest.mark.asyncio
async def test_check_anomalies_agent_error() -> None:
    """Test anomaly handling when agent fails."""
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock(side_effect=Exception("Agent error"))

    # Should not raise exception even if agent fails
    await monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
    )


@pytest.mark.asyncio
async def test_anomaly_callback_error() -> None:
    """Test handling of callback errors."""
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock()

    # Register a failing callback
    def failing_callback(anomaly: dict[str, Any]) -> None:
        raise Exception("Callback error")

    monitor.register_anomaly_callback(failing_callback)

    # Record a slow metric to trigger anomaly
    await monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
        correlation_id="test-456",
    )

    # Check that error event was sent to agent
    assert agent_handler.send_event.call_count == 2  # One for anomaly, one for error
    error_event = agent_handler.send_event.call_args_list[1][0][0]
    assert error_event.event_type == "detection_engine_callback_error"
    assert "Callback error" in error_event.reason


@pytest.mark.asyncio
async def test_anomaly_callback_error_agent_failure() -> None:
    """Test callback error handling when agent also fails."""
    monitor = PerformanceMonitor()
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock(side_effect=Exception("Agent error"))

    # Register a failing callback
    def failing_callback(anomaly: dict[str, Any]) -> None:
        raise Exception("Callback error")

    monitor.register_anomaly_callback(failing_callback)

    # Should handle double failure gracefully
    await monitor.record_metric(
        pattern="slow_pattern",
        execution_time=0.5,
        content_length=100,
        matched=False,
        agent_handler=agent_handler,
    )


def test_get_pattern_report_not_found() -> None:
    """Test get_pattern_report with non-existent pattern."""
    monitor = PerformanceMonitor()

    report = monitor.get_pattern_report("non_existent")
    assert report is None


def test_get_pattern_report_truncation() -> None:
    """Test get_pattern_report pattern truncation."""
    monitor = PerformanceMonitor()

    # Add a pattern with some stats
    pattern = "test_pattern"
    stats = PatternStats(
        pattern=pattern,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    monitor.pattern_stats[pattern] = stats

    report = monitor.get_pattern_report(pattern)
    assert report is not None
    assert report["pattern"] == pattern
    assert report["total_executions"] == 10
    assert report["match_rate"] == 0.5
    assert report["timeout_rate"] == 0.1


def test_get_pattern_report_long_pattern_truncation() -> None:
    """Test get_pattern_report with long pattern that needs truncation."""
    monitor = PerformanceMonitor()

    # Add a pattern that's already truncated in the stats
    stored_pattern = "a" * 100 + "...[truncated]"
    stats = PatternStats(
        pattern=stored_pattern,
        total_executions=10,
        total_matches=5,
        total_timeouts=1,
        avg_execution_time=0.05,
        max_execution_time=0.1,
        min_execution_time=0.01,
    )
    monitor.pattern_stats[stored_pattern] = stats

    # Request report with the long original pattern
    long_original_pattern = "a" * 150
    report = monitor.get_pattern_report(long_original_pattern)

    # Should find the truncated pattern
    assert report is not None
    assert report["total_executions"] == 10


@pytest.mark.asyncio
async def test_get_problematic_patterns_empty_stats() -> None:
    """Test get_problematic_patterns with empty execution stats."""
    monitor = PerformanceMonitor()

    # Add a pattern with no executions
    stats = PatternStats(pattern="empty_pattern")
    monitor.pattern_stats["empty_pattern"] = stats

    problematic = monitor.get_problematic_patterns()
    assert len(problematic) == 0


@pytest.mark.asyncio
async def test_get_problematic_patterns_high_timeout() -> None:
    """Test get_problematic_patterns with high timeout rate."""
    monitor = PerformanceMonitor()

    # Add patterns with different timeout rates
    for i in range(3):
        pattern = f"pattern_{i}"
        timeout_rate = 0.2 if i == 1 else 0.05  # pattern_1 has high timeout

        for j in range(10):
            await monitor.record_metric(
                pattern=pattern,
                execution_time=0.05,
                content_length=100,
                matched=False,
                timeout=(j < timeout_rate * 10),
            )

    problematic = monitor.get_problematic_patterns()

    # Should find pattern_1 as problematic
    assert len(problematic) == 1
    assert "pattern_1" in problematic[0]["pattern"]
    assert problematic[0]["issue"] == "high_timeout_rate"


@pytest.mark.asyncio
async def test_get_problematic_patterns_slow() -> None:
    """Test get_problematic_patterns with slow patterns."""
    monitor = PerformanceMonitor(slow_pattern_threshold=0.1)

    # Add slow and fast patterns
    patterns = [
        ("fast_pattern", 0.05),
        ("slow_pattern", 0.2),
        ("very_slow_pattern", 0.5),
    ]

    for pattern, exec_time in patterns:
        for _ in range(5):
            await monitor.record_metric(
                pattern=pattern,
                execution_time=exec_time,
                content_length=100,
                matched=False,
            )

    problematic = monitor.get_problematic_patterns()

    # Should find slow patterns as problematic
    assert len(problematic) == 2
    problematic_patterns = [p["pattern"] for p in problematic]
    assert any("slow_pattern" in p for p in problematic_patterns)
    assert any("very_slow_pattern" in p for p in problematic_patterns)
    assert all(p["issue"] == "consistently_slow" for p in problematic)


def test_get_summary_stats_empty() -> None:
    """Test get_summary_stats with no metrics."""
    monitor = PerformanceMonitor()

    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 0
    assert stats["avg_execution_time"] == 0.0
    assert stats["timeout_rate"] == 0.0
    assert stats["match_rate"] == 0.0


@pytest.mark.asyncio
async def test_get_summary_stats_with_data() -> None:
    """Test get_summary_stats with metrics."""
    monitor = PerformanceMonitor()

    # Add various metrics
    await monitor.record_metric("p1", 0.01, 100, True, False)
    await monitor.record_metric("p2", 0.02, 200, False, False)
    await monitor.record_metric("p3", 1.0, 300, False, True)  # Timeout
    await monitor.record_metric("p4", 0.03, 400, True, False)

    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 4
    assert stats["match_rate"] == 0.5  # 2 matches out of 4
    assert stats["timeout_rate"] == 0.25  # 1 timeout out of 4
    assert stats["total_patterns"] == 4


def test_register_anomaly_callback() -> None:
    """Test register_anomaly_callback."""
    monitor = PerformanceMonitor()

    def callback(anomaly: dict[str, Any]) -> None:
        pass  # pragma: no cover

    monitor.register_anomaly_callback(callback)
    assert len(monitor.anomaly_callbacks) == 1
    assert monitor.anomaly_callbacks[0] == callback


@pytest.mark.asyncio
async def test_clear_stats() -> None:
    """Test clear_stats method."""
    monitor = PerformanceMonitor()

    # Add some data
    await monitor.record_metric("pattern1", 0.01, 100, True)
    await monitor.record_metric("pattern2", 0.02, 200, False)

    assert len(monitor.pattern_stats) == 2
    assert len(monitor.recent_metrics) == 2

    # Clear stats
    await monitor.clear_stats()

    assert len(monitor.pattern_stats) == 0
    assert len(monitor.recent_metrics) == 0


@pytest.mark.asyncio
async def test_remove_pattern_stats() -> None:
    """Test remove_pattern_stats method."""
    monitor = PerformanceMonitor()

    # Add patterns
    await monitor.record_metric("pattern1", 0.01, 100, True)
    await monitor.record_metric("pattern2", 0.02, 200, False)

    assert len(monitor.pattern_stats) == 2

    # Remove one pattern
    await monitor.remove_pattern_stats("pattern1")

    assert len(monitor.pattern_stats) == 1
    assert "pattern1" not in monitor.pattern_stats
    assert "pattern2" in monitor.pattern_stats

    # Try to remove non-existent pattern (should not raise)
    await monitor.remove_pattern_stats("non_existent")


@pytest.mark.asyncio
async def test_get_slow_patterns() -> None:
    """Test get_slow_patterns method."""
    monitor = PerformanceMonitor()

    # Add patterns with different execution times
    patterns = [
        ("very_slow", 0.5),
        ("slow", 0.2),
        ("medium", 0.1),
        ("fast", 0.01),
        ("very_fast", 0.001),
    ]

    for pattern, exec_time in patterns:
        for _ in range(3):
            await monitor.record_metric(
                pattern=pattern,
                execution_time=exec_time,
                content_length=100,
                matched=False,
            )

    # Get top 3 slowest
    slow_patterns = monitor.get_slow_patterns(limit=3)

    assert len(slow_patterns) == 3
    # Check they're sorted by execution time
    assert "very_slow" in slow_patterns[0]["pattern"]
    assert "slow" in slow_patterns[1]["pattern"]
    assert "medium" in slow_patterns[2]["pattern"]


@pytest.mark.asyncio
async def test_metric_validation() -> None:
    """Test input validation in record_metric."""
    monitor = PerformanceMonitor()

    # Test with negative values (should be clamped to 0)
    await monitor.record_metric(
        pattern="test",
        execution_time=-1.0,  # Should become 0.0
        content_length=-100,  # Should become 0
        matched=False,
    )

    metric = monitor.recent_metrics[0]
    assert metric.execution_time == 0.0
    assert metric.content_length == 0


@pytest.mark.asyncio
async def test_pattern_stats_dataclass() -> None:
    """Test PatternStats dataclass functionality."""
    stats = PatternStats(pattern="test_pattern")

    assert stats.pattern == "test_pattern"
    assert stats.total_executions == 0
    assert stats.total_matches == 0
    assert stats.total_timeouts == 0
    assert stats.avg_execution_time == 0.0
    assert stats.max_execution_time == 0.0
    assert stats.min_execution_time == float("inf")
    assert isinstance(stats.recent_times, deque)
    assert stats.recent_times.maxlen == 100


def test_performance_metric_dataclass() -> None:
    """Test PerformanceMetric dataclass."""
    now = datetime.now(timezone.utc)
    metric = PerformanceMetric(
        pattern="test_pattern",
        execution_time=0.05,
        content_length=1000,
        timestamp=now,
        matched=True,
        timeout=False,
    )

    assert metric.pattern == "test_pattern"
    assert metric.execution_time == 0.05
    assert metric.content_length == 1000
    assert metric.timestamp == now
    assert metric.matched is True
    assert metric.timeout is False


@pytest.mark.asyncio
async def test_concurrent_access() -> None:
    """Test thread safety with concurrent metric recording."""
    monitor = PerformanceMonitor()

    async def record_metrics(pattern: str, count: int) -> None:
        for i in range(count):
            await monitor.record_metric(
                pattern=f"{pattern}_{i % 3}",
                execution_time=0.01 * (i % 5 + 1),
                content_length=100 * (i % 3 + 1),
                matched=i % 2 == 0,
            )

    # Run multiple concurrent tasks
    tasks = [
        record_metrics("task1", 10),
        record_metrics("task2", 10),
        record_metrics("task3", 10),
    ]

    await asyncio.gather(*tasks)

    # Verify data consistency
    assert len(monitor.recent_metrics) == 30
    total_patterns = len(monitor.pattern_stats)
    assert total_patterns > 0

    # Check that all patterns have valid stats
    for _, stats in monitor.pattern_stats.items():
        assert stats.total_executions > 0
        assert stats.max_execution_time >= stats.min_execution_time
        if stats.recent_times:
            assert stats.avg_execution_time > 0
