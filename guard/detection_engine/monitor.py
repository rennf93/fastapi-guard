import asyncio
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import mean, stdev
from typing import Any


@dataclass
class PerformanceMetric:
    """Represents a single performance measurement."""

    pattern: str
    execution_time: float
    content_length: int
    timestamp: datetime
    matched: bool
    timeout: bool = False


@dataclass
class PatternStats:
    """Statistics for a specific pattern."""

    pattern: str
    total_executions: int = 0
    total_matches: int = 0
    total_timeouts: int = 0
    avg_execution_time: float = 0.0
    max_execution_time: float = 0.0
    min_execution_time: float = float("inf")
    recent_times: deque[float] = field(default_factory=lambda: deque(maxlen=100))


class PerformanceMonitor:
    """
    Monitor pattern matching performance and alert on anomalies.
    """

    def __init__(
        self,
        anomaly_threshold: float = 3.0,
        slow_pattern_threshold: float = 0.1,
        history_size: int = 1000,
        max_tracked_patterns: int = 1000,
    ):
        """
        Initialize the PerformanceMonitor.

        Args:
            anomaly_threshold: Standard deviations from mean to consider anomaly
            slow_pattern_threshold: Execution time (seconds) to consider pattern slow
            history_size: Number of recent metrics to keep in history
            max_tracked_patterns: Maximum number of patterns to track
        """
        # Validate and bound parameters
        self.anomaly_threshold = max(1.0, min(10.0, float(anomaly_threshold)))
        self.slow_pattern_threshold = max(
            0.01, min(10.0, float(slow_pattern_threshold))
        )
        self.history_size = max(100, min(10000, int(history_size)))
        self.max_tracked_patterns = max(100, min(5000, int(max_tracked_patterns)))

        # Pattern statistics
        self.pattern_stats: dict[str, PatternStats] = {}

        # Recent metrics for anomaly detection
        self.recent_metrics: deque[PerformanceMetric] = deque(maxlen=history_size)

        # Anomaly callbacks
        self.anomaly_callbacks: list[Any] = []

        # Thread safety
        self._lock = asyncio.Lock()

    async def record_metric(
        self,
        pattern: str,
        execution_time: float,
        content_length: int,
        matched: bool,
        timeout: bool = False,
        agent_handler: Any = None,
        correlation_id: str | None = None,
    ) -> None:
        """
        Record a performance metric (thread-safe).

        Args:
            pattern: The pattern that was executed
            execution_time: Time taken to execute (seconds)
            content_length: Length of content checked
            matched: Whether the pattern matched
            timeout: Whether the execution timed out
            agent_handler: Optional agent handler for event logging
            correlation_id: Optional correlation ID for request tracking
        """
        # Sanitize pattern to prevent sensitive data leakage
        # Only store first 100 chars of pattern to avoid storing sensitive regex
        MAX_PATTERN_LENGTH = 100
        if len(pattern) > MAX_PATTERN_LENGTH:
            pattern = pattern[:MAX_PATTERN_LENGTH] + "...[truncated]"

        # Validate inputs to prevent data corruption
        execution_time = max(0.0, float(execution_time))
        content_length = max(0, int(content_length))

        # Create metric
        metric = PerformanceMetric(
            pattern=pattern,
            execution_time=execution_time,
            content_length=content_length,
            timestamp=datetime.now(timezone.utc),
            matched=matched,
            timeout=timeout,
        )

        async with self._lock:
            # Add to recent metrics
            self.recent_metrics.append(metric)

            # Update pattern statistics
            if pattern not in self.pattern_stats:
                # Enforce pattern limit
                if len(self.pattern_stats) >= self.max_tracked_patterns:
                    # Remove oldest pattern (FIFO)
                    oldest_pattern = next(iter(self.pattern_stats))
                    del self.pattern_stats[oldest_pattern]
                self.pattern_stats[pattern] = PatternStats(pattern=pattern)

            stats = self.pattern_stats[pattern]
            stats.total_executions += 1
            if matched:
                stats.total_matches += 1
            if timeout:
                stats.total_timeouts += 1

            if not timeout:
                stats.recent_times.append(execution_time)
                stats.max_execution_time = max(stats.max_execution_time, execution_time)
                stats.min_execution_time = min(stats.min_execution_time, execution_time)
                if stats.recent_times:
                    stats.avg_execution_time = mean(stats.recent_times)

        # Check for anomalies (outside lock to avoid blocking)
        await self._check_anomalies(metric, agent_handler, correlation_id)

    async def _check_anomalies(
        self,
        metric: PerformanceMetric,
        agent_handler: Any = None,
        correlation_id: str | None = None,
    ) -> None:
        """
        Check if the metric represents an anomaly.

        Args:
            metric: The metric to check
            agent_handler: Optional agent handler for event logging
            correlation_id: Optional correlation ID for request tracking
        """
        anomalies = []

        # Check for timeout
        if metric.timeout:
            anomalies.append(
                {
                    "type": "timeout",
                    "pattern": metric.pattern,
                    "content_length": metric.content_length,
                }
            )

        # Check for slow execution
        elif metric.execution_time > self.slow_pattern_threshold:
            anomalies.append(
                {
                    "type": "slow_execution",
                    "pattern": metric.pattern,
                    "execution_time": metric.execution_time,
                    "content_length": metric.content_length,
                }
            )

        # Check for statistical anomaly
        stats = self.pattern_stats.get(metric.pattern)
        if stats and len(stats.recent_times) >= 10:
            recent_times = list(stats.recent_times)
            if len(recent_times) > 1:
                avg_time = mean(recent_times)
                std_time = stdev(recent_times)
                if std_time > 0:
                    z_score = (metric.execution_time - avg_time) / std_time
                    if abs(z_score) > self.anomaly_threshold:
                        anomalies.append(
                            {
                                "type": "statistical_anomaly",
                                "pattern": metric.pattern,
                                "execution_time": metric.execution_time,
                                "z_score": z_score,
                                "avg_time": avg_time,
                                "std_time": std_time,
                            }
                        )

        # Send anomaly events to agent if available
        if agent_handler and anomalies:
            for anomaly in anomalies:
                try:
                    from datetime import datetime, timezone

                    # Import at runtime to avoid circular dependency
                    event_data = {
                        "timestamp": datetime.now(timezone.utc),
                        "event_type": f"pattern_anomaly_{anomaly['type']}",
                        "ip_address": "system",
                        "action_taken": "anomaly_detected",
                        "reason": f"Pattern performance anomaly: {anomaly['type']}",
                        "metadata": {
                            "component": "PerformanceMonitor",
                            "correlation_id": correlation_id,
                            **anomaly,
                        },
                    }
                    # Use duck typing to avoid import
                    event = type("SecurityEvent", (), event_data)()
                    await agent_handler.send_event(event)
                except Exception:
                    # Don't let agent errors affect monitoring
                    pass

        # Notify callbacks
        for anomaly in anomalies:
            # Sanitize anomaly data before passing to callbacks
            safe_anomaly = anomaly.copy()
            if "pattern" in safe_anomaly:
                # Only expose truncated pattern
                pattern = str(safe_anomaly["pattern"])
                safe_anomaly["pattern"] = (
                    pattern[:50] + "..." if len(pattern) > 50 else pattern
                )
                safe_anomaly["pattern_hash"] = str(hash(pattern))[:8]

            for callback in self.anomaly_callbacks:
                try:
                    # Pass sanitized data to callback
                    callback(safe_anomaly)
                except Exception as e:
                    # Log callback error but continue monitoring
                    if agent_handler:
                        try:
                            from datetime import datetime, timezone

                            event_data = {
                                "timestamp": datetime.now(timezone.utc),
                                "event_type": "detection_engine_callback_error",
                                "ip_address": "system",
                                "action_taken": "logged",
                                "reason": f"Anomaly callback failed: {str(e)}",
                                "metadata": {
                                    "component": "PerformanceMonitor",
                                    "correlation_id": correlation_id,
                                    "callback_error": str(e),
                                    "anomaly_type": safe_anomaly.get("type", "unknown"),
                                },
                            }
                            event = type("SecurityEvent", (), event_data)()
                            await agent_handler.send_event(event)
                        except Exception:
                            # Double failure - silently continue
                            pass

    def get_pattern_report(self, pattern: str) -> dict[str, Any] | None:
        """
        Get performance report for a specific pattern.

        Args:
            pattern: The pattern to report on

        Returns:
            Performance report dictionary or None if pattern not found
        """
        # Truncate pattern lookup to match storage
        MAX_PATTERN_LENGTH = 100
        if len(pattern) > MAX_PATTERN_LENGTH:
            pattern = pattern[:MAX_PATTERN_LENGTH] + "...[truncated]"

        stats = self.pattern_stats.get(pattern)
        if not stats:
            return None

        # Don't expose full pattern in reports
        safe_pattern = pattern[:50] + "..." if len(pattern) > 50 else pattern

        return {
            "pattern": safe_pattern,  # Truncated for security
            "pattern_hash": str(hash(pattern))[:8],  # Short hash for identification
            "total_executions": stats.total_executions,
            "total_matches": stats.total_matches,
            "total_timeouts": stats.total_timeouts,
            "match_rate": stats.total_matches / max(stats.total_executions, 1),
            "timeout_rate": stats.total_timeouts / max(stats.total_executions, 1),
            "avg_execution_time": round(stats.avg_execution_time, 4),  # Limit precision
            "max_execution_time": round(stats.max_execution_time, 4),
            "min_execution_time": round(
                stats.min_execution_time
                if stats.min_execution_time != float("inf")
                else 0.0,
                4,
            ),
        }

    def get_slow_patterns(self, limit: int = 10) -> list[dict[str, Any]]:
        """
        Get the slowest patterns by average execution time.

        Args:
            limit: Maximum number of patterns to return

        Returns:
            List of pattern reports sorted by average execution time
        """
        patterns_with_times = [
            (stats.avg_execution_time, pattern)
            for pattern, stats in self.pattern_stats.items()
            if stats.recent_times
        ]

        patterns_with_times.sort(reverse=True)

        reports = []
        for _, pattern in patterns_with_times[:limit]:
            report = self.get_pattern_report(pattern)
            if report is not None:
                reports.append(report)
        return reports

    def get_problematic_patterns(self) -> list[dict[str, Any]]:
        """
        Get patterns with high timeout rates or consistently slow performance.

        Returns:
            List of problematic pattern reports
        """
        problematic = []

        for pattern, stats in self.pattern_stats.items():
            if stats.total_executions == 0:
                continue

            timeout_rate = stats.total_timeouts / stats.total_executions

            # High timeout rate
            if timeout_rate > 0.1:  # More than 10% timeouts
                report = self.get_pattern_report(pattern)
                if report:
                    report["issue"] = "high_timeout_rate"
                    problematic.append(report)

            # Consistently slow
            elif stats.avg_execution_time > self.slow_pattern_threshold:
                report = self.get_pattern_report(pattern)
                if report:
                    report["issue"] = "consistently_slow"
                    problematic.append(report)

        return problematic

    def get_summary_stats(self) -> dict[str, Any]:
        """
        Get overall performance summary.

        Returns:
            Summary statistics dictionary
        """
        if not self.recent_metrics:
            return {
                "total_executions": 0,
                "avg_execution_time": 0.0,
                "timeout_rate": 0.0,
                "match_rate": 0.0,
            }

        recent_times = [m.execution_time for m in self.recent_metrics if not m.timeout]
        timeouts = sum(1 for m in self.recent_metrics if m.timeout)
        matches = sum(1 for m in self.recent_metrics if m.matched)

        return {
            "total_executions": len(self.recent_metrics),
            "avg_execution_time": mean(recent_times) if recent_times else 0.0,
            "max_execution_time": max(recent_times) if recent_times else 0.0,
            "min_execution_time": min(recent_times) if recent_times else 0.0,
            "timeout_rate": timeouts / len(self.recent_metrics),
            "match_rate": matches / len(self.recent_metrics),
            "total_patterns": len(self.pattern_stats),
        }

    def register_anomaly_callback(self, callback: Any) -> None:
        """
        Register a callback for anomaly notifications.

        Args:
            callback: Function to call when anomaly detected
        """
        self.anomaly_callbacks.append(callback)

    async def clear_stats(self) -> None:
        """Clear all performance statistics (thread-safe)."""
        async with self._lock:
            self.pattern_stats.clear()
            self.recent_metrics.clear()

    async def remove_pattern_stats(self, pattern: str) -> None:
        """
        Remove statistics for a specific pattern (thread-safe).

        Args:
            pattern: The pattern to remove stats for
        """
        async with self._lock:
            if pattern in self.pattern_stats:
                del self.pattern_stats[pattern]
