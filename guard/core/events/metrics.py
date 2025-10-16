# guard/core/events/metrics.py
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

from guard.models import SecurityConfig


class MetricsCollector:
    """Centralized metrics collection for middleware."""

    def __init__(self, agent_handler: Any, config: SecurityConfig):
        """
        Initialize the MetricsCollector.

        Args:
            agent_handler: The agent handler instance for sending metrics
            config: Security configuration
        """
        self.agent_handler = agent_handler
        self.config = config
        self.logger = logging.getLogger(__name__)

    async def send_metric(
        self, metric_type: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        """
        Send performance metric to agent.

        Args:
            metric_type: Type of metric (e.g., "response_time", "request_count")
            value: Metric value
            tags: Optional tags/labels for the metric
        """
        if self.agent_handler and self.config.agent_enable_metrics:
            try:
                from guard_agent import SecurityMetric

                metric = SecurityMetric(
                    timestamp=datetime.now(timezone.utc),
                    metric_type=metric_type,
                    value=value,
                    tags=tags or {},
                )
                await self.agent_handler.send_metric(metric)
            except Exception as e:
                # Don't let agent errors break middleware functionality
                self.logger.error(f"Failed to send metric to agent: {e}")

    async def collect_request_metrics(
        self, request: Request, response_time: float, status_code: int
    ) -> None:
        """
        Collect request metrics for agent.

        Args:
            request: The incoming request
            response_time: Time taken to process the request
            status_code: HTTP status code of the response
        """
        if not self.agent_handler or not self.config.agent_enable_metrics:
            return

        endpoint = str(request.url.path)
        method = request.method

        # Response time metric
        await self.send_metric(
            "response_time",
            response_time,
            {"endpoint": endpoint, "method": method, "status": str(status_code)},
        )

        # Request count metric
        await self.send_metric(
            "request_count", 1.0, {"endpoint": endpoint, "method": method}
        )

        # Error rate metric (for non-2xx responses)
        if status_code >= 400:
            await self.send_metric(
                "error_rate",
                1.0,
                {"endpoint": endpoint, "method": method, "status": str(status_code)},
            )
