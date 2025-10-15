"""Middleware events package.

This package provides event bus and metrics collection for the middleware.
"""

from guard.core.events.metrics import MetricsCollector
from guard.core.events.middleware_events import SecurityEventBus

__all__ = ["SecurityEventBus", "MetricsCollector"]
