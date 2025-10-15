"""Middleware events package.

This package provides event bus and metrics collection for the middleware.
"""

from guard.middleware_components.events.metrics import MetricsCollector
from guard.middleware_components.events.middleware_events import SecurityEventBus

__all__ = ["SecurityEventBus", "MetricsCollector"]
