"""Middleware supporting modules.

This package contains event bus, metrics, and security check modules
that support the main SecurityMiddleware class.

The SecurityMiddleware class itself is defined in guard/middleware.py
and should be imported from there:
    from guard.middleware import SecurityMiddleware
"""

from guard.middleware_components.events import MetricsCollector, SecurityEventBus

__all__ = ["SecurityEventBus", "MetricsCollector"]
