"""Context object for security check dependencies.

This module provides a CheckContext dataclass that encapsulates all shared
dependencies needed by security checks, enabling better testing and
decoupling from the middleware class.
"""

from dataclasses import dataclass
from logging import Logger
from typing import Any

from guard.core.events import SecurityEventBus
from guard.models import SecurityConfig


@dataclass
class CheckContext:
    """
    Context object containing shared dependencies for security checks.

    This context is injected into all check classes to provide access to
    configuration, logging, event bus, and handler instances. It serves as
    a clean abstraction layer that decouples checks from the middleware.

    Attributes:
        config: Security configuration with all settings and rules
        logger: Python logger for security event logging
        event_bus: Event bus for publishing security events to agents
        middleware: Reference to parent SecurityMiddleware (will be phased out)

    Example:
        >>> context = CheckContext(
        ...     config=security_config,
        ...     logger=logger,
        ...     event_bus=event_bus,
        ...     middleware=middleware_instance
        ... )
        >>> handler = context.get_handler("rate_limit")
    """

    # Core dependencies
    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus

    # Middleware reference for methods not yet extracted
    middleware: Any  # SecurityMiddleware - will be removed as extraction completes

    def get_handler(self, name: str) -> Any:
        """
        Get handler by name for dynamic access.

        This method provides a way to access handlers that are still
        attached to the middleware during the transition period.

        Args:
            name: Handler name (e.g., "rate_limit", "ip_ban", "redis")

        Returns:
            Handler instance if found, None otherwise

        Example:
            >>> rate_handler = context.get_handler("rate_limit")
            >>> redis_handler = context.get_handler("redis")
        """
        handler_attr = f"{name}_handler"
        return getattr(self.middleware, handler_attr, None)
