# guard/middleware_components/validation/context.py
"""Context for request validation operations."""

from dataclasses import dataclass
from logging import Logger

from guard.middleware_components.events import SecurityEventBus
from guard.models import SecurityConfig


@dataclass
class ValidationContext:
    """Context for request validation operations."""

    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
