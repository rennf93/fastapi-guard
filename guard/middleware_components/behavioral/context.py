# guard/middleware_components/behavioral/context.py
"""Context for behavioral rule processing."""

from dataclasses import dataclass
from logging import Logger

from guard.decorators.base import BaseSecurityDecorator
from guard.middleware_components.events import SecurityEventBus
from guard.models import SecurityConfig


@dataclass
class BehavioralContext:
    """Context for behavioral rule processing."""

    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    guard_decorator: BaseSecurityDecorator | None
