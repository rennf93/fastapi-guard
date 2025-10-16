# guard/core/behavioral/context.py
from dataclasses import dataclass
from logging import Logger

from guard.core.events import SecurityEventBus
from guard.decorators.base import BaseSecurityDecorator
from guard.models import SecurityConfig


@dataclass
class BehavioralContext:
    """Context for behavioral rule processing."""

    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    guard_decorator: BaseSecurityDecorator | None
