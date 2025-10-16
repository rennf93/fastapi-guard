# guard/core/bypass/context.py
from dataclasses import dataclass
from logging import Logger

from guard.core.events import SecurityEventBus
from guard.core.responses import ErrorResponseFactory
from guard.core.routing import RouteConfigResolver
from guard.core.validation import RequestValidator
from guard.models import SecurityConfig


@dataclass
class BypassContext:
    """Context for bypass handler operations."""

    config: SecurityConfig
    logger: Logger
    event_bus: SecurityEventBus
    route_resolver: RouteConfigResolver
    response_factory: ErrorResponseFactory
    validator: RequestValidator
