# guard/middleware_components/bypass/context.py
"""Context for bypass handler operations."""

from dataclasses import dataclass
from logging import Logger

from guard.middleware_components.events import SecurityEventBus
from guard.middleware_components.responses import ErrorResponseFactory
from guard.middleware_components.routing import RouteConfigResolver
from guard.middleware_components.validation import RequestValidator
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
