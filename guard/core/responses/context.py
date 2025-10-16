# guard/core/responses/context.py
from dataclasses import dataclass
from logging import Logger
from typing import Any

from guard.core.events import MetricsCollector
from guard.decorators.base import BaseSecurityDecorator
from guard.models import SecurityConfig


@dataclass
class ResponseContext:
    """
    Context for response creation and processing.

    Provides all dependencies needed for response factory operations
    through clean dependency injection pattern.
    """

    config: SecurityConfig
    logger: Logger
    metrics_collector: MetricsCollector

    # Optional dependencies
    agent_handler: Any | None = None
    guard_decorator: BaseSecurityDecorator | None = None
