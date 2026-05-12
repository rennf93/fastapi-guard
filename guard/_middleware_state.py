from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class MiddlewareState:
    security_pipeline: Any
    composite_handler: Any
    event_bus: Any
    metrics_collector: Any
    response_factory: Any
    validator: Any
    bypass_handler: Any
    behavioral_processor: Any
    handler_initializer: Any
    agent_handler: Any


_STATE_REGISTRY: dict[int, MiddlewareState] = {}


def get_state(config: Any) -> MiddlewareState | None:
    return _STATE_REGISTRY.get(id(config))


def register_state(config: Any, state: MiddlewareState) -> None:
    _STATE_REGISTRY[id(config)] = state


def clear_state_registry() -> None:
    _STATE_REGISTRY.clear()
