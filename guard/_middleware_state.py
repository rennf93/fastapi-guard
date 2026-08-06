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


_STATE_REGISTRY: dict[tuple[int, int], MiddlewareState] = {}


def _state_key(config: Any, decorator: Any) -> tuple[int, int]:
    return (id(config), id(decorator))


def get_state(config: Any, decorator: Any = None) -> MiddlewareState | None:
    return _STATE_REGISTRY.get(_state_key(config, decorator))


def register_state(config: Any, decorator: Any, state: MiddlewareState) -> None:
    _STATE_REGISTRY[_state_key(config, decorator)] = state


def clear_state_registry() -> None:
    _STATE_REGISTRY.clear()
