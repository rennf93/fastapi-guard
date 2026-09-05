from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tests.live_smoke.driver import ScenarioContext

ScenarioFunc = Callable[["ScenarioContext"], None]


@dataclass(frozen=True)
class Scenario:
    name: str
    func: ScenarioFunc
    covers: frozenset[str]
    config: dict[str, Any] = field(default_factory=dict)


SCENARIOS: list[Scenario] = []


def scenario(
    *, covers: set[str], config: dict[str, Any] | None = None
) -> Callable[[ScenarioFunc], ScenarioFunc]:
    def register(func: ScenarioFunc) -> ScenarioFunc:
        SCENARIOS.append(
            Scenario(
                name=func.__name__,
                func=func,
                covers=frozenset(covers),
                config=dict(config or {}),
            )
        )
        return func

    return register


def config_key(config: dict[str, Any]) -> str:
    import json

    return json.dumps(config, sort_keys=True, default=str)
