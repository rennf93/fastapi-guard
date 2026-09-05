from __future__ import annotations

import pytest

from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import SCENARIOS, Scenario, config_key

_ORDERED: list[Scenario] = sorted(SCENARIOS, key=lambda item: config_key(item.config))


@pytest.mark.parametrize(
    "live_scenario", _ORDERED, ids=[item.name for item in _ORDERED]
)
def test_scenario(live_scenario: Scenario, scenario_context: ScenarioContext) -> None:
    scenario_context.stack.restart_with(live_scenario.config)
    live_scenario.func(scenario_context)
