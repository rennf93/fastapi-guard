from __future__ import annotations

from guard_core.core.events.event_types import CHECK_NAME_VALUES
from guard_core.decorators import SecurityDecorator
from guard_core.models import SecurityConfig

from tests.live_smoke.registry import SCENARIOS


def _decorator_method_names() -> set[str]:
    return {
        name
        for name in dir(SecurityDecorator)
        if not name.startswith("_") and callable(getattr(SecurityDecorator, name))
    }


def _required_names() -> set[str]:
    return (
        set(SecurityConfig.model_fields)
        | _decorator_method_names()
        | set(CHECK_NAME_VALUES)
    )


def test_every_field_method_and_check_name_has_a_live_scenario() -> None:
    covered: set[str] = set()
    for item in SCENARIOS:
        covered |= item.covers

    missing = sorted(_required_names() - covered)
    assert not missing, (
        "no live-smoke scenario covers these SecurityConfig fields / "
        "SecurityDecorator methods / pipeline check names "
        f"({len(missing)} total):\n" + "\n".join(f"  - {name}" for name in missing)
    )
