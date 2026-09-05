from __future__ import annotations

import importlib
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.live_smoke.driver import (
    STACK_DIR,
    ScenarioContext,
    Stack,
    make_agent_client,
    make_http_client,
    make_otlp_client,
    make_redis_client,
)

_HERE = Path(__file__).resolve().parent


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "live_smoke: end-to-end scenarios against the live Docker stack "
        "(requires LIVE_SMOKE=1 and Docker)",
    )
    importlib.import_module("tests.live_smoke.scenarios")


def pytest_ignore_collect(collection_path: Path, config: pytest.Config) -> bool | None:
    if os.environ.get("LIVE_SMOKE") == "1":
        return None
    try:
        collection_path.relative_to(_HERE)
    except ValueError:
        return None
    return True


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    ours: list[pytest.Item] = []
    others: list[pytest.Item] = []
    for item in items:
        try:
            item.path.relative_to(_HERE)
        except ValueError:
            others.append(item)
            continue
        item.add_marker(pytest.mark.live_smoke)
        ours.append(item)

    ours.sort(key=lambda item: item.path.name == "test_completeness.py")
    items[:] = others + ours


def _check_preconditions() -> None:
    wheels = list((STACK_DIR / "wheels").glob("*.whl"))
    if not wheels:
        pytest.fail(
            "no fastapi-guard wheel in tests/live_smoke/stack/wheels/; run "
            "`uv build --wheel --out-dir tests/live_smoke/stack/wheels` first. "
            "See `make live-smoke`.",
            pytrace=False,
        )
    if not (STACK_DIR / "app" / "security.py").is_file():
        pytest.fail(
            "tests/live_smoke/stack/app/ is missing; run "
            "`python tests/live_smoke/copy_example_app.py` then "
            "`python tests/live_smoke/patch_example_config.py` first. "
            "See `make live-smoke`.",
            pytrace=False,
        )


@pytest.fixture(scope="session")
def stack() -> Iterator[Stack]:
    _check_preconditions()
    instance = Stack()
    instance.up()
    try:
        yield instance
    finally:
        instance.down()


@pytest.fixture(scope="session")
def scenario_context(stack: Stack) -> Iterator[ScenarioContext]:
    client = make_http_client()
    agent = make_agent_client()
    redis_client = make_redis_client()
    otlp = make_otlp_client()
    try:
        yield ScenarioContext(
            stack=stack, client=client, agent=agent, redis=redis_client, otlp=otlp
        )
    finally:
        client.close()
        agent.close()
        redis_client.close()
        otlp.close()
