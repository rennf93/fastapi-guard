import asyncio
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from guard_core.models import SecurityConfig

from guard.middleware import SecurityMiddleware


@pytest.fixture
def otel_config() -> SecurityConfig:
    return SecurityConfig(
        enable_otel=True,
        otel_service_name="guard-test",
        otel_exporter_endpoint="http://localhost:4318",
    )


async def test_initialize_runs_once_on_first_dispatch(
    otel_config: SecurityConfig,
) -> None:
    app = FastAPI()
    mw = SecurityMiddleware(app, config=otel_config)
    assert mw._initialized is False

    calls = 0
    original = mw.initialize

    async def counting_init() -> None:
        nonlocal calls
        calls += 1
        await original()

    with patch.object(mw, "initialize", side_effect=counting_init):
        await mw._ensure_initialized()
        await mw._ensure_initialized()
        await mw._ensure_initialized()

    assert calls == 1
    assert mw._initialized is True


async def test_initialize_rebinds_agent_handler_to_composite(
    otel_config: SecurityConfig,
) -> None:
    app = FastAPI()
    mw = SecurityMiddleware(app, config=otel_config)
    assert mw.handler_initializer.composite_handler is None

    await mw._ensure_initialized()

    assert mw.handler_initializer.composite_handler is not None
    assert mw.agent_handler is mw.handler_initializer.composite_handler


async def test_initialize_is_noop_when_no_telemetry_enabled() -> None:
    config = SecurityConfig()
    app = FastAPI()
    mw = SecurityMiddleware(app, config=config)

    await mw._ensure_initialized()

    assert mw._initialized is True
    assert mw.handler_initializer.composite_handler is None
    assert mw.agent_handler is None


async def test_concurrent_first_dispatch_triggers_single_init(
    otel_config: SecurityConfig,
) -> None:
    app = FastAPI()
    mw = SecurityMiddleware(app, config=otel_config)

    calls = 0
    original = mw.initialize

    async def counting_init() -> None:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.01)
        await original()

    with patch.object(mw, "initialize", side_effect=counting_init):
        await asyncio.gather(*[mw._ensure_initialized() for _ in range(10)])

    assert calls == 1


async def test_behavior_tracker_threaded_through_behavioral_context() -> None:
    enriched_config = SecurityConfig(
        enable_agent=True,
        agent_api_key="k",
        agent_project_id="p",
        enable_enrichment=True,
        enable_otel=True,
        otel_exporter_endpoint="http://localhost:4318",
    )
    app = FastAPI()
    mw = SecurityMiddleware(app, config=enriched_config)
    await mw._ensure_initialized()

    assert mw.handler_initializer.behavior_tracker is not None
    assert (
        mw.behavioral_processor.context.behavior_tracker
        is mw.handler_initializer.behavior_tracker
    )
