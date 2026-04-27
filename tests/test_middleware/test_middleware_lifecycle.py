import asyncio
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from guard_core.models import SecurityConfig

from guard.middleware import SecurityMiddleware


@pytest.fixture
def otel_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=False,
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
    pre_init_composite = mw.handler_initializer.composite_handler
    assert pre_init_composite is None

    await mw._ensure_initialized()

    composite = mw.handler_initializer.composite_handler
    assert composite is not None
    assert mw.agent_handler is composite


async def test_initialize_is_noop_when_no_telemetry_enabled() -> None:
    config = SecurityConfig(enable_redis=False)
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


async def test_ensure_initialized_fast_path_skips_lock_when_already_initialized(
    otel_config: SecurityConfig,
) -> None:
    app = FastAPI()
    mw = SecurityMiddleware(app, config=otel_config)
    await mw._ensure_initialized()
    assert mw._initialized is True

    cast(Any, mw).initialize = MagicMock(
        side_effect=AssertionError("should not be called again")
    )
    await mw._ensure_initialized()
    await mw._ensure_initialized()


async def test_ensure_initialized_double_check_after_lock(
    otel_config: SecurityConfig,
) -> None:
    app = FastAPI()
    mw = SecurityMiddleware(app, config=otel_config)

    original = mw.initialize

    async def slow_init() -> None:
        await asyncio.sleep(0.02)
        await original()

    cast(Any, mw).initialize = slow_init

    tasks = [asyncio.create_task(mw._ensure_initialized()) for _ in range(5)]
    await asyncio.gather(*tasks)

    assert mw._initialized is True


async def test_behavior_tracker_threaded_through_behavioral_context() -> None:
    enriched_config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="0123456789",
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
