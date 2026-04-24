import pytest
from fastapi import FastAPI
from guard_core.core.events.composite_handler import CompositeAgentHandler

from guard import SecurityConfig, SecurityMiddleware


@pytest.mark.asyncio
async def test_event_bus_routes_through_composite_when_otel_enabled() -> None:
    config = SecurityConfig(
        enable_otel=True,
        otel_service_name="wire-test",
    )
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)

    await middleware.initialize()

    assert isinstance(middleware.event_bus.agent_handler, CompositeAgentHandler)
    assert isinstance(middleware.metrics_collector.agent_handler, CompositeAgentHandler)


@pytest.mark.asyncio
async def test_event_bus_routes_through_composite_when_logfire_enabled() -> None:
    config = SecurityConfig(
        enable_logfire=True,
        logfire_service_name="wire-test",
    )
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)

    await middleware.initialize()

    assert isinstance(middleware.event_bus.agent_handler, CompositeAgentHandler)
    assert isinstance(middleware.metrics_collector.agent_handler, CompositeAgentHandler)


@pytest.mark.asyncio
async def test_event_bus_stays_bare_when_no_telemetry_configured() -> None:
    config = SecurityConfig()
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)

    await middleware.initialize()

    assert not isinstance(middleware.event_bus.agent_handler, CompositeAgentHandler)
    assert not isinstance(
        middleware.metrics_collector.agent_handler, CompositeAgentHandler
    )


@pytest.mark.asyncio
async def testcontexts_use_the_post_initialize_event_bus() -> None:
    config = SecurityConfig(
        enable_otel=True,
        otel_service_name="wire-test",
    )
    app = FastAPI()
    middleware = SecurityMiddleware(app, config=config)

    await middleware.initialize()

    assert middleware.validator.context.event_bus is middleware.event_bus
    assert middleware.bypass_handler.context.event_bus is middleware.event_bus
    assert middleware.behavioral_processor.context.event_bus is middleware.event_bus
    assert (
        middleware.response_factory.context.metrics_collector
        is middleware.metrics_collector
    )
