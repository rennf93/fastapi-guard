from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

from guard._middleware_state import MiddlewareState, get_state, register_state
from guard.middleware import SecurityMiddleware


def _find_security_middleware(app: Any) -> SecurityMiddleware | None:
    user_middleware = getattr(app, "user_middleware", None)
    if not user_middleware:
        return None
    for entry in user_middleware:
        cls = getattr(entry, "cls", None)
        if cls is SecurityMiddleware:
            kwargs = getattr(entry, "kwargs", None)
            if kwargs is None:
                kwargs = getattr(entry, "options", {})
            try:
                return cls(app, **kwargs)
            except Exception:
                return None
    return None


def _register_state_from_middleware(middleware: SecurityMiddleware) -> None:
    register_state(
        middleware.config,
        MiddlewareState(
            security_pipeline=middleware.security_pipeline,
            composite_handler=middleware.handler_initializer.composite_handler,
            event_bus=middleware.event_bus,
            metrics_collector=middleware.metrics_collector,
            response_factory=middleware.response_factory,
            validator=middleware.validator,
            bypass_handler=middleware.bypass_handler,
            behavioral_processor=middleware.behavioral_processor,
            handler_initializer=middleware.handler_initializer,
            agent_handler=middleware.agent_handler,
        ),
    )


async def _warm_middleware_or_adopt(middleware: SecurityMiddleware) -> None:
    warm = get_state(middleware.config)
    if warm is not None:
        middleware._adopt_warm_state(warm)
        middleware.mark_initialized()
        return
    await middleware.initialize()
    middleware.mark_initialized()
    _register_state_from_middleware(middleware)


@asynccontextmanager
async def guard_lifespan(app: Any) -> AsyncIterator[None]:
    middleware = _find_security_middleware(app)
    if middleware is not None:
        await _warm_middleware_or_adopt(middleware)
    yield


def make_lifespan(
    existing_lifespan: Callable[[Any], AbstractAsyncContextManager[None]] | None = None,
) -> Callable[[Any], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def combined(app: Any) -> AsyncIterator[None]:
        middleware = _find_security_middleware(app)
        if middleware is not None:
            await _warm_middleware_or_adopt(middleware)
        if existing_lifespan is not None:
            async with existing_lifespan(app):
                yield
        else:
            yield

    return combined
