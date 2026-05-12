from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig

from guard.lifespan import guard_lifespan
from guard.middleware import SecurityMiddleware


@pytest.fixture(autouse=True)
def _clear_singleton_redis_handlers() -> None:
    from guard_core.handlers.cloud_handler import cloud_handler
    from guard_core.handlers.ipban_handler import ip_ban_manager
    from guard_core.handlers.ratelimit_handler import rate_limit_handler
    from guard_core.handlers.suspatterns_handler import sus_patterns_handler

    ip_ban_manager.redis_handler = None
    sus_patterns_handler.redis_handler = None
    rate_limit_handler.redis_handler = None
    if cloud_handler._instance is not None:
        cloud_handler._instance.redis_handler = None


def test_lifespan_invokes_find_security_middleware_during_startup() -> None:
    config = SecurityConfig(enable_redis=False, lazy_init=True)
    app = FastAPI(lifespan=guard_lifespan)
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    from guard import lifespan as lifespan_module

    original = lifespan_module._find_security_middleware
    captured: list[object] = []

    def tracking(app_arg: object) -> object:
        result = original(app_arg)
        captured.append(result)
        return result

    with patch.object(lifespan_module, "_find_security_middleware", tracking):
        with TestClient(app, client=("127.0.0.1", 12345)) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json() == {"ok": True}

    assert captured, "guard_lifespan was not invoked during ASGI startup"
    assert isinstance(captured[0], SecurityMiddleware)


def test_no_lifespan_falls_back_to_lazy_init() -> None:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/health")
    async def health() -> dict[str, bool]:
        return {"ok": True}

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
