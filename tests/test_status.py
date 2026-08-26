import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from guard_core.core.initialization import HandlerInitializer
from guard_core.models import SecurityConfig
from starlette.applications import Starlette

from guard.middleware import SecurityMiddleware
from guard.status import add_status_route

requires_initialization_status = pytest.mark.skipif(
    not hasattr(HandlerInitializer, "get_initialization_status"),
    reason="requires guard-core>=3.8.0 (HandlerInitializer.get_initialization_status)",
)


def _app_with_middleware() -> FastAPI:
    config = SecurityConfig(enable_redis=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    return app


def test_status_route_not_registered_without_opt_in() -> None:
    app = _app_with_middleware()

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        response = client.get("/_guard/status")

    assert response.status_code == 404


def test_add_status_route_registers_default_path() -> None:
    app = _app_with_middleware()
    add_status_route(app)

    assert any(getattr(r, "path", None) == "/_guard/status" for r in app.routes)


def test_add_status_route_registers_custom_path() -> None:
    app = _app_with_middleware()
    add_status_route(app, path="/internal/guard-status")

    paths = [getattr(r, "path", None) for r in app.routes]
    assert "/internal/guard-status" in paths
    assert "/_guard/status" not in paths


def test_add_status_route_raises_without_middleware() -> None:
    app = FastAPI()

    with pytest.raises(RuntimeError):
        add_status_route(app)


@requires_initialization_status
def test_status_route_returns_serialized_status() -> None:
    app = _app_with_middleware()
    add_status_route(app)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        response = client.get("/_guard/status")

    assert response.status_code == 200
    body = response.json()
    assert "cloud_providers" in body
    assert "geo_ip" in body


def test_add_status_route_dependency_failure_rejects() -> None:
    app = _app_with_middleware()

    def deny() -> None:
        raise HTTPException(status_code=401)

    add_status_route(app, dependencies=[Depends(deny)])

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        response = client.get("/_guard/status")

    assert response.status_code == 401


@requires_initialization_status
def test_add_status_route_dependency_success_returns_status_json() -> None:
    app = _app_with_middleware()

    def allow() -> None:
        return None

    add_status_route(app, dependencies=[Depends(allow)])

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        response = client.get("/_guard/status")

    assert response.status_code == 200
    body = response.json()
    assert "cloud_providers" in body


def test_add_status_route_on_plain_starlette_app_uses_add_route() -> None:
    config = SecurityConfig(enable_redis=False)
    app = Starlette()
    app.add_middleware(SecurityMiddleware, config=config)
    add_status_route(app)

    assert any(getattr(r, "path", None) == "/_guard/status" for r in app.routes)


def test_add_status_route_starlette_app_with_dependencies_raises_type_error() -> None:
    config = SecurityConfig(enable_redis=False)
    app = Starlette()
    app.add_middleware(SecurityMiddleware, config=config)

    def deny() -> None:
        raise HTTPException(status_code=401)

    with pytest.raises(TypeError):
        add_status_route(app, dependencies=[Depends(deny)])


def test_add_status_route_starlette_app_with_none_dependencies_still_registers() -> (
    None
):
    config = SecurityConfig(enable_redis=False)
    app = Starlette()
    app.add_middleware(SecurityMiddleware, config=config)
    add_status_route(app, dependencies=None)

    assert any(getattr(r, "path", None) == "/_guard/status" for r in app.routes)
