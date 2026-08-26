import asyncio
from collections.abc import MutableMapping
from typing import Any

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from guard_core.handlers import ratelimit_handler as ratelimit_handler_module
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.models import SecurityConfig
from starlette.exceptions import WebSocketException
from starlette.websockets import WebSocketDisconnect

from guard.middleware import SecurityMiddleware
from guard.websocket import _WebSocketGuardRequest, guard_websocket


@pytest.fixture(autouse=True)
def _reset_by_ip_rate_limit_state() -> None:
    ratelimit_handler_module._by_ip_request_timestamps.clear()
    ratelimit_handler_module._by_ip_autoban_counts.clear()


def _app_with_websocket(config: SecurityConfig) -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")
        await websocket.close()

    return app


def _client_less_websocket(app: FastAPI) -> WebSocket:
    async def receive() -> dict[str, Any]:
        raise NotImplementedError

    async def send(message: MutableMapping[str, Any]) -> None:
        raise NotImplementedError

    scope = {
        "type": "websocket",
        "path": "/ws",
        "headers": [],
        "query_string": b"",
        "app": app,
    }
    return WebSocket(scope, receive=receive, send=send)


def test_guard_websocket_rejects_banned_ip_before_accept() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = _app_with_websocket(config)
    asyncio.run(ip_ban_manager.ban_ip("203.0.113.50", duration=60, reason="test"))

    with TestClient(app, client=("203.0.113.50", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008


def test_guard_websocket_accepts_allowed_ip() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"


def test_guard_websocket_rejects_once_rate_limit_exhausted() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008


def test_guard_websocket_honours_forwarded_header_behind_trusted_proxy() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        trusted_proxies=("10.0.0.1",),
        blacklist=("203.0.113.9",),
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("10.0.0.1", 5000)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(
                "/ws", headers={"X-Forwarded-For": "203.0.113.9"}
            ):
                pass

    assert exc_info.value.code == 1008


def test_guard_websocket_requires_security_middleware_registered() -> None:
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with pytest.raises(RuntimeError):
            with client.websocket_connect("/ws"):
                pass


async def test_guard_websocket_rejects_client_less_socket_by_default() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = _app_with_websocket(config)
    websocket = _client_less_websocket(app)

    with pytest.raises(WebSocketException) as exc_info:
        await guard_websocket(websocket)

    assert exc_info.value.code == 1008


async def test_guard_websocket_allows_client_less_socket_when_not_fail_secure() -> None:
    config = SecurityConfig(
        enable_redis=False, enable_penetration_detection=False, fail_secure=False
    )
    app = _app_with_websocket(config)
    websocket = _client_less_websocket(app)

    await guard_websocket(websocket)


async def test_websocket_guard_request_exposes_the_full_protocol_surface() -> None:
    async def receive() -> dict[str, Any]:
        raise NotImplementedError

    async def send(message: MutableMapping[str, Any]) -> None:
        raise NotImplementedError

    scope = {
        "type": "websocket",
        "path": "/ws",
        "headers": [(b"host", b"testserver")],
        "query_string": b"token=abc",
        "scheme": "ws",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "app": FastAPI(),
    }
    websocket = WebSocket(scope, receive=receive, send=send)
    guard_request = _WebSocketGuardRequest(websocket)

    assert guard_request.url_path == "/ws"
    assert guard_request.url_scheme == "ws"
    assert guard_request.url_full == "ws://testserver/ws?token=abc"
    assert guard_request.url_replace_scheme("wss").startswith("wss://")
    assert guard_request.method == "WEBSOCKET"
    assert guard_request.client_host == "127.0.0.1"
    assert guard_request.query_params["token"] == "abc"
    assert await guard_request.body() == b""
    assert guard_request.scope is scope
