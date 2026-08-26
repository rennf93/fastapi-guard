import asyncio
import logging
from collections.abc import MutableMapping
from typing import Any

import pytest
from fastapi import Depends, FastAPI, WebSocket
from fastapi.testclient import TestClient
from guard_core import check_rate_limit_by_ip as real_check_rate_limit_by_ip
from guard_core.exceptions import GuardRedisError
from guard_core.handlers import ratelimit_handler as ratelimit_handler_module
from guard_core.handlers.ipban_handler import ip_ban_manager
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from starlette.exceptions import WebSocketException
from starlette.websockets import WebSocketDisconnect

from guard.middleware import SecurityMiddleware
from guard.websocket import (
    WS_CLOSE_REASONS,
    WebSocketCloseReason,
    _WebSocketGuardRequest,
    guard_websocket,
    make_guard_websocket,
)


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
    assert exc_info.value.reason == "IP banned"


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
    assert exc_info.value.reason == "Rate limit exceeded"


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
    assert exc_info.value.reason == "IP not allowed"


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
    assert exc_info.value.reason == "Client address could not be determined"


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


async def _raise_ip_ban_redis_error(ip: str) -> bool:
    raise GuardRedisError(503, "Redis operation failed")


async def _raise_rate_limit_redis_error(*args: Any, **kwargs: Any) -> bool:
    raise GuardRedisError(503, "Redis operation failed")


def test_guard_websocket_skips_ip_ban_check_when_redis_fail_open(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(ip_ban_manager, "is_ip_banned", _raise_ip_ban_redis_error)
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        redis_fail_open=True,
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.WARNING):
        with TestClient(app, client=("127.0.0.1", 12345)) as client:
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_text() == "connected"

    assert any(
        "ip_ban_manager.is_ip_banned" in r.message and "failing open" in r.message
        for r in caplog.records
    )


def test_guard_websocket_closes_with_1013_when_ip_ban_check_fails_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ip_ban_manager, "is_ip_banned", _raise_ip_ban_redis_error)
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        redis_fail_open=False,
        fail_secure=True,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1013
    assert exc_info.value.reason == "Security check failed"


def test_guard_websocket_skips_ip_ban_check_when_not_fail_secure(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(ip_ban_manager, "is_ip_banned", _raise_ip_ban_redis_error)
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        redis_fail_open=False,
        fail_secure=False,
    )
    app = _app_with_websocket(config)

    with caplog.at_level(logging.ERROR):
        with TestClient(app, client=("127.0.0.1", 12345)) as client:
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_text() == "connected"

    assert any("ip_ban_manager.is_ip_banned" in r.message for r in caplog.records)


def test_guard_websocket_closes_with_1013_when_rate_limit_check_fails_secure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "guard.websocket.check_rate_limit_by_ip", _raise_rate_limit_redis_error
    )
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        redis_fail_open=False,
        fail_secure=True,
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1013
    assert exc_info.value.reason == "Security check failed"


def test_ws_close_reasons_pins_the_exact_code_reason_pair_set() -> None:
    assert set(WS_CLOSE_REASONS) == {
        WebSocketCloseReason(1008, "IP banned"),
        WebSocketCloseReason(1008, "IP not allowed"),
        WebSocketCloseReason(1008, "Rate limit exceeded"),
        WebSocketCloseReason(1008, "Client address could not be determined"),
        WebSocketCloseReason(1013, "Security check failed"),
    }
    assert len(WS_CLOSE_REASONS) == 5


def test_guard_websocket_skips_rate_limit_when_client_is_whitelisted() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
        whitelist=("127.0.0.1",),
    )
    app = _app_with_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        for _ in range(3):
            with client.websocket_connect("/ws") as websocket:
                assert websocket.receive_text() == "connected"


def _app_with_factory_websocket(config: SecurityConfig) -> FastAPI:
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(make_guard_websocket(config))
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    return app


def test_make_guard_websocket_enforces_ban_list_without_middleware() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = _app_with_factory_websocket(config)
    asyncio.run(ip_ban_manager.ban_ip("203.0.113.61", duration=60, reason="test"))

    with TestClient(app, client=("203.0.113.61", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "IP banned"


def test_make_guard_websocket_enforces_allow_list_without_middleware() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        blacklist=("203.0.113.62",),
    )
    app = _app_with_factory_websocket(config)

    with TestClient(app, client=("203.0.113.62", 12345)) as client:
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "IP not allowed"


def test_make_guard_websocket_enforces_rate_limit_without_middleware() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
    )
    app = _app_with_factory_websocket(config)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"


def test_guard_websocket_still_raises_without_middleware_beside_factory_route() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = FastAPI()

    @app.websocket("/factory")
    async def factory_endpoint(
        websocket: WebSocket, _: None = Depends(make_guard_websocket(config))
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    @app.websocket("/legacy")
    async def legacy_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/factory") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(RuntimeError):
            with client.websocket_connect("/legacy"):
                pass


def test_guard_websocket_sets_client_ip_on_state_for_direct_peer() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    captured: dict[str, str] = {}

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        captured["client_ip"] = websocket.state.client_ip
        await websocket.send_text("connected")

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

    assert captured["client_ip"] == "127.0.0.1"


def test_guard_websocket_sets_client_ip_on_state_for_trusted_proxy_chain() -> None:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        trusted_proxies=("10.0.0.1",),
    )
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)
    captured: dict[str, str] = {}

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        captured["client_ip"] = websocket.state.client_ip
        await websocket.send_text("connected")

    with TestClient(app, client=("10.0.0.1", 5000)) as client:
        with client.websocket_connect(
            "/ws", headers={"X-Forwarded-For": "203.0.113.9"}
        ) as websocket:
            assert websocket.receive_text() == "connected"

    assert captured["client_ip"] == "203.0.113.9"


async def test_guard_websocket_falls_back_to_memory_when_manager_not_initialized() -> (
    None
):
    RedisManager._instance = None
    config = SecurityConfig(
        enable_redis=True,
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
    assert exc_info.value.reason == "Rate limit exceeded"
    final_instance: RedisManager | None = RedisManager._instance
    assert final_instance is not None
    assert final_instance._redis is None


async def test_guard_websocket_reuses_the_middlewares_redis_manager(
    security_config_redis: SecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    security_config_redis.enable_redis = True
    security_config_redis.enable_penetration_detection = False
    security_config_redis.enable_rate_limiting = True
    security_config_redis.rate_limit = 1
    security_config_redis.rate_limit_window = 60
    security_config_redis.whitelist = ()
    security_config_redis.blocked_countries = frozenset()
    config = security_config_redis

    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(guard_websocket)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    captured: dict[str, Any] = {}

    async def _capturing_check_rate_limit_by_ip(*args: Any, **kwargs: Any) -> bool:
        captured["redis_handler"] = kwargs.get("redis_handler")
        return await real_check_rate_limit_by_ip(*args, **kwargs)

    monkeypatch.setattr(
        "guard.websocket.check_rate_limit_by_ip", _capturing_check_rate_limit_by_ip
    )

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

        assert client.portal is not None
        client.portal.call(RedisManager(config).close)

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"
    assert captured["redis_handler"] is not None
    assert captured["redis_handler"] is RedisManager._instance


async def test_make_guard_websocket_warns_once_and_falls_back_to_memory_store(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = SecurityConfig(
        enable_redis=True,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
    )

    with caplog.at_level(logging.WARNING):
        dependency = make_guard_websocket(config)

    warnings = [
        r
        for r in caplog.records
        if "make_guard_websocket" in r.message and "in-memory store" in r.message
    ]
    assert len(warnings) == 1

    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(dependency)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"

    warnings_after_connects = [
        r
        for r in caplog.records
        if "make_guard_websocket" in r.message and "in-memory store" in r.message
    ]
    assert len(warnings_after_connects) == 1


async def test_make_guard_websocket_uses_the_given_redis_handler(
    security_config_redis: SecurityConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    security_config_redis.enable_redis = True
    security_config_redis.enable_penetration_detection = False
    security_config_redis.enable_rate_limiting = True
    security_config_redis.rate_limit = 1
    security_config_redis.rate_limit_window = 60
    security_config_redis.whitelist = ()
    security_config_redis.blocked_countries = frozenset()
    config = security_config_redis

    redis_handler = RedisManager(config)
    await redis_handler.initialize()

    captured: dict[str, Any] = {}

    async def _capturing_check_rate_limit_by_ip(*args: Any, **kwargs: Any) -> bool:
        captured["redis_handler"] = kwargs.get("redis_handler")
        return await real_check_rate_limit_by_ip(*args, **kwargs)

    monkeypatch.setattr(
        "guard.websocket.check_rate_limit_by_ip", _capturing_check_rate_limit_by_ip
    )

    dependency = make_guard_websocket(config, redis_handler=redis_handler)
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(dependency)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect("/ws"):
                pass

        assert client.portal is not None
        client.portal.call(redis_handler.close)

    assert exc_info.value.code == 1008
    assert exc_info.value.reason == "Rate limit exceeded"
    assert captured["redis_handler"] is redis_handler


async def test_make_guard_websocket_never_mutates_the_redis_singletons_config(
    security_config_redis: SecurityConfig,
) -> None:
    security_config_redis.enable_redis = True
    owner_config = security_config_redis
    owner_manager = RedisManager(owner_config)
    await owner_manager.initialize()

    foreign_config = SecurityConfig(
        enable_redis=True,
        enable_penetration_detection=False,
        enable_rate_limiting=True,
        rate_limit=1,
        rate_limit_window=60,
    )
    dependency = make_guard_websocket(foreign_config)
    app = FastAPI()

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket, _: None = Depends(dependency)
    ) -> None:
        await websocket.accept()
        await websocket.send_text("connected")

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        with client.websocket_connect("/ws") as websocket:
            assert websocket.receive_text() == "connected"

    assert RedisManager._instance is owner_manager
    assert RedisManager._instance.config is owner_config
    await owner_manager.close()
