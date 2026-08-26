from collections.abc import Mapping
from typing import Any, cast

from guard_core import check_rate_limit_by_ip, ip_ban_manager, is_ip_allowed
from guard_core.handlers.redis_handler import RedisManager
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import UNKNOWN_CLIENT_IDENTITY, extract_client_ip
from starlette import status
from starlette.exceptions import WebSocketException
from starlette.websockets import WebSocket

from guard.adapters import _join_repeated_header_lines
from guard.lifespan import _find_security_config


class _WebSocketGuardRequest:
    def __init__(self, websocket: WebSocket) -> None:
        self._websocket = websocket

    @property
    def url_path(self) -> str:
        return self._websocket.url.path

    @property
    def url_scheme(self) -> str:
        return self._websocket.url.scheme

    @property
    def url_full(self) -> str:
        return str(self._websocket.url)

    def url_replace_scheme(self, scheme: str) -> str:
        return str(self._websocket.url.replace(scheme=scheme))

    @property
    def method(self) -> str:
        return "WEBSOCKET"

    @property
    def client_host(self) -> str | None:
        if self._websocket.client:
            return self._websocket.client.host
        return None

    @property
    def headers(self) -> Mapping[str, str]:
        return _join_repeated_header_lines(self._websocket.headers)

    @property
    def query_params(self) -> Mapping[str, str]:
        return self._websocket.query_params

    async def body(self) -> bytes:
        return b""

    @property
    def state(self) -> Any:
        return self._websocket.state

    @property
    def scope(self) -> dict[str, Any]:
        return cast(dict[str, Any], self._websocket.scope)


async def guard_websocket(websocket: WebSocket) -> None:
    config = _find_security_config(websocket.scope.get("app"))
    if config is None:
        raise RuntimeError(
            "guard_websocket requires SecurityMiddleware to be registered via "
            "app.add_middleware(SecurityMiddleware, config=...)"
        )

    guard_request: GuardRequest = _WebSocketGuardRequest(websocket)
    client_ip = await extract_client_ip(guard_request, config)

    if client_ip == UNKNOWN_CLIENT_IDENTITY and config.fail_secure:
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Client address could not be determined",
        )

    if await ip_ban_manager.is_ip_banned(client_ip):
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION, reason="IP banned"
        )

    if not await is_ip_allowed(client_ip, config, config.geo_ip_handler):
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION, reason="IP not allowed"
        )

    if client_ip == UNKNOWN_CLIENT_IDENTITY:
        return

    redis_handler = RedisManager(config) if config.enable_redis else None
    allowed = await check_rate_limit_by_ip(
        client_ip, config, redis_handler=redis_handler, endpoint_path="ws"
    )
    if not allowed:
        raise WebSocketException(
            code=status.WS_1008_POLICY_VIOLATION, reason="Rate limit exceeded"
        )
