import logging
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from typing import Any, NamedTuple, cast

from guard_core import check_rate_limit_by_ip, ip_ban_manager, is_ip_allowed
from guard_core.exceptions import GuardRedisError
from guard_core.handlers.redis_handler import RedisManager
from guard_core.models import SecurityConfig
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import UNKNOWN_CLIENT_IDENTITY, extract_client_ip
from starlette import status
from starlette.exceptions import WebSocketException
from starlette.websockets import WebSocket

from guard.adapters import _join_repeated_header_lines
from guard.lifespan import _find_security_config, _find_security_redis_handler

logger = logging.getLogger("guard_core")


class WebSocketCloseReason(NamedTuple):
    code: int
    reason: str


WS_CLOSE_IP_BANNED = WebSocketCloseReason(status.WS_1008_POLICY_VIOLATION, "IP banned")
WS_CLOSE_IP_NOT_ALLOWED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "IP not allowed"
)
WS_CLOSE_RATE_LIMIT_EXCEEDED = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Rate limit exceeded"
)
WS_CLOSE_CLIENT_ADDRESS_UNKNOWN = WebSocketCloseReason(
    status.WS_1008_POLICY_VIOLATION, "Client address could not be determined"
)
WS_CLOSE_SECURITY_CHECK_FAILED = WebSocketCloseReason(
    status.WS_1013_TRY_AGAIN_LATER, "Security check failed"
)

WS_CLOSE_REASONS: tuple[WebSocketCloseReason, ...] = (
    WS_CLOSE_IP_BANNED,
    WS_CLOSE_IP_NOT_ALLOWED,
    WS_CLOSE_RATE_LIMIT_EXCEEDED,
    WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
    WS_CLOSE_SECURITY_CHECK_FAILED,
)


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


async def _guarded_redis_call(
    awaitable: Coroutine[Any, Any, bool],
    config: SecurityConfig,
    check_name: str,
    default: bool,
) -> bool:
    try:
        return await awaitable
    except GuardRedisError as exc:
        if config.redis_fail_open:
            logger.warning(
                "Skipping %s: Redis unavailable, failing open (redis_fail_open=True)",
                check_name,
            )
            return default
        logger.error("Error in %s: %s", check_name, exc, exc_info=True)
        if config.fail_secure:
            logger.warning(
                "Blocking websocket handshake due to %s error in fail-secure mode",
                check_name,
            )
            raise WebSocketException(
                code=WS_CLOSE_SECURITY_CHECK_FAILED.code,
                reason=WS_CLOSE_SECURITY_CHECK_FAILED.reason,
            ) from exc
        return default


async def _run_websocket_checks(
    websocket: WebSocket,
    config: SecurityConfig,
    redis_handler: RedisManager | None,
) -> None:
    guard_request: GuardRequest = _WebSocketGuardRequest(websocket)
    client_ip = await extract_client_ip(guard_request, config)
    websocket.state.client_ip = client_ip

    if client_ip == UNKNOWN_CLIENT_IDENTITY and config.fail_secure:
        raise WebSocketException(
            code=WS_CLOSE_CLIENT_ADDRESS_UNKNOWN.code,
            reason=WS_CLOSE_CLIENT_ADDRESS_UNKNOWN.reason,
        )

    is_banned = await _guarded_redis_call(
        ip_ban_manager.is_ip_banned(client_ip),
        config,
        "ip_ban_manager.is_ip_banned",
        default=False,
    )
    if is_banned:
        raise WebSocketException(
            code=WS_CLOSE_IP_BANNED.code, reason=WS_CLOSE_IP_BANNED.reason
        )

    if not await is_ip_allowed(client_ip, config, config.geo_ip_handler):
        raise WebSocketException(
            code=WS_CLOSE_IP_NOT_ALLOWED.code, reason=WS_CLOSE_IP_NOT_ALLOWED.reason
        )

    if client_ip == UNKNOWN_CLIENT_IDENTITY or config.whitelist:
        return

    allowed = await _guarded_redis_call(
        check_rate_limit_by_ip(
            client_ip, config, redis_handler=redis_handler, endpoint_path="ws"
        ),
        config,
        "check_rate_limit_by_ip",
        default=True,
    )
    if not allowed:
        raise WebSocketException(
            code=WS_CLOSE_RATE_LIMIT_EXCEEDED.code,
            reason=WS_CLOSE_RATE_LIMIT_EXCEEDED.reason,
        )


async def guard_websocket(websocket: WebSocket) -> None:
    app = websocket.scope.get("app")
    config = _find_security_config(app)
    if config is None:
        raise RuntimeError(
            "guard_websocket requires SecurityMiddleware to be registered via "
            "app.add_middleware(SecurityMiddleware, config=...)"
        )
    redis_handler = _find_security_redis_handler(app)
    await _run_websocket_checks(websocket, config, redis_handler)


def make_guard_websocket(
    config: SecurityConfig,
    redis_handler: RedisManager | None = None,
) -> Callable[[WebSocket], Awaitable[None]]:
    if config.enable_redis and redis_handler is None:
        logger.warning(
            "enable_redis=True but no redis_handler was given to "
            "make_guard_websocket; the websocket rate limit uses the "
            "in-memory store"
        )

    async def _guard_websocket_dependency(websocket: WebSocket) -> None:
        await _run_websocket_checks(websocket, config, redis_handler)

    return _guard_websocket_dependency
