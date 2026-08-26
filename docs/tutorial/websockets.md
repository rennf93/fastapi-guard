---

title: WebSockets - FastAPI Guard
description: Securing WebSocket routes with the guard_websocket dependency
keywords: websocket, guard_websocket, dependency injection
---

WebSockets
==========

`SecurityMiddleware` protects HTTP requests only. It is built on Starlette's `BaseHTTPMiddleware`, which never runs its `dispatch` method for a `"websocket"` ASGI scope; a `@app.websocket` route registered on the same app receives zero protection from the middleware, regardless of configuration.

___

The guard_websocket Dependency
-------------------------------

Secure a WebSocket route explicitly with `Depends(guard_websocket)`:

```python
from fastapi import Depends, FastAPI, WebSocket

from guard import SecurityConfig, SecurityMiddleware, guard_websocket

app = FastAPI()
app.add_middleware(
    SecurityMiddleware,
    config=SecurityConfig(
        trusted_proxies=["10.0.0.1"],
        blacklist=("203.0.113.9",),
    ),
)


@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket, _: None = Depends(guard_websocket)
) -> None:
    await websocket.accept()
    await websocket.send_text("connected")
```

`guard_websocket` runs before the route function, using the same `SecurityConfig` passed to `app.add_middleware(SecurityMiddleware, config=...)`. In order, it checks:

1. `ip_ban_manager.is_ip_banned` -- is the resolved client IP currently banned.
2. `is_ip_allowed` -- whitelist/blacklist, blocked countries, blocked cloud providers.
3. `check_rate_limit_by_ip` -- a rate-limit bucket isolated from the HTTP pipeline's own bucket for the same IP (keyed by `endpoint_path="ws"`), Redis-backed when `enable_redis=True`, in-memory otherwise.

On the first failing check, the connection is closed with WebSocket close code `1008` (Policy Violation) before `accept()` is ever called; the client sees the handshake rejected, not an accepted-then-closed connection.

If Redis is unreachable while `ip_ban_manager.is_ip_banned` or `check_rate_limit_by_ip` runs, `guard_websocket` follows the same `redis_fail_open` and `fail_secure` rules as the HTTP pipeline: `redis_fail_open=True` skips the failing check and treats it as passed; otherwise `fail_secure=True` (the default) refuses the handshake with close code `1013` (Try Again Later); otherwise the check is skipped and the error is logged.

___

Client Resolution
------------------

The client IP is resolved the same way as the HTTP pipeline: `websocket.client.host` if the connection has a peer, or `X-Forwarded-For` when the connecting peer is a trusted proxy (`trusted_proxies`, `trusted_proxy_depth`). A connection with no peer at all (a Unix domain socket, some serverless adapters) needs `"unix"` in `trusted_proxies` to resolve from `X-Forwarded-For`, exactly as for HTTP; see [Proxy Security](security/proxy-security.md#unix-sockets-and-serverless-adapters).

When the client address still cannot be resolved, `guard_websocket` follows the same `fail_secure` setting as the HTTP pipeline: `fail_secure=True` (the default) closes the connection with code `1008` before running any further check; `fail_secure=False` runs the ban, allow-list, and blocked-country checks against identity `"unknown"` (allowed unless a whitelist or a country allow-list is configured) and skips the rate-limit check, since there is no real IP to key a rate-limit bucket on.

___

Scope
-----

`guard_websocket` does not run penetration detection, security headers, HTTPS enforcement, or any per-route decorator; those are HTTP-pipeline concepts with no WebSocket equivalent. It requires `SecurityMiddleware` to already be registered on the app (`app.add_middleware(SecurityMiddleware, config=...)`); calling it without that raises `RuntimeError` at connection time.
