from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware

_ATTACK_BODY = b"username=<script>alert(document.cookie)</script>"
_BENIGN_BODY = b"a benign form submission describing quarterly onboarding metrics"


def _chunked(payload: bytes, chunk_size: int = 8) -> AsyncIterator[bytes]:
    async def chunks() -> AsyncIterator[bytes]:
        for start in range(0, len(payload), chunk_size):
            yield payload[start : start + chunk_size]

    return chunks()


def _echo_app(config: SecurityConfig) -> FastAPI:
    app = FastAPI()

    @app.post("/echo-length")
    async def echo_length(request: Request) -> dict[str, int]:
        body = await request.body()
        return {"received": len(body)}

    app.add_middleware(SecurityMiddleware, config=config)
    return app


async def test_chunked_request_without_content_length_is_scanned() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    app = _echo_app(config)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/echo-length",
            content=_chunked(_ATTACK_BODY),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == 400
    assert "Suspicious activity detected" in response.text


async def test_chunked_benign_request_reaches_endpoint_with_full_body() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=True)
    app = _echo_app(config)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/echo-length",
            content=_chunked(_BENIGN_BODY),
            headers={"Content-Type": "text/plain"},
        )

    assert response.status_code == 200
    assert response.json() == {"received": len(_BENIGN_BODY)}


def _streaming_app_with_body_rule(pattern: str) -> FastAPI:
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        trusted_proxies=("127.0.0.1",),
        behavior_scan_response_body=True,
    )
    app = FastAPI()
    decorator = SecurityDecorator(config)

    @decorator.return_monitor(
        pattern=pattern, max_occurrences=1, window=86400, action="ban"
    )
    @app.get("/stream")
    async def stream() -> StreamingResponse:
        async def chunks() -> AsyncIterator[bytes]:
            yield b"chunk-one|"
            yield b"chunk-two|"
            yield b"chunk-three"

        return StreamingResponse(chunks(), media_type="text/plain")

    app.add_middleware(SecurityMiddleware, config=config)
    app.state.guard_decorator = decorator
    return app


async def test_streaming_response_delivered_intact_while_body_rule_scans() -> None:
    app = _streaming_app_with_body_rule("no-such-token-in-the-stream")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/stream", headers={"X-Forwarded-For": "203.0.113.77"}
        )

    assert response.status_code == 200
    assert response.content == b"chunk-one|chunk-two|chunk-three"


async def test_body_return_pattern_rule_fires_on_real_response() -> None:
    app = _streaming_app_with_body_rule("chunk-one")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.get("/stream", headers={"X-Forwarded-For": "203.0.113.88"})
        second = await client.get(
            "/stream", headers={"X-Forwarded-For": "203.0.113.88"}
        )
        third = await client.get("/stream", headers={"X-Forwarded-For": "203.0.113.88"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 403
