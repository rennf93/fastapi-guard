from fastapi import FastAPI
from guard_core.protocols import GuardResponse
from httpx import ASGITransport, AsyncClient

from guard import SecurityConfig
from guard.middleware import SecurityMiddleware

BLOCKED_IP = "203.0.113.10"


def _config(**overrides: object) -> SecurityConfig:
    return SecurityConfig(
        blacklist=(BLOCKED_IP,),
        enable_rate_limiting=False,
        enable_redis=False,
        **overrides,  # type: ignore[arg-type]
    )


async def _blocked_response_headers(config: SecurityConfig) -> tuple[int, str, str]:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/ping")
    async def ping() -> dict[str, bool]:
        return {"ok": True}

    async with AsyncClient(
        transport=ASGITransport(app=app, client=(BLOCKED_IP, 50000)),
        base_url="http://test",
    ) as client:
        response = await client.get("/ping")
    return (
        response.status_code,
        response.headers.get("content-type", ""),
        response.headers.get("x-content-type-options", ""),
    )


async def test_block_response_is_plain_text() -> None:
    assert await _blocked_response_headers(_config()) == (
        403,
        "text/plain; charset=utf-8",
        "nosniff",
    )


async def test_custom_error_message_is_plain_text() -> None:
    config = _config(custom_error_responses={403: "Access denied"})

    status_code, content_type, _nosniff = await _blocked_response_headers(config)

    assert (status_code, content_type) == (403, "text/plain; charset=utf-8")


async def test_response_modifier_can_still_set_its_own_content_type() -> None:
    async def problem_json(response: GuardResponse) -> GuardResponse:
        response.headers["content-type"] = "application/problem+json"
        return response

    config = _config(custom_response_modifier=problem_json)

    status_code, content_type, _nosniff = await _blocked_response_headers(config)

    assert (status_code, content_type) == (403, "application/problem+json")
