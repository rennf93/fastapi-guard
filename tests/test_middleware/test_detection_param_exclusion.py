import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from guard import SecurityConfig, SecurityDecorator
from guard.middleware import SecurityMiddleware

# What an RFC 8252 native client (an MCP client, for one) sends to /authorize: the ssrf
# category matches the loopback host in redirect_uri.
LOOPBACK_AUTHORIZE = {
    "response_type": "code",
    "client_id": "cli",
    "redirect_uri": "http://localhost:6274/oauth/callback",
}


def _config(**overrides: object) -> SecurityConfig:
    return SecurityConfig(
        enable_penetration_detection=True,
        enable_rate_limiting=False,
        enable_ip_banning=False,
        enable_redis=False,
        **overrides,  # type: ignore[arg-type]
    )


async def _authorize(app: FastAPI) -> int:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/oauth/authorize", params=LOOPBACK_AUTHORIZE)
    return response.status_code


@pytest.mark.asyncio
async def test_loopback_redirect_uri_is_flagged_by_default() -> None:
    app = FastAPI()
    app.add_middleware(SecurityMiddleware, config=_config())

    @app.get("/oauth/authorize")
    async def authorize() -> dict[str, str]:
        return {"ok": "yes"}

    assert await _authorize(app) == 400


@pytest.mark.asyncio
async def test_excluded_detection_params_lets_the_redirect_uri_through() -> None:
    app = FastAPI()
    app.add_middleware(
        SecurityMiddleware, config=_config(excluded_detection_params={"redirect_uri"})
    )

    @app.get("/oauth/authorize")
    async def authorize() -> dict[str, str]:
        return {"ok": "yes"}

    assert await _authorize(app) == 200


@pytest.mark.asyncio
async def test_detection_exclusion_decorator_scopes_it_to_the_route() -> None:
    app = FastAPI()
    config = _config()
    decorator = SecurityDecorator(config)

    @decorator.detection_exclusion(params={"redirect_uri"})
    @app.get("/oauth/authorize")
    async def authorize() -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/search")
    async def search() -> dict[str, str]:
        return {"ok": "yes"}

    app.add_middleware(SecurityMiddleware, config=config)
    app.state.guard_decorator = decorator

    assert await _authorize(app) == 200
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        other = await client.get(
            "/search", params={"redirect_uri": "http://localhost:6274/oauth/callback"}
        )
    assert other.status_code == 400
