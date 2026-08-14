from fastapi import FastAPI, status
from guard_core.models import SecurityConfig
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport

from guard.middleware import SecurityMiddleware


async def test_blacklisted_ip_still_blocked_and_whitelisted_ip_still_allowed() -> None:
    app = FastAPI()
    config = SecurityConfig(
        whitelist=("127.0.0.1",),
        blacklist=("203.0.113.99",),
        enable_penetration_detection=False,
        enable_redis=False,
        trusted_proxies=("127.0.0.1",),
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/")
    async def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        allowed = await client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert allowed.status_code == status.HTTP_200_OK

        blocked = await client.get("/", headers={"X-Forwarded-For": "203.0.113.99"})
        assert blocked.status_code == status.HTTP_403_FORBIDDEN
