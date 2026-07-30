from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from guard.middleware import SecurityMiddleware

RATE_LIMIT = 3
ATTEMPTS = 12


def _build_app() -> FastAPI:
    app = FastAPI()
    config = SecurityConfig(
        enable_rate_limiting=True,
        rate_limit=RATE_LIMIT,
        rate_limit_window=60,
        enable_redis=False,
        enable_ip_banning=False,
        enable_penetration_detection=False,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get("/api/login")
    async def login() -> dict[str, bool]:
        return {"ok": True}

    return app


def _drive_with_rotating_forwarded_for(
    *, wrap_in_uvicorn_proxy_headers: bool
) -> list[int]:
    """One attacker, one connecting peer (127.0.0.1), a fresh X-Forwarded-For
    value on every request, trusted_proxies left unset throughout."""
    asgi: Any = _build_app()
    if wrap_in_uvicorn_proxy_headers:
        asgi = ProxyHeadersMiddleware(asgi, trusted_hosts="127.0.0.1")

    codes = []
    with TestClient(asgi, client=("127.0.0.1", 5555)) as client:
        for i in range(ATTEMPTS):
            response = client.get(
                "/api/login", headers={"X-Forwarded-For": f"9.9.{i}.{i}"}
            )
            codes.append(response.status_code)
    return codes


def test_uvicorns_own_proxy_headers_let_rotating_forwarded_for_evade_rate_limit() -> (
    None
):
    """This is the regression: uvicorn's default proxy_headers=True rewrites
    scope["client"] from X-Forwarded-For before SecurityMiddleware ever runs,
    so trusted_proxies unset does not mean the header is never trusted — every
    forged value earns the attacker a fresh rate-limit bucket and the limiter
    never engages."""
    codes = _drive_with_rotating_forwarded_for(wrap_in_uvicorn_proxy_headers=True)
    assert codes.count(200) == ATTEMPTS
    assert codes.count(429) == 0


def test_disabling_uvicorns_proxy_headers_restores_the_rate_limit() -> None:
    """The documented remediation actually works: with uvicorn's own
    forwarded-header handling off, the connecting peer stays 127.0.0.1 for
    every request regardless of X-Forwarded-For, so the same SecurityMiddleware
    config correctly buckets all of them together and the limiter engages."""
    codes = _drive_with_rotating_forwarded_for(wrap_in_uvicorn_proxy_headers=False)
    assert codes.count(200) == RATE_LIMIT
    assert codes.count(429) == ATTEMPTS - RATE_LIMIT
