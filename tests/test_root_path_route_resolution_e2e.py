from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard_core.models import SecurityConfig

from guard.middleware import SecurityMiddleware

THING_PATH = "/api/thing"
HEALTH_PATH = "/health"
BLOCKED_USER_AGENT = "badbot"


def _build_app() -> FastAPI:
    app = FastAPI()
    config = SecurityConfig(
        endpoint_rate_limits={THING_PATH: (2, 60)},
        exclude_paths=[HEALTH_PATH],
        blocked_user_agents=[BLOCKED_USER_AGENT],
        enable_redis=False,
        enable_penetration_detection=False,
    )
    app.add_middleware(SecurityMiddleware, config=config)

    @app.get(THING_PATH)
    async def thing() -> dict[str, bool]:
        return {"ok": True}

    @app.get(HEALTH_PATH)
    async def health() -> dict[str, bool]:
        return {"ok": True}

    return app


def _drive(*, root_path: str, prefix: str) -> tuple[list[int], int]:
    with TestClient(
        _build_app(), root_path=root_path, client=("127.0.0.1", 5555)
    ) as client:
        codes = [
            client.get(
                f"{prefix}{THING_PATH}", headers={"User-Agent": "normal-agent"}
            ).status_code
            for _ in range(3)
        ]
        health_status = client.get(
            f"{prefix}{HEALTH_PATH}", headers={"User-Agent": BLOCKED_USER_AGENT}
        ).status_code
    return codes, health_status


def test_endpoint_rate_limit_and_exclude_paths_apply_without_root_path() -> None:
    codes, health_status = _drive(root_path="", prefix="")
    assert codes == [200, 200, 429]
    assert health_status == 200


def test_endpoint_rate_limit_and_exclude_paths_apply_under_root_path() -> None:
    codes, health_status = _drive(root_path="/mounted", prefix="/mounted")
    assert codes == [200, 200, 429]
    assert health_status == 200
