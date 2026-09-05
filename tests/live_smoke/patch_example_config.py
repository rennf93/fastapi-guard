import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent / "stack" / "app"
DEST = APP_DIR / "security.py"
ROUTES_INIT = APP_DIR / "routes" / "__init__.py"
MAIN_PY = APP_DIR / "main.py"
SMOKE_EXTRA_ROUTE = APP_DIR / "routes" / "smoke_extra.py"

_MARKER = "_smoke_apply_overrides"

_PATCH = """

def _smoke_on_block(request, payload):
    import json as _smoke_json
    import os as _smoke_os

    path = _smoke_os.environ.get("SMOKE_ON_BLOCK_LOG")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(_smoke_json.dumps(payload, default=str) + "\\n")


def _smoke_on_error(stage, exc, context):
    import json as _smoke_json
    import os as _smoke_os

    path = _smoke_os.environ.get("SMOKE_ON_ERROR_LOG")
    if not path:
        return
    payload = {"stage": stage, "error": str(exc), "context": context}
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(_smoke_json.dumps(payload, default=str) + "\\n")


smoke_nonce = "unknown"


def _smoke_apply_overrides() -> None:
    import json as _smoke_json
    import os as _smoke_os

    global security_config, guard, smoke_nonce

    config_path = _smoke_os.environ.get("SMOKE_CONFIG_PATH")
    overrides: dict = {}
    if config_path and _smoke_os.path.isfile(config_path):
        text = Path(config_path).read_text(encoding="utf-8").strip()
        if text:
            overrides = _smoke_json.loads(text)

    smoke_nonce = overrides.pop("smoke_nonce", smoke_nonce)
    Path("/tmp/smoke_nonce.txt").write_text(smoke_nonce, encoding="utf-8")
    smoke_geoip_db = overrides.pop("smoke_geoip_db", None)

    merged = security_config.model_dump()
    merged.update(overrides)
    merged["on_block"] = _smoke_on_block
    merged["on_error"] = _smoke_on_error
    merged["exclude_paths"] = sorted(
        {*merged.get("exclude_paths", []), "/smoke/nonce", "/smoke/agent-config"}
    )

    if smoke_geoip_db:
        from guard_core.handlers.ipinfo_handler import IPInfoManager

        merged["geo_ip_handler"] = IPInfoManager(
            token="smoke-geoip-token",
            db_path=Path(smoke_geoip_db),
            max_age=merged.get("geo_ip_db_max_age", 86400),
        )

    security_config = SecurityConfig(**merged)
    guard = SecurityDecorator(security_config)


_smoke_apply_overrides()
"""

_SMOKE_EXTRA_ROUTE_SOURCE = """from fastapi import APIRouter, Query, Request

from app.security import guard, security_config
from guard.adapters import StarletteGuardRequest

router = APIRouter(tags=["Smoke Framework"])

_AGENT_CONFIG_SECRET_FIELDS = {
    "api_key",
    "project_encryption_key",
    "payload_signing_secret",
}


@router.get("/smoke/nonce")
async def smoke_nonce_route() -> dict[str, str]:
    from app.security import smoke_nonce

    return {"nonce": smoke_nonce}


@router.get("/smoke/agent-config")
async def smoke_agent_config_route() -> dict[str, object]:
    agent_config = security_config.to_agent_config()
    if agent_config is None:
        return {"enabled": False}
    data = agent_config.model_dump(exclude={"on_error"})
    for field in _AGENT_CONFIG_SECRET_FIELDS:
        if data.get(field):
            data[field] = "***MASKED***"
    return {"enabled": True, **data}


@router.get("/smoke/authz-header")
@guard.require_authorization_header(scheme="bearer")
async def smoke_authz_header_route() -> dict[str, bool]:
    return {"ok": True}


@router.get("/smoke/detection-exclusion")
@guard.detection_exclusion(params={"safe_marker"})
async def smoke_detection_exclusion_route(
    safe_marker: str = Query(None),
) -> dict[str, str | None]:
    return {"safe_marker": safe_marker}


@router.get("/smoke/decorator-events")
async def smoke_decorator_events_route(request: Request) -> dict[str, bool]:
    guard_request = StarletteGuardRequest(request)
    await guard.send_decorator_event(
        event_type="smoke_decorator_event",
        request=guard_request,
        action_taken="observed",
        reason="smoke framework probe",
        decorator_type="smoke",
    )
    await guard.send_decorator_violation_event(
        request=guard_request,
        violation_type="smoke_violation",
        reason="smoke framework probe",
    )
    await guard.send_access_denied_event(
        request=guard_request,
        reason="smoke framework probe",
        decorator_type="smoke",
    )
    await guard.send_authentication_failed_event(
        request=guard_request,
        reason="smoke framework probe",
        auth_type="smoke",
    )
    await guard.send_rate_limit_event(
        request=guard_request,
        limit=1,
        window=60,
    )
    return {"triggered": True}


async def smoke_startup_hook() -> None:
    redis_handler = None
    if security_config.enable_redis:
        from guard_core.handlers.redis_handler import RedisManager

        redis_handler = RedisManager(security_config)
    await guard.initialize_behavior_tracking(redis_handler)
"""

_ROUTES_INIT_MARKER = "smoke_extra_router"

_MAIN_PY_IMPORT_ANCHOR = "from app.security import guard, security_config\n"
_MAIN_PY_IMPORT_INSERT = (
    "from app.routes.smoke_extra import smoke_startup_hook\n"
    "from app.security import guard, security_config\n"
)
_MAIN_PY_INCLUDE_ANCHOR = "app.include_router(test_router)\n"
_MAIN_PY_INCLUDE_INSERT = (
    "app.include_router(test_router)\napp.include_router(smoke_extra_router)\n"
)
_MAIN_PY_STARTUP_ANCHOR = (
    '    logger.info("FastAPI Guard Advanced Example starting up...")\n'
)
_MAIN_PY_STARTUP_INSERT = (
    '    logger.info("FastAPI Guard Advanced Example starting up...")\n'
    "    await smoke_startup_hook()\n"
)


def _patch_security() -> None:
    if not DEST.is_file():
        raise FileNotFoundError(f"{DEST} does not exist; run copy_example_app.py first")
    original = DEST.read_text(encoding="utf-8")
    if _MARKER in original:
        return
    text = original
    if "\nfrom pathlib import Path\n" not in text:
        text = text.replace("import os\n", "import os\nfrom pathlib import Path\n", 1)
    DEST.write_text(text + _PATCH, encoding="utf-8")


def _write_smoke_extra_route() -> None:
    SMOKE_EXTRA_ROUTE.write_text(_SMOKE_EXTRA_ROUTE_SOURCE, encoding="utf-8")


def _patch_routes_init() -> None:
    text = ROUTES_INIT.read_text(encoding="utf-8")
    if _ROUTES_INIT_MARKER in text:
        return
    text = text.replace(
        "from app.routes.rate_limiting import router as rate_router\n",
        "from app.routes.rate_limiting import router as rate_router\n"
        "from app.routes.smoke_extra import router as smoke_extra_router\n",
        1,
    )
    text = text.replace(
        '    "rate_router",\n',
        '    "rate_router",\n    "smoke_extra_router",\n',
        1,
    )
    ROUTES_INIT.write_text(text, encoding="utf-8")


def _patch_main() -> None:
    text = MAIN_PY.read_text(encoding="utf-8")
    if "smoke_extra_router" in text and "smoke_startup_hook" in text:
        return
    text = text.replace(
        "    test_router,\n)",
        "    smoke_extra_router,\n    test_router,\n)",
        1,
    )
    text = text.replace(_MAIN_PY_IMPORT_ANCHOR, _MAIN_PY_IMPORT_INSERT, 1)
    text = text.replace(_MAIN_PY_INCLUDE_ANCHOR, _MAIN_PY_INCLUDE_INSERT, 1)
    text = text.replace(_MAIN_PY_STARTUP_ANCHOR, _MAIN_PY_STARTUP_INSERT, 1)
    MAIN_PY.write_text(text, encoding="utf-8")


def patch() -> None:
    _patch_security()
    _write_smoke_extra_route()
    _patch_routes_init()
    _patch_main()


if __name__ == "__main__":
    patch()
    print(f"patched {DEST}")
    sys.exit(0)
