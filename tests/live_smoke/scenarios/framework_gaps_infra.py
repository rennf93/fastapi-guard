import os

from tests.live_smoke.driver import (
    STACK_DIR,
    ScenarioContext,
    make_redis_client,
    run_in_app_container,
    wait_until,
)
from tests.live_smoke.registry import scenario
from tests.live_smoke.scenarios.access_control import _build_mmdb

EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]
CLIENT_IP = "192.168.50.50"

_GEO_HANDLER_HOST_PATH = STACK_DIR / "scenario_data" / "geo_smoke_handler.mmdb"
GEO_HANDLER_CONTAINER_PATH = "/smoke/geo_smoke_handler.mmdb"

if os.environ.get("LIVE_SMOKE") == "1":
    _GEO_HANDLER_HOST_PATH.parent.mkdir(parents=True, exist_ok=True)
    _GEO_HANDLER_HOST_PATH.write_bytes(_build_mmdb({CLIENT_IP: "US"}))


REDIS_URL_CONFIG = {
    "redis_url": "redis://redis:6379/1",
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"redis_url"}, config=REDIS_URL_CONFIG)
def redis_url_targets_the_configured_database(ctx: ScenarioContext) -> None:
    db1 = make_redis_client(db=1)
    try:
        db1.flushdb()
        ctx.redis.flushdb()

        ctx.client.get("/basic/ip", params={"q": "hello"})

        keys_db1 = wait_until(lambda: db1.keys("smoke:*") or None, timeout=10.0)
        assert keys_db1, "redis_url=redis://redis:6379/1 wrote no keys into db 1"

        keys_db0 = ctx.redis.keys("smoke:*")
        assert not keys_db0, (
            "this scenario's own traffic should not have written to db 0 once "
            f"redis_url points at db 1, found {keys_db0}"
        )
    finally:
        db1.flushdb()
        db1.close()


GEO_HANDLER_CONFIG = {
    "blocked_countries": ["ZZ"],
    "smoke_geoip_db": GEO_HANDLER_CONTAINER_PATH,
    "geo_ip_db_max_age": 3600,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"geo_ip_handler"}, config=GEO_HANDLER_CONFIG)
def geo_ip_handler_resolves_country_from_the_explicit_handler(
    ctx: ScenarioContext,
) -> None:
    response = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert response.status_code == 200, (
        "an explicit geo_ip_handler built from smoke_geoip_db should resolve the "
        f"client's country and let it through blocked_countries=['ZZ']: "
        f"{response.status_code}"
    )


_GEO_MAX_AGE_PROBE = """
import asyncio
import logging
import os
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

from guard_core.handlers.ipinfo_handler import IPInfoManager

db_path = Path("/tmp/smoke_geo_max_age_probe.mmdb")
db_path.write_bytes(Path({fixture!r}).read_bytes())
stale = time.time() - 100000
os.utime(db_path, (stale, stale))

handler = IPInfoManager(token="smoke-max-age-token", db_path=db_path, max_age=1)
asyncio.run(handler.initialize())
print("SMOKE_PROBE_DONE", handler.reader is not None)
"""


def _geo_max_age_probe_output(timeout: float = 25.0) -> str:
    result = run_in_app_container(
        _GEO_MAX_AGE_PROBE.format(fixture=GEO_HANDLER_CONTAINER_PATH), timeout=timeout
    )
    return result.stdout + result.stderr


@scenario(covers={"geo_ip_db_max_age"}, config=GEO_HANDLER_CONFIG)
def geo_ip_db_max_age_triggers_a_refresh_attempt_when_stale(
    ctx: ScenarioContext,
) -> None:
    output = _geo_max_age_probe_output()
    assert "SMOKE_PROBE_DONE" in output, (
        "geo_ip_db_max_age probe did not complete inside its bounded exec "
        f"window; output: {output!r}"
    )
    assert "IPInfo database download failed, keeping existing reader" in output, (
        "geo_ip_db_max_age=1 with a stale mtime should make IPInfoManager."
        f"initialize() attempt (and log the failure of) a fresh download; "
        f"probe output: {output!r}"
    )


ENFORCE_HTTPS_CONFIG = {
    "enforce_https": True,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"enforce_https"}, config=ENFORCE_HTTPS_CONFIG)
def enforce_https_field_redirects_plain_http_requests(ctx: ScenarioContext) -> None:
    response = ctx.client.get("/basic/health")
    assert response.status_code == 301, (
        f"enforce_https=True should redirect a plain HTTP request: "
        f"{response.status_code}"
    )
