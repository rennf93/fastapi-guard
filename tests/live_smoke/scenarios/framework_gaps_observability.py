import base64

from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]
BADBOT_HEADERS = {"User-Agent": "badbot"}

OTEL_SERVICE_NAME = "smoke-otel-service-gap"
OTEL_CONFIG = {
    "enable_otel": True,
    "otel_service_name": OTEL_SERVICE_NAME,
    "otel_exporter_endpoint": "http://otlp-stub:4318",
    "otel_resource_attributes": {"deployment.environment": "smoke-otel-env"},
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


def _otlp_trace_bodies(ctx: ScenarioContext) -> list[bytes]:
    response = ctx.otlp.get("/_debug/state")
    response.raise_for_status()
    return [
        base64.b64decode(request["body_base64"])
        for request in response.json().get("requests", [])
        if request.get("path") == "/v1/traces"
    ]


def _otel_traces_seen(ctx: ScenarioContext) -> list[bytes] | None:
    bodies = [
        body for body in _otlp_trace_bodies(ctx) if OTEL_SERVICE_NAME.encode() in body
    ]
    return bodies or None


@scenario(
    covers={"otel_service_name", "otel_exporter_endpoint", "otel_resource_attributes"},
    config=OTEL_CONFIG,
)
def otel_exports_service_name_and_resource_attributes(ctx: ScenarioContext) -> None:
    ctx.otlp.post("/_debug/reset")

    ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

    bodies = wait_until(lambda: _otel_traces_seen(ctx), timeout=30.0)
    assert bodies, (
        "no OTLP traces POST carrying otel_service_name reached otlp-stub; "
        "otel_exporter_endpoint is not wiring real telemetry"
    )
    assert any(b"smoke-otel-env" in body for body in bodies), (
        "otel_resource_attributes['deployment.environment'] never appeared in the "
        "exported OTLP traces payload"
    )


LOGFIRE_SERVICE_NAME = "smoke-logfire-service-gap"
LOGFIRE_CONFIG = {
    "enable_logfire": True,
    "logfire_service_name": LOGFIRE_SERVICE_NAME,
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


def _logfire_request_seen(ctx: ScenarioContext) -> bool:
    response = ctx.otlp.get("/_debug/state")
    response.raise_for_status()
    for request in response.json().get("requests", []):
        headers = {name.lower(): value for name, value in request["headers"].items()}
        if headers.get("user-agent", "").startswith("logfire/"):
            return True
    return False


@scenario(covers={"logfire_service_name"}, config=LOGFIRE_CONFIG)
def logfire_delivers_spans_to_its_configured_base_url(ctx: ScenarioContext) -> None:
    ctx.otlp.post("/_debug/reset")

    ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

    seen = wait_until(lambda: _logfire_request_seen(ctx), timeout=30.0)
    assert seen, (
        "no logfire-originated request (User-Agent: logfire/...) reached the "
        "OTLP stub; LOGFIRE_BASE_URL/logfire_service_name wiring is not working"
    )
