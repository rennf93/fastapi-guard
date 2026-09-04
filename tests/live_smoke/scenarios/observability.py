from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

OTEL_AND_LOGFIRE_CONFIG = {
    "enable_otel": True,
    "otel_service_name": "smoke-otel-service",
    "otel_exporter_endpoint": "http://otlp-stub:4318",
    "otel_resource_attributes": {"deployment.environment": "smoke"},
    "enable_logfire": True,
    "logfire_service_name": "smoke-logfire-service",
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}


def _otlp_requests_seen(ctx: ScenarioContext) -> int | None:
    response = ctx.otlp.get("/_debug/state")
    if response.status_code != 200:
        return None
    count = len(response.json().get("requests", []))
    return count or None


@scenario(
    covers={"enable_otel", "enable_logfire"},
    config=OTEL_AND_LOGFIRE_CONFIG,
)
def otel_and_logfire_handlers_start_with_extras_installed(
    ctx: ScenarioContext,
) -> None:
    ctx.otlp.post("/_debug/reset")
    mark = ctx.stack.logs.mark()
    response = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert response.status_code == 200, (
        "enabling otel and logfire must not break the request pipeline"
    )

    log_text = "\n".join(ctx.stack.logs.lines_since(mark))
    assert "OTEL handler disabled" not in log_text, (
        "opentelemetry-sdk is installed in the image, the handler must start"
    )
    assert "Logfire handler disabled" not in log_text, (
        "logfire is installed in the image, the handler must start"
    )

    seen = wait_until(lambda: _otlp_requests_seen(ctx), timeout=30.0)
    assert seen, "no export reached otlp-stub after enabling otel and logfire"
