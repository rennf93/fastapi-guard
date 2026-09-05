import json
from typing import Any

from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

AGENT_API_KEY = "smoke-agent-key"
AGENT_ENDPOINT = "http://agent-stub:8090"
EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]
BADBOT_HEADERS = {"User-Agent": "badbot"}
ON_ERROR_LOG = "/smoke/on_error.jsonl"


def _reset_agent(ctx: ScenarioContext) -> None:
    ctx.agent.post("/_debug/reset")


def _set_agent_delay(ctx: ScenarioContext, seconds: float) -> None:
    ctx.agent.post("/_debug/delay", json={"seconds": seconds})


def _set_agent_forced_status(ctx: ScenarioContext, code: int | None) -> None:
    ctx.agent.post("/_debug/status", json={"code": code})


def _debug_state(ctx: ScenarioContext) -> dict[str, Any]:
    response = ctx.agent.get("/_debug/state")
    response.raise_for_status()
    data: dict[str, Any] = response.json()
    return data


def _events_request(ctx: ScenarioContext) -> dict[str, Any] | None:
    for request in _debug_state(ctx).get("requests", []):
        if request.get("path") == "/api/v1/events":
            return dict(request)
    return None


def _high_water_mark(ctx: ScenarioContext) -> int:
    return int(_debug_state(ctx).get("high_water_mark", 0))


IDENTITY_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_install_id": "smoke-install-id-0001",
    "agent_payload_signing_secret": "smoke-signing-secret",
    "agent_guard_version": "smoke-guard-version-9.9.9",
    "agent_flush_interval": 2,
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"agent_install_id", "agent_payload_signing_secret", "agent_guard_version"},
    config=IDENTITY_CONFIG,
)
def agent_transport_identity_headers_and_envelope(ctx: ScenarioContext) -> None:
    _reset_agent(ctx)

    ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

    request = wait_until(lambda: _events_request(ctx), timeout=20.0)
    assert request is not None, "no /api/v1/events request reached the agent stub"

    headers = {name.lower(): value for name, value in request["headers"].items()}
    assert headers.get("x-agent-install-id") == "smoke-install-id-0001", headers
    signature = headers.get("x-payload-signature")
    assert signature and signature.startswith("v1="), (
        f"agent_payload_signing_secret should produce an X-Payload-Signature "
        f"header; got {signature!r}"
    )

    envelope = request["envelope"]
    assert envelope.get("guard_version") == "smoke-guard-version-9.9.9", envelope


TIMEOUT_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_timeout": 1,
    "agent_retry_attempts": 0,
    "agent_flush_interval": 2,
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


def _read_timeout_logged(ctx: ScenarioContext, mark: str) -> list[str]:
    return [
        line
        for line in ctx.stack.logs.lines_since(mark)
        if "HTTP client error for POST" in line and "ReadTimeout" in line
    ]


@scenario(covers={"agent_timeout"}, config=TIMEOUT_CONFIG)
def agent_timeout_bounds_transport_requests(ctx: ScenarioContext) -> None:
    _reset_agent(ctx)
    _set_agent_delay(ctx, 3.0)
    mark = ctx.stack.logs.mark()
    try:
        ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

        timed_out = wait_until(lambda: _read_timeout_logged(ctx, mark), timeout=15.0)
        assert timed_out, (
            "agent_timeout=1 with a 3s stub delay never logged a read timeout"
        )
    finally:
        _set_agent_delay(ctx, 0.0)

    healthy = ctx.client.get("/basic/health")
    assert healthy.status_code == 200, (
        "the app must stay healthy after an agent transport timeout"
    )


def _concurrency_config(max_concurrent_flushes: int) -> dict[str, object]:
    return {
        "enable_agent": True,
        "agent_api_key": AGENT_API_KEY,
        "agent_endpoint": AGENT_ENDPOINT,
        "agent_buffer_size": 4,
        "agent_high_watermark_ratio": 0.25,
        "agent_max_concurrent_flushes": max_concurrent_flushes,
        "agent_flush_interval": 120,
        "auto_ban_threshold": 1000,
        "rate_limit": 1000,
        "excluded_detection_headers": EXCLUDED_HEADERS,
    }


CONCURRENCY_CONFIG = _concurrency_config(1)
CONCURRENCY_CONFIG_WIDE = _concurrency_config(8)


def _burst_high_water_mark(ctx: ScenarioContext) -> int:
    _reset_agent(ctx)
    _set_agent_delay(ctx, 2.0)
    try:
        for _ in range(20):
            ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

        wait_until(lambda: _high_water_mark(ctx) >= 1, timeout=15.0)
    finally:
        _set_agent_delay(ctx, 0.0)

    return _high_water_mark(ctx)


@scenario(covers={"agent_max_concurrent_flushes"}, config=CONCURRENCY_CONFIG)
def agent_max_concurrent_flushes_bounds_in_flight_sends(ctx: ScenarioContext) -> None:
    narrow_mark = _burst_high_water_mark(ctx)

    ctx.stack.restart_with(CONCURRENCY_CONFIG_WIDE, force=True)
    wide_mark = _burst_high_water_mark(ctx)

    assert narrow_mark < wide_mark, (
        "agent_max_concurrent_flushes should bound in-flight event/metric POSTs; "
        f"narrow (max_concurrent_flushes=1) observed high_water_mark="
        f"{narrow_mark}, wide (max_concurrent_flushes=8) observed "
        f"high_water_mark={wide_mark}, expected narrow < wide"
    )


AGENT_CONFIG_WIRING_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_max_payload_size": 4096,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"agent_max_payload_size"}, config=AGENT_CONFIG_WIRING_CONFIG)
def agent_max_payload_size_reflected_in_effective_config(ctx: ScenarioContext) -> None:
    response = ctx.client.get("/smoke/agent-config")
    assert response.status_code == 200
    data = response.json()
    assert data.get("enabled") is True, data
    assert data.get("max_payload_size") == 4096, data


ON_ERROR_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_strict": False,
    "agent_retry_attempts": 0,
    "agent_flush_interval": 2,
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


def _on_error_log_has_transport_failure(ctx: ScenarioContext) -> bool:
    try:
        text = ctx.stack.container_file(ON_ERROR_LOG)
    except FileNotFoundError:
        return False
    return any(
        json.loads(line).get("stage") == "transport_send"
        for line in text.splitlines()
        if line.strip()
    )


@scenario(covers={"on_error"}, config=ON_ERROR_CONFIG)
def on_error_hook_records_transport_failure(ctx: ScenarioContext) -> None:
    _reset_agent(ctx)
    _set_agent_forced_status(ctx, 500)
    try:
        ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

        found = wait_until(
            lambda: _on_error_log_has_transport_failure(ctx), timeout=20.0
        )
        assert found, "on_error hook never recorded a transport_send failure"
    finally:
        _set_agent_forced_status(ctx, None)

    healthy = ctx.client.get("/basic/health")
    assert healthy.status_code == 200
