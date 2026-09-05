import json
from typing import Any

import httpx

from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

CONFIG = {
    "log_sensitive_headers": ["x-internal-token"],
    "log_sensitive_params": ["sig"],
    "log_sensitive_body_fields": ["ssn"],
    "enable_agent": True,
    "agent_api_key": "smoke-agent-key",
    "agent_endpoint": "http://agent-stub:8090",
    "agent_flush_interval": 2,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}

_BASE_HEADERS = {
    "Authorization": "Bearer LS-BEARER",
    "Cookie": "sid=LS-COOKIE",
    "X-API-Key": "LS-APIKEY",
    "Proxy-Authorization": "Basic LS-PROXYAUTH",
    "X-Internal-Token": "LS-INTERNAL",
}

_RAW_SECRETS = [
    "LS-BEARER",
    "LS-COOKIE",
    "LS-APIKEY",
    "LS-PROXYAUTH",
    "LS-INTERNAL",
    "LS-SIG",
    "LS-SSN-TOP",
    "LS-SSN-NESTED",
    "LS-SSN-FORM",
]
_MUST_STILL_SHOW = ["q=hello", "alert(1)"]
_MUST_APPEAR_ONCE = [
    "Request from",
    "Suspicious pattern in header 'x-internal-token'",
    "Suspicious pattern in query param 'sig'",
    "Suspicious pattern in ssn",
    "Suspicious pattern in note",
    "Rate limit exceeded for IP:",
    "Banned IP attempted access",
]


def _run_battery(client: httpx.Client) -> httpx.Response:
    client.get(
        "/basic/ip", params={"sig": "LS-SIG", "q": "hello"}, headers=_BASE_HEADERS
    )

    client.get("/rate/strict-limit", headers=_BASE_HEADERS)
    rate_limited = client.get("/rate/strict-limit", headers=_BASE_HEADERS)
    assert rate_limited.status_code == 429

    header_xss = dict(_BASE_HEADERS)
    header_xss["X-Internal-Token"] = "LS-INTERNAL-XSS<script>alert(1)</script>"
    client.get("/basic/ip", params={"sig": "LS-SIG", "q": "hello"}, headers=header_xss)

    query_xss_params = {"sig": "LS-SIGXSS<script>alert(1)</script>", "q": "hello"}
    client.get("/basic/ip", params=query_xss_params, headers=_BASE_HEADERS)

    client.post(
        "/basic/echo",
        params={"sig": "LS-SIG", "q": "hello"},
        headers=_BASE_HEADERS,
        json={
            "ssn": "LS-SSN-TOP<script>alert(1)</script>",
            "account": {"ssn": "LS-SSN-NESTED<script>alert(1)</script>"},
        },
    )

    client.post(
        "/basic/echo",
        params={"sig": "LS-SIG", "q": "hello"},
        headers={**_BASE_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        content="ssn=LS-SSN-FORM' OR 1=1--",
    )

    client.post(
        "/basic/echo",
        params={"sig": "LS-SIG", "q": "hello"},
        headers=_BASE_HEADERS,
        json={"note": "<script>alert(1)</script>"},
    )

    for _ in range(3):
        client.get("/basic/ip", params=query_xss_params, headers=_BASE_HEADERS)

    return client.get(
        "/basic/ip", params={"sig": "LS-SIG", "q": "hello"}, headers=_BASE_HEADERS
    )


def _assert_expected_lines_present(lines: list[str]) -> None:
    for expected in _MUST_APPEAR_ONCE:
        assert any(expected in line for line in lines), f"missing log line: {expected}"


def _assert_no_secret_leaked(text: str) -> None:
    assert "[REDACTED]" in text
    for secret in _RAW_SECRETS:
        assert secret not in text, f"raw secret {secret!r} leaked into the log"
    for marker in _MUST_STILL_SHOW:
        assert marker in text, f"non-sensitive marker {marker!r} missing from the log"


def _agent_events_seen(ctx: ScenarioContext) -> dict[str, Any] | None:
    response = ctx.agent.get("/_debug/state")
    if response.status_code != 200:
        return None
    state: dict[str, Any] = response.json()
    detections = [
        event
        for event in state.get("events", [])
        if event.get("event_type") == "pattern_detected"
    ]
    return state if detections else None


def _assert_no_secret_in_telemetry(ctx: ScenarioContext) -> None:
    state = wait_until(lambda: _agent_events_seen(ctx), timeout=30.0)
    assert state is not None, "no detection event reached the agent stub"
    dumped = json.dumps(state)
    for secret in _RAW_SECRETS:
        assert secret not in dumped, f"raw secret {secret!r} reached the agent stub"
    previews = [
        event.get("metadata", {}).get("content_preview")
        for event in state["events"]
        if event.get("event_type") == "pattern_detected"
    ]
    assert previews, "no pattern_detected event carried a content_preview"
    assert all(
        preview == "[REDACTED]" or "LS-" not in str(preview) for preview in previews
    ), previews


@scenario(
    covers={
        "log_sensitive_headers",
        "log_sensitive_params",
        "log_sensitive_body_fields",
    },
    config=CONFIG,
)
def sensitive_data_redacted_across_log_lines(ctx: ScenarioContext) -> None:
    ctx.agent.post("/_debug/reset")
    mark = ctx.stack.logs.mark()

    banned = _run_battery(ctx.client)
    assert banned.status_code == 403

    lines = ctx.stack.logs.lines_since(mark)
    guard_lines = [line for line in lines if " - guard_core" in line]
    _assert_expected_lines_present(guard_lines)
    _assert_no_secret_leaked("\n".join(guard_lines))
    _assert_no_secret_in_telemetry(ctx)
