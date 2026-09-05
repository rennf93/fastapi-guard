from typing import Any

from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]
UNRESOLVED_PATH = "/this-path-does-not-exist-smoke"
BADBOT_HEADERS = {"User-Agent": "badbot"}

RESPONSE_CUSTOMIZATION_CONFIG = {
    "custom_error_responses": {"403": "SMOKE_CUSTOM_403_BODY"},
    "route_resolution_strict": True,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


def _assert_route_resolution_strict(ctx: ScenarioContext, mark: str) -> None:
    unresolved = ctx.client.get(UNRESOLVED_PATH)
    assert unresolved.status_code == 500, (
        "route_resolution_strict=True should turn an unroutable path into a 500, "
        f"got {unresolved.status_code}"
    )
    lines = ctx.stack.logs.lines_since(mark)
    assert any("Route resolution failed" in line for line in lines)


def _assert_resolved_route_and_response_modifier(ctx: ScenarioContext) -> None:
    resolved = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert resolved.status_code == 200, (
        "route_resolution_strict=True must not affect an already-resolved route"
    )
    assert resolved.headers.get("X-Content-Type-Options") == "nosniff", (
        "custom_response_modifier should stamp X-Content-Type-Options, which "
        "the base security_headers config never sets on its own"
    )


def _assert_custom_request_check(ctx: ScenarioContext) -> None:
    debug_blocked = ctx.client.get("/basic/ip", params={"q": "hello", "debug": "true"})
    assert debug_blocked.status_code == 403
    assert debug_blocked.json()["detail"] == "Debug mode not allowed", (
        "custom_request_check should intercept ?debug=true before the handler runs"
    )


def _assert_custom_error_response(ctx: ScenarioContext) -> None:
    badbot_blocked = ctx.client.get(
        "/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS
    )
    assert badbot_blocked.status_code == 403
    assert badbot_blocked.text == "SMOKE_CUSTOM_403_BODY", (
        "custom_error_responses[403] should replace the default block message"
    )


def _assert_excluded_paths_skip_user_agent_check(ctx: ScenarioContext) -> None:
    health_with_badbot = ctx.client.get("/health", headers=BADBOT_HEADERS)
    assert health_with_badbot.status_code == 200, (
        "exclude_paths should keep /health out of the user_agent check"
    )

    docs_with_badbot = ctx.client.get("/docs", headers=BADBOT_HEADERS)
    assert docs_with_badbot.status_code == 200, (
        "exclude_paths should keep /docs out of the user_agent check"
    )


@scenario(
    covers={
        "custom_error_responses",
        "custom_request_check",
        "custom_response_modifier",
        "route_resolution_strict",
        "exclude_paths",
    },
    config=RESPONSE_CUSTOMIZATION_CONFIG,
)
def pipeline_response_customization_and_route_resolution(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    _assert_route_resolution_strict(ctx, mark)
    _assert_resolved_route_and_response_modifier(ctx)
    _assert_custom_request_check(ctx)
    _assert_custom_error_response(ctx)
    _assert_excluded_paths_skip_user_agent_check(ctx)


BYPASS_CONFIG = {
    "rate_limit": 3,
    "rate_limit_window": 60,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"bypass"}, config=BYPASS_CONFIG)
def bypass_decorator_skips_rate_limit_on_its_route(ctx: ScenarioContext) -> None:
    bypass_statuses = [
        ctx.client.get("/access/bypass-demo").status_code for _ in range(6)
    ]
    assert all(status == 200 for status in bypass_statuses), (
        "@guard.bypass(['rate_limit', 'ip']) should never hit the global "
        f"rate_limit=3/60s; statuses={bypass_statuses}"
    )

    limited_statuses = [
        ctx.client.get("/basic/ip", params={"q": "hello"}).status_code for _ in range(6)
    ]
    assert 429 in limited_statuses, (
        "a non-bypassed route should hit the global rate_limit=3/60s; "
        f"statuses={limited_statuses}"
    )


AGENT_WIRING_CONFIG = {
    "enable_agent": True,
    "agent_api_key": "smoke-agent-key",
    "agent_endpoint": "http://agent-stub:8090",
    "agent_flush_interval": 2,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


def _state_with_behavioral_violation(ctx: ScenarioContext) -> dict[str, Any] | None:
    response = ctx.agent.get("/_debug/state")
    if response.status_code != 200:
        return None
    state: dict[str, Any] = response.json()
    matches = any(
        event.get("event_type") == "behavioral_violation"
        for event in state.get("events", [])
    )
    return state if matches else None


def _fire_usage_monitor_burst(ctx: ScenarioContext) -> None:
    for _ in range(11):
        ctx.client.get("/behavior/usage-monitor")


@scenario(covers={"initialize_agent"}, config=AGENT_WIRING_CONFIG)
def decorator_agent_wiring_via_behavior_tracker(ctx: ScenarioContext) -> None:
    ctx.agent.post("/_debug/reset")
    _fire_usage_monitor_burst(ctx)

    state = wait_until(lambda: _state_with_behavioral_violation(ctx), timeout=15.0)
    if state is None:
        _fire_usage_monitor_burst(ctx)
        state = wait_until(lambda: _state_with_behavioral_violation(ctx), timeout=30.0)

    assert state is not None, (
        "SecurityDecorator.initialize_agent must wire behavior_tracker.agent_handler "
        "so a crossed usage_monitor threshold reaches the agent stub"
    )
