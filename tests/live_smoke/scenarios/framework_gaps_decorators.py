from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]
BASE_CONFIG = {"excluded_detection_headers": EXCLUDED_HEADERS}


@scenario(covers={"require_authorization_header"}, config=BASE_CONFIG)
def require_authorization_header_enforces_presence_only(ctx: ScenarioContext) -> None:
    client = ctx.client

    missing = client.get("/smoke/authz-header")
    assert missing.status_code == 401, missing.status_code

    present = client.get(
        "/smoke/authz-header", headers={"Authorization": "Bearer anything-at-all"}
    )
    assert present.status_code == 200, present.status_code


@scenario(covers={"detection_exclusion"}, config=BASE_CONFIG)
def detection_exclusion_skips_the_named_param(ctx: ScenarioContext) -> None:
    client = ctx.client
    attack = "<script>alert(1)</script>"

    excluded = client.get("/smoke/detection-exclusion", params={"safe_marker": attack})
    assert excluded.status_code == 200, (
        f"detection_exclusion(params={{'safe_marker'}}) still blocked an attack in "
        f"the excluded param: {excluded.status_code}"
    )

    scanned = client.get(
        "/smoke/detection-exclusion", params={"safe_marker": "hello", "q": attack}
    )
    assert scanned.status_code == 400, (
        f"a non-excluded query param on the same route stopped being scanned: "
        f"{scanned.status_code}"
    )


@scenario(covers={"require_auth"}, config=BASE_CONFIG)
def require_auth_decorator_rejects_missing_bearer_token(ctx: ScenarioContext) -> None:
    client = ctx.client

    missing = client.get("/auth/bearer-auth")
    assert missing.status_code == 401

    present = client.get(
        "/auth/bearer-auth", headers={"Authorization": "Bearer smoke-token"}
    )
    assert present.status_code == 200


AGENT_EVENTS_CONFIG = {
    "enable_agent": True,
    "agent_api_key": "smoke-agent-key",
    "agent_endpoint": "http://agent-stub:8090",
    "agent_flush_interval": 2,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}

_EXPECTED_EVENT_TYPES = {
    "smoke_decorator_event",
    "decorator_violation",
    "access_denied",
    "authentication_failed",
    "rate_limited",
}


def _event_types_seen(ctx: ScenarioContext) -> set[str] | None:
    response = ctx.agent.get("/_debug/state")
    if response.status_code != 200:
        return None
    events = response.json().get("events", [])
    seen = {event.get("event_type") for event in events}
    return seen if _EXPECTED_EVENT_TYPES & seen else None


@scenario(
    covers={
        "send_decorator_event",
        "send_decorator_violation_event",
        "send_access_denied_event",
        "send_authentication_failed_event",
        "send_rate_limit_event",
        "initialize_behavior_tracking",
    },
    config=AGENT_EVENTS_CONFIG,
)
def decorator_event_helpers_reach_the_agent(ctx: ScenarioContext) -> None:
    ctx.agent.post("/_debug/reset")

    response = ctx.client.get("/smoke/decorator-events")
    assert response.status_code == 200, response.status_code
    assert response.json() == {"triggered": True}

    seen = wait_until(lambda: _event_types_seen(ctx), timeout=20.0)
    assert seen is not None, (
        "none of the SecurityDecorator send_*_event helpers reached the agent stub"
    )
    assert _EXPECTED_EVENT_TYPES <= seen, (
        f"expected every one of {_EXPECTED_EVENT_TYPES}, got {seen}"
    )
