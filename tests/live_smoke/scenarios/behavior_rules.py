import json

from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

_BASE = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}


def _lines_mentioning(ctx: ScenarioContext, mark: str, needle: str) -> list[str]:
    return [line for line in ctx.stack.logs.lines_since(mark) if needle in line]


def _unique_config(rate_limit: int) -> dict[str, object]:
    return {**_BASE, "rate_limit": rate_limit}


@scenario(covers={"usage_monitor"}, config=_unique_config(1101))
def usage_monitor_logs_without_blocking(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()

    for _ in range(11):
        response = ctx.client.get("/behavior/usage-monitor")
        assert response.status_code == 200, (
            f"usage_monitor(action='log') blocked a request: {response.status_code}"
        )

    assert _lines_mentioning(
        ctx, mark, "Behavioral anomaly detected: Usage threshold exceeded: 10 calls"
    ), "usage_monitor never logged the threshold-exceeded warning"


@scenario(covers={"suspicious_frequency"}, config=_unique_config(1102))
def suspicious_frequency_throttle_logs_without_blocking(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()

    for _ in range(10):
        response = ctx.client.get("/behavior/suspicious-frequency")
        assert response.status_code == 200, (
            "suspicious_frequency(action='throttle') blocked a request: "
            f"{response.status_code}"
        )

    assert _lines_mentioning(ctx, mark, "Throttling IP"), (
        "suspicious_frequency never logged a throttle warning"
    )


@scenario(covers={"honeypot_detection"}, config=_unique_config(1103))
def honeypot_detection_blocks_bot_filled_field(ctx: ScenarioContext) -> None:
    clean = ctx.client.post("/advanced/honeypot", json={"input": "hello"})
    assert clean.status_code == 200, (
        f"honeypot_detection blocked a clean submission: {clean.status_code}"
    )

    filled = ctx.client.post(
        "/advanced/honeypot",
        json={"input": "hello", "honeypot_field": "bot-filled-this"},
    )
    assert filled.status_code == 403, (
        f"honeypot_detection did not block a filled honeypot field: "
        f"{filled.status_code}"
    )


@scenario(covers={"return_monitor"}, config=_unique_config(1104))
def return_monitor_decorator_allows_non_matching_status(
    ctx: ScenarioContext,
) -> None:
    for _ in range(4):
        response = ctx.client.get("/behavior/return-monitor/200")
        assert response.status_code == 200, (
            "return_monitor(pattern='status:404') interfered with a "
            f"non-matching status: {response.status_code}"
        )


@scenario(covers={"behavior_analysis"}, config=_unique_config(1105))
def behavior_analysis_logs_frequency_rule_violation(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()

    for _ in range(11):
        response = ctx.client.post("/behavior/behavior-rules")
        assert response.status_code == 200, (
            "behavior_analysis's frequency rule (action='throttle') blocked a "
            f"request: {response.status_code}"
        )

    assert _lines_mentioning(ctx, mark, "Usage threshold exceeded: 10 calls in 60s"), (
        "behavior_analysis never logged the frequency rule violation"
    )


_GLOBAL_RULE_CONFIG = {
    **_BASE,
    "behavior_scan_response_body": True,
    "behavior_max_response_body_inspect_bytes": 65536,
    "global_behavior_rules": [
        {
            "rule_type": "return_pattern",
            "threshold": 3,
            "window": 60,
            "pattern": "json:message==Echo response",
            "action": "ban",
            "ban_duration": 30,
        }
    ],
}


def _echo_status(ctx: ScenarioContext) -> int:
    return ctx.client.post("/basic/echo", json={"note": "hello"}).status_code


def _banned(ctx: ScenarioContext) -> bool:
    return _echo_status(ctx) == 403


@scenario(
    covers={
        "global_behavior_rules",
        "behavior_scan_response_body",
        "behavior_max_response_body_inspect_bytes",
    },
    config=_GLOBAL_RULE_CONFIG,
)
def global_behavior_rules_bans_after_response_body_pattern_match(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    for _ in range(4):
        _echo_status(ctx)

    banned = wait_until(lambda: _banned(ctx), timeout=10.0)
    assert banned, "global_behavior_rules never banned the client after 4 matches"

    matched = _lines_mentioning(
        ctx,
        mark,
        "Global return pattern threshold exceeded: 3 for 'json:message==Echo response'",
    )
    assert matched, (
        "no log line recorded the global return_pattern rule match; "
        f"recent lines: {json.dumps(ctx.stack.logs.lines_since(mark)[-10:])}"
    )
