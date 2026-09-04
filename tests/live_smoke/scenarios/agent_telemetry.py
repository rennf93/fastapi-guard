import base64
import time
from typing import Any

from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

AGENT_API_KEY = "smoke-agent-key"
AGENT_ENDPOINT = "http://agent-stub:8090"
UNREACHABLE_ENDPOINT = "http://127.0.0.1:9"
EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]
BADBOT_HEADERS = {"User-Agent": "badbot"}
ENCRYPTION_KEY = base64.urlsafe_b64encode(b"0" * 32).decode()


def _reset_agent(ctx: ScenarioContext) -> None:
    ctx.agent.post("/_debug/reset")


def _debug_state(ctx: ScenarioContext) -> dict[str, Any] | None:
    response = ctx.agent.get("/_debug/state")
    if response.status_code != 200:
        return None
    return dict(response.json())


def _find_event(state: dict[str, Any], event_type: str) -> dict[str, Any] | None:
    for event in state.get("events", []):
        if event.get("event_type") == event_type:
            return dict(event)
    return None


def _state_with_event_type(
    ctx: ScenarioContext, event_type: str
) -> dict[str, Any] | None:
    state = _debug_state(ctx)
    if state is None or _find_event(state, event_type) is None:
        return None
    return state


def _state_with_metric_type(
    ctx: ScenarioContext, metric_type: str
) -> dict[str, Any] | None:
    state = _debug_state(ctx)
    if state is None:
        return None
    has_metric = any(
        metric.get("metric_type") == metric_type for metric in state.get("metrics", [])
    )
    return state if has_metric else None


def _lines_containing(ctx: ScenarioContext, mark: str, needle: str) -> list[str]:
    return [line for line in ctx.stack.logs.lines_since(mark) if needle in line]


def _rule_apply_count(ctx: ScenarioContext) -> int:
    text = ctx.stack.logs.full_text()
    boundary = text.rfind("Starting gunicorn")
    current_boot = text[boundary:] if boundary >= 0 else text
    return current_boot.count("Applying dynamic rules: smoke-rule v")


def _state_with_status(ctx: ScenarioContext) -> dict[str, Any] | None:
    state = _debug_state(ctx)
    if state is None or not state.get("status"):
        return None
    return state


AGENT_ENRICHMENT_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_flush_interval": 2,
    "agent_project_id": "smoke-enrich-project",
    "enable_enrichment": True,
    "agent_compression_enabled": True,
    "agent_compression_threshold": 1,
    "agent_enable_events": True,
    "agent_enable_metrics": False,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={
        "agent_project_id",
        "enable_enrichment",
        "agent_compression_enabled",
        "agent_compression_threshold",
        "agent_enable_events",
        "agent_enable_metrics",
    },
    config=AGENT_ENRICHMENT_CONFIG,
)
def agent_enrichment_metadata_and_compressed_delivery(ctx: ScenarioContext) -> None:
    _reset_agent(ctx)

    ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

    state = wait_until(
        lambda: _state_with_event_type(ctx, "user_agent_blocked"), timeout=20.0
    )
    assert state is not None, "no user_agent_blocked event reached the agent stub"

    event = _find_event(state, "user_agent_blocked")
    assert event is not None
    metadata = event.get("metadata") or {}
    assert metadata.get("guard.project_id") == "smoke-enrich-project", metadata
    assert metadata.get("guard.threat_score") == 30, metadata
    assert "guard.service.name" in metadata, metadata
    assert "guard.behavior.recent_event_count" in metadata, metadata
    assert state.get("metrics") == [], (
        "agent_enable_metrics=False should keep the metrics batch empty"
    )


AGENT_MUTED_TYPES_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_flush_interval": 2,
    "agent_enable_events": True,
    "agent_enable_metrics": True,
    "muted_event_types": ["user_agent_blocked"],
    "muted_metric_types": ["request_count"],
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"muted_event_types", "muted_metric_types"},
    config=AGENT_MUTED_TYPES_CONFIG,
)
def agent_muted_types_suppress_telemetry(ctx: ScenarioContext) -> None:
    _reset_agent(ctx)

    ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

    state = wait_until(
        lambda: _state_with_metric_type(ctx, "response_time"), timeout=20.0
    )
    assert state is not None, "response_time metric never reached the agent stub"

    assert not any(
        event.get("event_type") == "user_agent_blocked"
        for event in state.get("events", [])
    ), "muted_event_types=['user_agent_blocked'] failed to suppress the event"
    assert not any(
        metric.get("metric_type") == "request_count"
        for metric in state.get("metrics", [])
    ), "muted_metric_types=['request_count'] failed to suppress the metric"


AGENT_STRICT_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_buffer_size": 0,
    "agent_strict": False,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"agent_strict", "agent_buffer_size"},
    config=AGENT_STRICT_CONFIG,
)
def agent_strict_false_degrades_gracefully(ctx: ScenarioContext) -> None:
    response = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert response.status_code == 200, (
        "agent_strict=False must keep the app healthy even when agent "
        "construction fails (agent_buffer_size=0 is invalid)"
    )

    log_text = ctx.stack.logs.full_text()
    assert "Failed to initialize Guard Agent" in log_text
    assert "Continuing without agent functionality" in log_text


AGENT_WATERMARK_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_buffer_size": 10,
    "agent_high_watermark_ratio": 0.2,
    "agent_flush_interval": 120,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"agent_high_watermark_ratio"},
    config=AGENT_WATERMARK_CONFIG,
)
def agent_high_watermark_triggers_early_flush(ctx: ScenarioContext) -> None:
    _reset_agent(ctx)

    ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)
    ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

    state = wait_until(
        lambda: _state_with_event_type(ctx, "user_agent_blocked"), timeout=15.0
    )
    assert state is not None, (
        "agent_high_watermark_ratio=0.2 on a buffer_size=10 buffer should flush "
        "after 2 buffered events, well before the 120s flush_interval"
    )


AGENT_DROP_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_buffer_size": 2,
    "agent_buffer_overflow_policy": "drop",
    "agent_high_watermark_ratio": 2.0,
    "agent_flush_interval": 120,
    "auto_ban_threshold": 1000,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"agent_buffer_overflow_policy"}, config=AGENT_DROP_CONFIG)
def agent_buffer_overflow_policy_drops_oldest_event(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()

    for _ in range(5):
        ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

    dropped = wait_until(
        lambda: _lines_containing(ctx, mark, "dropping oldest event"), timeout=15.0
    )
    assert dropped, (
        "agent_buffer_overflow_policy='drop' should evict the oldest event once "
        "agent_buffer_size=2 fills up; agent_high_watermark_ratio=2.0 and "
        "agent_flush_interval=120 keep any flush from draining the buffer first"
    )


AGENT_RETRY_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": UNREACHABLE_ENDPOINT,
    "agent_buffer_size": 10,
    "agent_high_watermark_ratio": 0.1,
    "agent_retry_attempts": 1,
    "agent_backoff_factor": 2.0,
    "agent_flush_interval": 120,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"agent_retry_attempts", "agent_backoff_factor"},
    config=AGENT_RETRY_CONFIG,
)
def agent_retry_attempts_and_backoff_factor_are_bounded(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()
    start = time.monotonic()

    ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

    attempt_two = wait_until(
        lambda: _lines_containing(ctx, mark, "Attempt 2 failed for events"),
        timeout=40.0,
    )
    elapsed = time.monotonic() - start
    assert attempt_two, "agent_retry_attempts=1 should have produced a 2nd attempt"
    assert elapsed >= 1.0, (
        f"agent_backoff_factor=2.0 should delay the 2nd attempt by ~2s, "
        f"observed {elapsed:.2f}s total"
    )
    assert not _lines_containing(ctx, mark, "Attempt 3 failed for events"), (
        "agent_retry_attempts=1 should cap retries at 2 total attempts"
    )


AGENT_ENCRYPTION_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_project_encryption_key": ENCRYPTION_KEY,
    "agent_retry_attempts": 0,
    "agent_flush_interval": 2,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"agent_project_encryption_key"},
    config=AGENT_ENCRYPTION_CONFIG,
)
def agent_project_encryption_key_targets_encrypted_endpoint(
    ctx: ScenarioContext,
) -> None:
    _reset_agent(ctx)
    mark = ctx.stack.logs.mark()

    ctx.client.get("/basic/ip", params={"q": "hello"}, headers=BADBOT_HEADERS)

    rejected = wait_until(
        lambda: _lines_containing(ctx, mark, "permanently rejected (404)"),
        timeout=15.0,
    )
    assert rejected, (
        "agent_project_encryption_key should route events to "
        "/api/v1/events/encrypted, which this stub does not implement (404)"
    )

    state = _debug_state(ctx)
    assert state is not None and state.get("events") == [], (
        "the plain agent stub must never decode an encrypted payload"
    )


AGENT_INTERVAL_CONFIG = {
    "enable_agent": True,
    "agent_api_key": AGENT_API_KEY,
    "agent_endpoint": AGENT_ENDPOINT,
    "agent_status_interval": 60,
    "enable_dynamic_rules": True,
    "dynamic_rule_interval": 60,
    "agent_flush_interval": 5,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"agent_status_interval", "dynamic_rule_interval"},
    config=AGENT_INTERVAL_CONFIG,
)
def agent_status_and_dynamic_rule_interval_cadence(ctx: ScenarioContext) -> None:
    _reset_agent(ctx)

    first_fetch = wait_until(lambda: _rule_apply_count(ctx) >= 1, timeout=40.0)
    assert first_fetch, "no initial dynamic-rule fetch happened at startup"

    too_soon = wait_until(lambda: _rule_apply_count(ctx) >= 2, timeout=8.0)
    assert not too_soon, (
        "dynamic_rule_interval=60 should not refire within 8s of the first fetch"
    )

    state = wait_until(lambda: _state_with_status(ctx), timeout=90.0)
    assert state is not None, (
        "agent_status_interval=60 should have posted a status report to the "
        "agent stub by now"
    )
