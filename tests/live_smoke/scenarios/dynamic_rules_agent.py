import json
from typing import Any

from tests.live_smoke.driver import ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

DYNAMIC_RULES_CACHE_PATH = "/tmp/guard-last-known-rules.json"
REDIS_KEY = "smoke:dynamic_rules:last_known"

CONFIG = {
    "enable_agent": True,
    "agent_api_key": "smoke-agent-key",
    "agent_endpoint": "http://agent-stub:8090",
    "agent_sensitive_headers": ["x-agent-secret"],
    "agent_flush_interval": 2,
    "enable_dynamic_rules": True,
    "dynamic_rules_cache_path": DYNAMIC_RULES_CACHE_PATH,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}


@scenario(
    covers={
        "enable_dynamic_rules",
        "dynamic_rules_cache_path",
        "enable_agent",
        "agent_api_key",
        "agent_endpoint",
        "agent_sensitive_headers",
        "agent_flush_interval",
    },
    config=CONFIG,
)
def dynamic_rules_and_agent_wiring(ctx: ScenarioContext) -> None:
    ctx.agent.post("/_debug/reset")
    mark = ctx.stack.logs.mark()

    stored = wait_until(lambda: ctx.redis.get(REDIS_KEY), timeout=20.0)
    assert stored, "no last-known dynamic rules snapshot was written to Redis"
    assert '"rule_id":"smoke-rule"' in stored.replace(" ", "")
    assert '"auto_ban_threshold":9' in stored.replace(" ", "")

    cache_content = wait_until(lambda: _read_cache_or_none(ctx), timeout=20.0)
    assert cache_content, "dynamic_rules_cache_path snapshot file was never written"
    assert '"rule_id":"smoke-rule"' in cache_content.replace(" ", "")

    error_lines = ctx.stack.logs.lines_since(mark, kind="Failed to")
    assert not error_lines, f"unexpected 'Failed to' error lines: {error_lines}"

    ctx.client.get(
        "/basic/ip",
        params={"q": "hello"},
        headers={
            "User-Agent": "badbot",
            "X-Agent-Secret": "LS-AGENT-SECRET-VALUE",
        },
    )

    state = wait_until(lambda: _debug_state_with_telemetry(ctx), timeout=25.0)
    assert state is not None, "agent stub recorded no events/status within 25s"
    dump = json.dumps(state)
    assert "LS-AGENT-SECRET-VALUE" not in dump, (
        "a header named in agent_sensitive_headers leaked into telemetry sent to "
        f"the agent: {dump}"
    )


def _read_cache_or_none(ctx: ScenarioContext) -> str | None:
    try:
        return ctx.stack.container_file(DYNAMIC_RULES_CACHE_PATH)
    except FileNotFoundError:
        return None


def _debug_state_with_telemetry(ctx: ScenarioContext) -> dict[str, Any] | None:
    response = ctx.agent.get("/_debug/state")
    if response.status_code != 200:
        return None
    data: dict[str, Any] = response.json()
    if not (data["events"] or data["status"]):
        return None
    return data
