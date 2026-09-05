import json

from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

CUSTOM_LOG_FILE = "/tmp/smoke-custom.log"

CONFIG = {
    "log_format": "json",
    "custom_log_file": CUSTOM_LOG_FILE,
    "muted_check_logs": ["user_agent"],
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}


def _assert_muted_check_suppressed_the_line(stdout_lines: list[str]) -> None:
    assert not any("Blocked user agent: badbot" in line for line in stdout_lines), (
        "muted_check_logs=['user_agent'] did not suppress the block log line"
    )


def _assert_custom_log_file_has_json_entries(ctx: ScenarioContext) -> list[dict]:
    file_content = ctx.stack.container_file(CUSTOM_LOG_FILE)
    entries = [json.loads(line) for line in file_content.splitlines() if line.strip()]
    assert entries, "custom_log_file produced no entries"
    for entry in entries:
        assert set(entry) >= {"timestamp", "level", "logger", "message"}
    return entries


def _assert_json_entries_reflect_the_battery(entries: list[dict]) -> None:
    assert any("Request from" in entry["message"] for entry in entries)
    assert not any(
        "Blocked user agent: badbot" in entry["message"] for entry in entries
    )


@scenario(covers={"log_format", "custom_log_file", "muted_check_logs"}, config=CONFIG)
def log_format_json_file_and_muted_checks(ctx: ScenarioContext) -> None:
    client = ctx.client
    mark = ctx.stack.logs.mark()

    client.get("/basic/ip", params={"q": "hello"})
    blocked = client.get(
        "/basic/ip", params={"q": "hello"}, headers={"User-Agent": "badbot"}
    )
    assert blocked.status_code == 403

    _assert_muted_check_suppressed_the_line(ctx.stack.logs.lines_since(mark))
    entries = _assert_custom_log_file_has_json_entries(ctx)
    _assert_json_entries_reflect_the_battery(entries)
