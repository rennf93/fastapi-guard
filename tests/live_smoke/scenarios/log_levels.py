from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

CONFIG = {
    "log_suspicious_level": "ERROR",
    "log_request_level": "ERROR",
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}


@scenario(covers={"log_suspicious_level", "log_request_level"}, config=CONFIG)
def suspicious_and_request_log_levels_change_verbosity(ctx: ScenarioContext) -> None:
    client = ctx.client
    mark = ctx.stack.logs.mark()

    client.get("/basic/ip", params={"q": "hello"})
    blocked = client.get(
        "/basic/ip", params={"q": "hello"}, headers={"User-Agent": "badbot"}
    )
    assert blocked.status_code == 403

    lines = ctx.stack.logs.lines_since(mark)
    assert any("ERROR" in line and "Request from" in line for line in lines), (
        "log_request_level=ERROR did not raise the request line's level"
    )
    assert any(
        "ERROR" in line and "Suspicious activity detected" in line for line in lines
    ), "log_suspicious_level=ERROR did not raise the suspicious line's level"
