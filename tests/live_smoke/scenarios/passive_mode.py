from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

CONFIG = {
    "passive_mode": True,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}


@scenario(covers={"passive_mode"}, config=CONFIG)
def passive_mode_flags_without_blocking(ctx: ScenarioContext) -> None:
    client = ctx.client
    mark = ctx.stack.logs.mark()

    response = client.get(
        "/basic/ip",
        params={"token": "LSPASSIVE<script>alert(1)</script>", "q": "hello"},
    )
    assert response.status_code == 200

    lines = ctx.stack.logs.lines_since(mark)
    assert any(
        "[PASSIVE MODE] Penetration attempt detected from" in line for line in lines
    )
