from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

CONFIG = {"excluded_detection_headers": ["x-real-ip", "x-forwarded-for"]}


@scenario(covers={"excluded_detection_headers"}, config=CONFIG)
def excluded_detection_headers_proxy_identity(ctx: ScenarioContext) -> None:
    client = ctx.client
    mark = ctx.stack.logs.mark()

    response = client.get("/basic/ip", params={"q": "hello"})

    lines = ctx.stack.logs.lines_since(mark)
    flagged = [
        line for line in lines if "Suspicious pattern in header 'x-real-ip'" in line
    ]

    assert response.status_code == 200, (
        "a plain request through nginx was blocked even though x-real-ip is in "
        f"excluded_detection_headers; response={response.status_code} lines={lines}"
    )
    assert not flagged, (
        "excluded_detection_headers did not stop the private-IP pattern from "
        f"matching the proxy's own x-real-ip value: {flagged}"
    )
