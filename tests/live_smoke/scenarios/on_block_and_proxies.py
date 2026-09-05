import ipaddress
import json
import re

from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

ON_BLOCK_LOG = "/tmp/smoke-on-block.jsonl"

CONFIG: dict[str, object] = {
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}

_REQUEST_FROM_RE = re.compile(
    r"Request from (?P<ip>[0-9a-fA-F:.]+): (?P<method>\S+) (?P<url>\S+)"
)


def _assert_client_ip_resolved_through_proxy(match: re.Match[str]) -> None:
    ip = ipaddress.ip_address(match.group("ip"))
    assert ip.is_private, (
        f"client_ip {ip} resolved from nginx's X-Real-IP/X-Forwarded-For is not "
        "a private/proxy address; trusted_proxies resolution looks wrong"
    )
    assert match.group("url").startswith("http://"), (
        "trust_x_forwarded_proto did not carry nginx's X-Forwarded-Proto into "
        f"the logged URL: {match.group('url')}"
    )


def _assert_request_lines_show_trusted_proxy_ip(lines: list[str]) -> None:
    matches = [m for m in (_REQUEST_FROM_RE.search(line) for line in lines) if m]
    assert matches, "no 'Request from' line was captured"
    for match in matches:
        _assert_client_ip_resolved_through_proxy(match)


def _assert_on_block_recorded_the_user_agent_block(ctx: ScenarioContext) -> None:
    on_block_text = ctx.stack.container_file(ON_BLOCK_LOG)
    entries = [json.loads(line) for line in on_block_text.splitlines() if line.strip()]
    matching = [
        entry
        for entry in entries
        if entry.get("check_name") == "user_agent" and entry.get("status_code") == 403
    ]
    assert matching, f"on_block never recorded a user_agent block; seen: {entries[-5:]}"


@scenario(
    covers={
        "on_block",
        "trusted_proxies",
        "trusted_proxy_depth",
        "trust_x_forwarded_proto",
    },
    config=CONFIG,
)
def on_block_and_trusted_proxies(ctx: ScenarioContext) -> None:
    client = ctx.client
    mark = ctx.stack.logs.mark()

    clean = client.get("/basic/ip", params={"q": "hello"})
    assert clean.status_code == 200

    blocked = client.get(
        "/basic/ip", params={"q": "hello"}, headers={"User-Agent": "badbot"}
    )
    assert blocked.status_code == 403

    _assert_request_lines_show_trusted_proxy_ip(ctx.stack.logs.lines_since(mark))
    _assert_on_block_recorded_the_user_agent_block(ctx)
