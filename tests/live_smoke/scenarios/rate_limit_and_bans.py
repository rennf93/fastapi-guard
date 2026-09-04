import os

import httpx

from tests.live_smoke.driver import STACK_DIR, ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]
CLIENT_IP = "192.168.50.50"

_TYPE_STRING = 2
_TYPE_UINT16 = 5
_TYPE_UINT32 = 6
_TYPE_MAP = 7
_TYPE_UINT64 = 9
_TYPE_ARRAY = 11
_NODE = "node"
_DATA = "data"


def _mmdb_control_byte(data_type: int, size: int) -> bytes:
    if data_type <= 7:
        return bytes([(data_type << 5) | size])
    return bytes([size, data_type - 7])


def _mmdb_encode_string(value: str) -> bytes:
    payload = value.encode("utf-8")
    return _mmdb_control_byte(_TYPE_STRING, len(payload)) + payload


def _mmdb_encode_uint(data_type: int, value: int, byte_len: int) -> bytes:
    raw = value.to_bytes(byte_len, "big").lstrip(b"\x00")
    return _mmdb_control_byte(data_type, len(raw)) + raw


def _mmdb_country_record(country: str) -> bytes:
    key = _mmdb_encode_string("country")
    value = _mmdb_encode_string(country)
    return _mmdb_control_byte(_TYPE_MAP, 1) + key + value


def _mmdb_metadata(node_count: int) -> bytes:
    entries: dict[str, bytes] = {
        "node_count": _mmdb_encode_uint(_TYPE_UINT32, node_count, 4),
        "record_size": _mmdb_encode_uint(_TYPE_UINT16, 24, 2),
        "ip_version": _mmdb_encode_uint(_TYPE_UINT16, 4, 2),
        "database_type": _mmdb_encode_string("guard-core-live-smoke"),
        "languages": _mmdb_control_byte(_TYPE_ARRAY, 1) + _mmdb_encode_string("en"),
        "binary_format_major_version": _mmdb_encode_uint(_TYPE_UINT16, 2, 2),
        "binary_format_minor_version": _mmdb_encode_uint(_TYPE_UINT16, 0, 2),
        "build_epoch": _mmdb_encode_uint(_TYPE_UINT64, 1_700_000_000, 8),
        "description": (
            _mmdb_control_byte(_TYPE_MAP, 1)
            + _mmdb_encode_string("en")
            + _mmdb_encode_string("guard-core-live-smoke")
        ),
    }
    body = _mmdb_control_byte(_TYPE_MAP, len(entries))
    for key, encoded_value in entries.items():
        body += _mmdb_encode_string(key) + encoded_value
    return body


def _build_single_entry_mmdb(ip: str, country: str) -> bytes:
    octets = [int(part) for part in ip.split(".")]
    bits = "".join(f"{octet:08b}" for octet in octets)

    nodes: list[list[tuple[str, int] | None]] = [[None, None]]
    node_idx = 0
    for position, bit in enumerate(bits):
        branch = int(bit)
        if position == len(bits) - 1:
            nodes[node_idx][branch] = (_DATA, 0)
        else:
            nodes.append([None, None])
            child_idx = len(nodes) - 1
            nodes[node_idx][branch] = (_NODE, child_idx)
            node_idx = child_idx

    node_count = len(nodes)
    data_section = _mmdb_country_record(country)

    def resolve(value: tuple[str, int] | None) -> int:
        if value is None:
            return node_count
        kind, payload = value
        if kind == _NODE:
            return payload
        return node_count + 16

    tree = bytearray()
    for left, right in nodes:
        tree += resolve(left).to_bytes(3, "big")
        tree += resolve(right).to_bytes(3, "big")

    return (
        bytes(tree)
        + b"\x00" * 16
        + data_section
        + b"\xab\xcd\xefMaxMind.com"
        + _mmdb_metadata(node_count)
    )


_GEO_CN_HOST_PATH = STACK_DIR / "scenario_data" / "rate_limit_geo_cn.mmdb"
GEO_CN_CONTAINER_PATH = "/smoke/rate_limit_geo_cn.mmdb"

if os.environ.get("LIVE_SMOKE") == "1":
    _GEO_CN_HOST_PATH.parent.mkdir(parents=True, exist_ok=True)
    _GEO_CN_HOST_PATH.write_bytes(_build_single_entry_mmdb(CLIENT_IP, "CN"))

GLOBAL_RATE_LIMIT_CONFIG = {
    "rate_limit": 3,
    "rate_limit_window": 60,
    "enable_rate_limiting": True,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"rate_limit", "rate_limit_window", "enable_rate_limiting"},
    config=GLOBAL_RATE_LIMIT_CONFIG,
)
def global_rate_limit_blocks_after_the_configured_request_count(
    ctx: ScenarioContext,
) -> None:
    client = ctx.client
    statuses = [client.get("/basic/health").status_code for _ in range(4)]
    assert statuses[:3] == [200, 200, 200], statuses
    assert statuses[3] == 429, statuses


ENDPOINT_RATE_LIMIT_CONFIG = {
    "endpoint_rate_limits": {"/basic/health": [2, 60]},
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"endpoint_rate_limits"}, config=ENDPOINT_RATE_LIMIT_CONFIG)
def endpoint_rate_limits_override_the_global_limit_per_path(
    ctx: ScenarioContext,
) -> None:
    client = ctx.client
    statuses = [client.get("/basic/health").status_code for _ in range(3)]
    assert statuses[:2] == [200, 200], statuses
    assert statuses[2] == 429, statuses


GEO_RATE_LIMIT_CONFIG = {
    "blocked_countries": ["ZZ"],
    "ipinfo_token": "smoke-token",
    "ipinfo_db_path": GEO_CN_CONTAINER_PATH,
    "rate_limit": 10000,
    "rate_limit_window": 60,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"geo_rate_limit"}, config=GEO_RATE_LIMIT_CONFIG)
def geo_rate_limit_applies_the_resolved_countrys_bucket(ctx: ScenarioContext) -> None:
    client = ctx.client
    statuses = [client.get("/rate/geo-rate-limit").status_code for _ in range(11)]
    assert all(status == 200 for status in statuses[:10]), statuses
    assert statuses[10] == 429, statuses


AUTO_BAN_CONFIG = {
    "auto_ban_threshold": 2,
    "auto_ban_duration": 6,
    "enable_ip_banning": True,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


def _is_not_banned(client: httpx.Client) -> bool:
    return client.get("/basic/ip", params={"q": "hello"}).status_code != 403


@scenario(
    covers={"auto_ban_threshold", "auto_ban_duration", "enable_ip_banning"},
    config=AUTO_BAN_CONFIG,
)
def auto_ban_threshold_and_duration_govern_penetration_bans(
    ctx: ScenarioContext,
) -> None:
    client = ctx.client
    xss_params = {"q": "<script>alert(1)</script>"}

    first = client.get("/basic/ip", params=xss_params)
    assert first.status_code == 400

    second = client.get("/basic/ip", params=xss_params)
    assert second.status_code == 403

    third = client.get("/basic/ip", params={"q": "hello"})
    assert third.status_code == 403

    assert wait_until(lambda: _is_not_banned(client), timeout=15.0, interval=1.0), (
        "IP stayed banned past auto_ban_duration"
    )


RATE_LIMIT_AUTOBAN_CONFIG = {
    "enable_rate_limiting": True,
    "rate_limit": 1,
    "rate_limit_window": 60,
    "enable_ip_banning": True,
    "enable_rate_limit_auto_ban": True,
    "threat_ban_config": {"rate_limit": {"threshold": 2, "duration": 8}},
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"enable_rate_limit_auto_ban", "threat_ban_config"},
    config=RATE_LIMIT_AUTOBAN_CONFIG,
)
def rate_limit_auto_ban_uses_the_configured_threat_ban_thresholds(
    ctx: ScenarioContext,
) -> None:
    client = ctx.client
    mark = ctx.stack.logs.mark()

    statuses = [client.get("/basic/health").status_code for _ in range(6)]

    assert 429 in statuses, statuses
    assert 403 in statuses, statuses

    lines = ctx.stack.logs.lines_since(mark)
    assert any("IP banned due to rate_limit threshold" in line for line in lines)
