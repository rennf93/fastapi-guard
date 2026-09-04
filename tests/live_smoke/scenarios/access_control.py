import os
from pathlib import Path

from tests.live_smoke.driver import STACK_DIR, ScenarioContext, wait_until
from tests.live_smoke.registry import scenario

CLIENT_IP = "192.168.50.50"
EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]

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


def _build_mmdb(entries: dict[str, str]) -> bytes:
    nodes: list[list[tuple[str, int] | None]] = [[None, None]]
    leaf_countries: dict[tuple[int, int], str] = {}

    def insert(ip: str, country: str) -> None:
        octets = [int(part) for part in ip.split(".")]
        bits = "".join(f"{octet:08b}" for octet in octets)
        node_idx = 0
        for position, bit in enumerate(bits):
            branch = int(bit)
            if position == len(bits) - 1:
                nodes[node_idx][branch] = (_DATA, 0)
                leaf_countries[(node_idx, branch)] = country
                continue
            child = nodes[node_idx][branch]
            if isinstance(child, tuple) and child[0] == _NODE:
                node_idx = child[1]
                continue
            nodes.append([None, None])
            child_idx = len(nodes) - 1
            nodes[node_idx][branch] = (_NODE, child_idx)
            node_idx = child_idx

    for ip, country in entries.items():
        insert(ip, country)

    node_count = len(nodes)

    data_section = b""
    data_offsets: dict[str, int] = {}
    for country in entries.values():
        if country not in data_offsets:
            data_offsets[country] = len(data_section)
            data_section += _mmdb_country_record(country)

    def resolve(node_idx: int, branch: int, value: tuple[str, int] | None) -> int:
        if value is None:
            return node_count
        kind, payload = value
        if kind == _NODE:
            return payload
        country = leaf_countries[(node_idx, branch)]
        return node_count + 16 + data_offsets[country]

    tree = bytearray()
    for idx, (left, right) in enumerate(nodes):
        tree += resolve(idx, 0, left).to_bytes(3, "big")
        tree += resolve(idx, 1, right).to_bytes(3, "big")

    return (
        bytes(tree)
        + b"\x00" * 16
        + data_section
        + b"\xab\xcd\xefMaxMind.com"
        + _mmdb_metadata(node_count)
    )


_GEO_DIR = STACK_DIR / "scenario_data"
_GEO_US_HOST_PATH = _GEO_DIR / "geo_smoke_us.mmdb"
_GEO_CN_HOST_PATH = _GEO_DIR / "geo_smoke_cn.mmdb"
GEO_US_CONTAINER_PATH = "/smoke/geo_smoke_us.mmdb"
GEO_CN_CONTAINER_PATH = "/smoke/geo_smoke_cn.mmdb"


def _write_geo_fixtures() -> None:
    _GEO_DIR.mkdir(parents=True, exist_ok=True)
    _GEO_US_HOST_PATH.write_bytes(_build_mmdb({CLIENT_IP: "US"}))
    _GEO_CN_HOST_PATH.write_bytes(_build_mmdb({CLIENT_IP: "CN"}))


def _geo_fixtures_path(path: Path) -> str:
    return str(path)


if os.environ.get("LIVE_SMOKE") == "1":
    _write_geo_fixtures()


WHITELIST_CONFIG = {
    "whitelist": [CLIENT_IP, "127.0.0.1"],
    "excluded_detection_headers": EXCLUDED_HEADERS,
}
BLACKLIST_CONFIG = {
    "blacklist": [CLIENT_IP],
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"whitelist", "ip_security"}, config=WHITELIST_CONFIG)
def global_whitelist_allows_the_client_ip(ctx: ScenarioContext) -> None:
    response = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert response.status_code == 200


@scenario(covers={"blacklist"}, config=BLACKLIST_CONFIG)
def global_blacklist_blocks_the_client_ip(ctx: ScenarioContext) -> None:
    response = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert response.status_code == 403


ACCESS_DECORATORS_CONFIG = {
    "blocked_user_agents": ["smoke-blocked-agent"],
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"blocked_user_agents", "block_user_agents", "user_agent", "require_ip"},
    config=ACCESS_DECORATORS_CONFIG,
)
def user_agent_and_require_ip_decorators_block_as_configured(
    ctx: ScenarioContext,
) -> None:
    client = ctx.client

    blocked_global = client.get(
        "/basic/ip",
        params={"q": "hello"},
        headers={"User-Agent": "smoke-blocked-agent/1.0"},
    )
    assert blocked_global.status_code == 403

    allowed_global = client.get(
        "/basic/ip", params={"q": "hello"}, headers={"User-Agent": "curl/8.0"}
    )
    assert allowed_global.status_code == 200

    blocked_decorator = client.get(
        "/content/no-bots", headers={"User-Agent": "some-crawler-9000"}
    )
    assert blocked_decorator.status_code == 403

    allowed_decorator = client.get(
        "/content/no-bots", headers={"User-Agent": "curl/8.0"}
    )
    assert allowed_decorator.status_code == 200

    blocked_ip = client.get("/access/ip-whitelist")
    assert blocked_ip.status_code == 403


CLOUD_CONFIG = {
    "cloud_ip_refresh_interval": 60,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={
        "block_clouds",
        "block_cloud_providers",
        "cloud_ip_refresh_interval",
        "cloud_ip_store",
        "cloud_provider",
        "cloud_ip_refresh",
    },
    config=CLOUD_CONFIG,
)
def cloud_provider_checks_do_not_block_a_private_ip(ctx: ScenarioContext) -> None:
    client = ctx.client
    for path in ("/access/no-cloud", "/access/no-aws", "/basic/ip"):
        response = client.get(path, params={"q": "hello"})
        assert response.status_code == 200, (path, response.status_code)

    keys = wait_until(lambda: ctx.redis.keys("smoke:cloud_ip_v2:*"), timeout=15.0)
    assert keys, "no cached cloud IP ranges were written by cloud_ip_store"


EMERGENCY_BLOCKED_CONFIG = {
    "emergency_mode": True,
    "emergency_whitelist": [],
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"emergency_mode"}, config=EMERGENCY_BLOCKED_CONFIG)
def emergency_mode_blocks_non_whitelisted_traffic(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()
    response = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert response.status_code == 503

    lines = ctx.stack.logs.lines_since(mark)
    assert any("[EMERGENCY MODE] Access denied" in line for line in lines)


EMERGENCY_WHITELIST_CONFIG = {
    "emergency_mode": True,
    "emergency_whitelist": [CLIENT_IP],
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"emergency_whitelist"}, config=EMERGENCY_WHITELIST_CONFIG)
def emergency_whitelist_allows_listed_ip_through(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()
    response = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert response.status_code == 200

    lines = ctx.stack.logs.lines_since(mark)
    assert any(
        "[EMERGENCY MODE] Allowed access for whitelisted IP" in line for line in lines
    )


GEO_CONFIG_ALLOW = {
    "blocked_countries": ["ZZ"],
    "ipinfo_token": "smoke-token",
    "ipinfo_db_path": _geo_fixtures_path(Path(GEO_US_CONTAINER_PATH)),
    "log_country_check_level": "ERROR",
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={
        "allow_countries",
        "block_countries",
        "log_country_check_level",
        "ipinfo_token",
        "ipinfo_db_path",
    },
    config=GEO_CONFIG_ALLOW,
)
def geo_country_rules_allow_and_log_a_resolved_country(ctx: ScenarioContext) -> None:
    client = ctx.client
    mark = ctx.stack.logs.mark()

    allowed = client.get("/access/country-allow", params={"q": "hello"})
    assert allowed.status_code == 200

    passthrough = client.get("/access/country-block", params={"q": "hello"})
    assert passthrough.status_code == 200

    plain = client.get("/basic/ip", params={"q": "hello"})
    assert plain.status_code == 200

    lines = ctx.stack.logs.lines_since(mark)
    assert any(
        "ERROR" in line and "IP not from blocked or whitelisted country" in line
        for line in lines
    )


GEO_CONFIG_BLOCK = {
    "blocked_countries": ["CN"],
    "ipinfo_token": "smoke-token",
    "ipinfo_db_path": _geo_fixtures_path(Path(GEO_CN_CONTAINER_PATH)),
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"block_countries", "allow_countries", "blocked_countries"},
    config=GEO_CONFIG_BLOCK,
)
def geo_country_rules_block_a_matching_resolved_country(ctx: ScenarioContext) -> None:
    client = ctx.client

    blocked_route = client.get("/access/country-block", params={"q": "hello"})
    assert blocked_route.status_code == 403

    mismatched_allow = client.get("/access/country-allow", params={"q": "hello"})
    assert mismatched_allow.status_code == 403

    blocked_global = client.get("/basic/ip", params={"q": "hello"})
    assert blocked_global.status_code == 403


GEO_CONFIG_WHITELIST = {
    "whitelist_countries": ["US"],
    "ipinfo_token": "smoke-token",
    "ipinfo_db_path": _geo_fixtures_path(Path(GEO_US_CONTAINER_PATH)),
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"whitelist_countries"}, config=GEO_CONFIG_WHITELIST)
def whitelist_countries_allows_a_matching_resolved_country(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()
    response = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert response.status_code == 200

    lines = ctx.stack.logs.lines_since(mark)
    assert any("IP from whitelisted country" in line for line in lines)
