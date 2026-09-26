from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

CLIENT_IP = "192.168.50.50"
EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]

# The pipeline's global rate limit keys the sliding window at
# {prefix}rate_limit:rate:{ip} (guard_core ratelimit_handler); the stack
# runs with REDIS_PREFIX=smoke:.
RATE_LIMIT_BUCKET = f"smoke:rate_limit:rate:{CLIENT_IP}"

EXEMPT_RATE_LIMIT_CONFIG = {
    "rate_limit": 2,
    "rate_limit_window": 60,
    "enable_rate_limiting": True,
    "exempt_ips": [CLIENT_IP],
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"exempt_ips"}, config=EXEMPT_RATE_LIMIT_CONFIG)
def exempt_ip_exceeds_the_rate_limit_without_being_throttled(
    ctx: ScenarioContext,
) -> None:
    client = ctx.client

    statuses = [client.get("/basic/health").status_code for _ in range(4)]
    assert statuses == [200, 200, 200, 200], statuses

    # The exempt skip sits ahead of the limiter in the pipeline, so no
    # shared bucket is ever written for the exempt IP.
    assert ctx.redis.exists(RATE_LIMIT_BUCKET) == 0, "exempt IP wrote a rate bucket"

    # Exemption is not immunity: penetration detection still applies.
    attack = client.get("/basic/ip", params={"q": "<script>alert(1)</script>"})
    assert attack.status_code == 400


NON_EXEMPT_RATE_LIMIT_CONFIG = {
    "rate_limit": 2,
    "rate_limit_window": 60,
    "enable_rate_limiting": True,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(
    covers={"rate_limit", "rate_limit_window", "enable_rate_limiting"},
    config=NON_EXEMPT_RATE_LIMIT_CONFIG,
)
def the_same_limit_throttles_a_non_exempt_client(ctx: ScenarioContext) -> None:
    client = ctx.client

    statuses = [client.get("/basic/health").status_code for _ in range(3)]
    assert statuses[:2] == [200, 200], statuses
    assert statuses[2] == 429, statuses

    # Contrast pin for the exempt scenario above: without the exemption the
    # limiter owns a bucket for this IP at the crossing.
    assert ctx.redis.exists(RATE_LIMIT_BUCKET) == 1, "missing rate bucket"


BLACKLIST_OVERRIDES_EXEMPTION_CONFIG = {
    "exempt_ips": [CLIENT_IP],
    "blacklist": [CLIENT_IP],
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"blacklist"}, config=BLACKLIST_OVERRIDES_EXEMPTION_CONFIG)
def blacklist_beats_exemption(ctx: ScenarioContext) -> None:
    response = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert response.status_code == 403
