from tests.live_smoke.driver import ScenarioContext
from tests.live_smoke.registry import scenario

_BASE = {
    "auto_ban_threshold": 1000,
    "rate_limit": 1000,
    "excluded_detection_headers": ["x-real-ip", "x-forwarded-for"],
}


def _unique_config(rate_limit: int) -> dict[str, object]:
    return {**_BASE, "rate_limit": rate_limit}


@scenario(
    covers={"max_request_size", "request_size_content"}, config=_unique_config(1201)
)
def max_request_size_decorator_blocks_oversized_body(ctx: ScenarioContext) -> None:
    within_limit = ctx.client.post("/content/size-limit", json={"data": "x" * 100})
    assert within_limit.status_code == 200, (
        f"a body under max_request_size was blocked: {within_limit.status_code}"
    )

    oversized = ctx.client.post(
        "/content/size-limit", json={"data": "x" * (1024 * 100 + 1)}
    )
    assert oversized.status_code == 413, (
        f"a body over max_request_size was not blocked: {oversized.status_code}"
    )


@scenario(covers={"content_type_filter"}, config=_unique_config(1202))
def content_type_filter_decorator_blocks_disallowed_content_type(
    ctx: ScenarioContext,
) -> None:
    allowed = ctx.client.post(
        "/content/json-only",
        content=b'{"hello": "world"}',
        headers={"Content-Type": "application/json"},
    )
    assert allowed.status_code == 200, (
        f"content_type_filter blocked an allowed content type: {allowed.status_code}"
    )

    disallowed = ctx.client.post(
        "/content/json-only",
        content=b"hello=world",
        headers={"Content-Type": "text/plain"},
    )
    assert disallowed.status_code == 415, (
        "content_type_filter did not block a disallowed content type: "
        f"{disallowed.status_code}"
    )


@scenario(
    covers={"custom_validation", "custom_validators"}, config=_unique_config(1203)
)
def custom_validation_decorator_blocks_matching_user_agent(
    ctx: ScenarioContext,
) -> None:
    clean = ctx.client.get(
        "/content/custom-validation", headers={"User-Agent": "regular-client"}
    )
    assert clean.status_code == 200, (
        f"custom_validation blocked a non-matching user agent: {clean.status_code}"
    )

    matching = ctx.client.get(
        "/content/custom-validation",
        headers={"User-Agent": "suspicious-pattern-bot"},
    )
    assert matching.status_code == 403, (
        f"custom_validation did not block a matching user agent: {matching.status_code}"
    )


@scenario(covers={"custom_request"}, config=_unique_config(1204))
def custom_request_hook_blocks_debug_flag(ctx: ScenarioContext) -> None:
    clean = ctx.client.get("/basic/ip", params={"q": "hello"})
    assert clean.status_code == 200, (
        f"a plain request was blocked by the custom_request hook: {clean.status_code}"
    )

    debug = ctx.client.get("/basic/ip", params={"debug": "true"})
    assert debug.status_code == 403, (
        f"custom_request did not block ?debug=true: {debug.status_code}"
    )


@scenario(
    covers={"route_config", "get_route_config"},
    config={**_BASE, "route_resolution_strict": True},
)
def route_config_strict_mode_blocks_unresolved_route(ctx: ScenarioContext) -> None:
    mark = ctx.stack.logs.mark()

    resolved = ctx.client.get("/content/no-bots")
    assert resolved.status_code == 200, (
        "route_resolution_strict blocked a normally-resolvable decorated route: "
        f"{resolved.status_code}"
    )

    unresolved = ctx.client.get("/this-path-does-not-exist-anywhere")
    assert unresolved.status_code == 500, (
        "route_resolution_strict did not turn an unresolved path into a 500: "
        f"{unresolved.status_code}"
    )

    lines = ctx.stack.logs.lines_since(mark)
    assert any(
        "Route resolution failed; per-route decorator config could not be applied"
        in line
        for line in lines
    ), "no route_config unresolved-route warning was logged"


_CORS_CONFIG = {
    **_BASE,
    "cors_allow_origins": ["https://allowed.example.com"],
    "cors_allow_methods": ["GET"],
    "cors_allow_headers": ["*"],
    "cors_allow_credentials": False,
    "cors_expose_headers": ["x-total-count"],
    "cors_max_age": 120,
}


def _assert_allowed_preflight(ctx: ScenarioContext) -> None:
    response = ctx.client.options(
        "/basic/ip",
        headers={
            "Origin": "https://allowed.example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-custom-header",
        },
    )
    assert response.status_code == 200, (
        "a preflight from an allowed origin/method/header was rejected: "
        f"{response.status_code} {response.text}"
    )
    assert (
        response.headers.get("access-control-allow-origin")
        == "https://allowed.example.com"
    )
    assert response.headers.get("access-control-allow-methods") == "GET"
    assert response.headers.get("access-control-max-age") == "120"
    assert response.headers.get("access-control-allow-headers") == "x-custom-header"


def _assert_disallowed_preflight(ctx: ScenarioContext) -> None:
    response = ctx.client.options(
        "/basic/ip",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 400, (
        f"a preflight from a disallowed origin was accepted: {response.status_code}"
    )
    assert "access-control-allow-origin" not in response.headers


def _assert_simple_allowed_origin(ctx: ScenarioContext) -> None:
    response = ctx.client.get(
        "/basic/ip",
        params={"q": "hello"},
        headers={"Origin": "https://allowed.example.com"},
    )
    assert response.status_code == 200
    assert (
        response.headers.get("access-control-allow-origin")
        == "https://allowed.example.com"
    )
    assert response.headers.get("access-control-expose-headers") == "x-total-count"


def _assert_simple_disallowed_origin(ctx: ScenarioContext) -> None:
    response = ctx.client.get(
        "/basic/ip",
        params={"q": "hello"},
        headers={"Origin": "https://evil.example.com"},
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


@scenario(
    covers={
        "enable_cors",
        "cors_allow_origins",
        "cors_allow_methods",
        "cors_allow_headers",
        "cors_expose_headers",
        "cors_max_age",
        "request_logging",
    },
    config=_CORS_CONFIG,
)
def cors_settings_control_preflight_and_simple_responses(
    ctx: ScenarioContext,
) -> None:
    mark = ctx.stack.logs.mark()

    _assert_allowed_preflight(ctx)
    _assert_disallowed_preflight(ctx)
    _assert_simple_allowed_origin(ctx)
    _assert_simple_disallowed_origin(ctx)

    lines = ctx.stack.logs.lines_since(mark)
    assert any("Request from" in line for line in lines), (
        "request_logging never produced a 'Request from' line"
    )


@scenario(
    covers={"cors_allow_credentials"},
    config={
        **_BASE,
        "cors_allow_origins": ["https://allowed.example.com"],
        "cors_allow_credentials": True,
    },
)
def cors_allow_credentials_adds_credentials_header(ctx: ScenarioContext) -> None:
    response = ctx.client.get(
        "/basic/ip",
        params={"q": "hello"},
        headers={"Origin": "https://allowed.example.com"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-credentials") == "true", (
        "cors_allow_credentials=True did not add the credentials header"
    )


_SECURITY_HEADERS_OVERRIDE = {
    "enabled": True,
    "hsts": {"max_age": 31536000, "include_subdomains": True, "preload": False},
    "csp": None,
    "frame_options": "SAMEORIGIN",
    "content_type_options": "nosniff",
    "xss_protection": "1; mode=block",
    "referrer_policy": "strict-origin-when-cross-origin",
    "permissions_policy": "geolocation=(), microphone=(), camera=()",
    "custom": {"X-Smoke-Test": "yes"},
}


@scenario(
    covers={"security_headers"},
    config={**_BASE, "security_headers": _SECURITY_HEADERS_OVERRIDE},
)
def security_headers_override_reflected_in_response(ctx: ScenarioContext) -> None:
    response = ctx.client.get("/basic/health")
    assert response.status_code == 200
    assert response.headers.get("x-smoke-test") == "yes", (
        "security_headers.custom was not applied to the response"
    )
