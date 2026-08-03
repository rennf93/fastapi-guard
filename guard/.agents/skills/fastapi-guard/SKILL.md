---
name: fastapi-guard
description: Production-ready security middleware for FastAPI. Use when adding IP filtering, rate limiting, per-route security decorators, route-resolution strict mode, global behavior rules, passive/log-only mode, or Guard Agent SaaS telemetry to a FastAPI app. Covers SecurityMiddleware setup, SecurityConfig tuning, and the guard-agent buffer/flush footgun.
---

# FastAPI Guard

Security middleware for FastAPI: IP filtering, rate limiting, signature-based attack-pattern detection, and 20+ per-route security decorators. Import package is `guard` (distribution name `fastapi-guard`).

## Quick Reference

* Install: `uv add fastapi-guard` (or `pip install fastapi-guard`). Optional SaaS telemetry: `pip install fastapi-guard[agent]`.
* Add the middleware on `FastAPI` with `SecurityMiddleware(app, config=SecurityConfig(...))`; see [Setup](#setup).
* IP filtering: `whitelist` (restrictive) and `blacklist` (CIDR/IP); see [the IP filtering reference](references/ip-filtering.md).
* Rate limiting: `enable_rate_limiting`, `rate_limit`, `rate_limit_window`, `endpoint_rate_limits`; see [the rate limiting reference](references/rate-limiting.md).
* Per-route rules: compose `SecurityDecorator` decorators (`@guard.rate_limit(...)`, `@guard.ip_filter(...)`, etc.).
* Strict routing: `route_resolution_strict=True` blocks unresolved routes instead of passing them through; see [the route resolution reference](references/route-resolution.md).
* Global behavior rules: `global_behavior_rules` apply to every route (e.g. 404 watchers); see [the route resolution reference](references/route-resolution.md).
* Passive mode: `passive_mode=True` logs but never blocks; see [Passive Mode](#passive-mode).
* Guard Agent telemetry: `enable_agent=True` plus the `agent_*` fields; see [the agent integration reference](references/agent-integration.md).

## Setup

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

app = FastAPI()

config = SecurityConfig(
    enable_rate_limiting=True,
    rate_limit=30,
    rate_limit_window=60,
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    block_cloud_providers={"AWS", "GCP", "Azure"},
)

app.add_middleware(SecurityMiddleware, config=config)
```

For production, wire `guard.lifespan.guard_lifespan` into `FastAPI(lifespan=...)` so initialization runs at app startup instead of on the first request:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware
from guard.lifespan import guard_lifespan

config = SecurityConfig(enable_rate_limiting=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with guard_lifespan(app, config):
        yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(SecurityMiddleware, config=config)
```

`SecurityMiddleware` is a Starlette `BaseHTTPMiddleware`. Construct one `SecurityConfig` and pass the same instance to both the middleware and the lifespan.

## Per-Route Security Decorators

Compose rules at the endpoint level with `SecurityDecorator`:

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityDecorator

config = SecurityConfig()
guard = SecurityDecorator(config)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)


@app.get("/api/payments")
@guard.rate_limit(max_requests=10, window_seconds=60)
@guard.require_auth
async def list_payments():
    return []
```

Decorators are composable and stack top-down. Each one writes a per-route `RouteConfig` that the middleware resolves at request time.

## IP Filtering

`whitelist` is restrictive: when non-empty, only listed IPs/CIDRs pass the global IP check. `blacklist` is enforced ahead of country and cloud-provider checks. An explicit whitelist match overrides the blacklist; dynamic IP bans still apply to both.

```python
config = SecurityConfig(
    whitelist=["10.0.0.0/8", "192.168.1.1"],
    blacklist=["203.0.113.0/24"],
    enable_ip_banning=True,
    auto_ban_threshold=5,
    auto_ban_duration=86400,
)
```

See [the IP filtering reference](references/ip-filtering.md) for country rules, cloud-provider blocking, and the geo IP handler.

## Rate Limiting

Global limit plus optional per-endpoint overrides. Redis is used for distributed state when `enable_redis=True` (default); without Redis, limits are per-process.

```python
config = SecurityConfig(
    enable_rate_limiting=True,
    rate_limit=100,
    rate_limit_window=60,
    endpoint_rate_limits={"/api/login": (5, 60)},
)
```

See [the rate limiting reference](references/rate-limiting.md) for the decorator form and Redis notes.

## Route Resolution Strict Mode

By default (`route_resolution_strict=False`), a request whose route cannot be resolved runs the pipeline with no per-route config, so undecorated routes and unrouted paths pass through. Set `True` when every request must be attributable to a known route:

```python
config = SecurityConfig(route_resolution_strict=True)
```

Note: this also turns requests to paths the app does not serve into 500s instead of 404s. See [the route resolution reference](references/route-resolution.md).

## Global Behavior Rules

`global_behavior_rules` apply to every route in addition to any decorator-specified rules. Useful for global 404 watchers or request-volume thresholds:

```python
from guard import BehaviorRule, SecurityConfig

config = SecurityConfig(
    global_behavior_rules=[
        BehaviorRule(action="log", reason="global_404_watch"),
    ],
)
```

See [the route resolution reference](references/route-resolution.md) for rule shape and ordering.

## Passive Mode

`passive_mode=True` runs every check in log-only mode: suspicious requests are logged but never blocked. Use it to trial rules against production traffic before enforcing them.

```python
config = SecurityConfig(
    passive_mode=True,
    global_behavior_rules=[BehaviorRule(action="log", reason="shadow")],
)
```

Switch to `passive_mode=False` once the log output shows the rules firing on the traffic you expect.

## Guard Agent Telemetry

`enable_agent=True` ships security events and metrics to the Guard SaaS. Requires the `guard-agent` package (`pip install fastapi-guard[agent]`). Without it installed, the middleware degrades to agent-off unless `agent_strict=True` raises at init.

```python
config = SecurityConfig(
    enable_agent=True,
    agent_api_key="...",
    agent_project_id="...",
    agent_buffer_size=100,
    agent_flush_interval=30,
)
```

The buffer/flush defaults (100 events, 30s) are safe. Do not raise `agent_buffer_size` toward thousands while shortening `agent_flush_interval` — see [the agent integration reference](references/agent-integration.md) for the 413 requeue footgun.

## Exports

`guard` re-exports the public surface from `guard_core`: `SecurityMiddleware`, `SecurityConfig`, `SecurityDecorator`, `RouteConfig`, `BehaviorRule`, `BehaviorTracker`, `IPBanManager`, `RateLimitManager`, `RedisManager`, `GeoIPHandler`, `GuardRequest`, `GuardResponse`, `GuardResponseFactory`, `SecurityHeadersManager`, `CloudManager`, and the singletons `cloud_handler`, `ip_ban_manager`, `rate_limit_handler`, `redis_handler`, `security_headers_manager`, `sus_patterns_handler`.

## Tooling

* Docs: https://rennf93.github.io/fastapi-guard/latest/
* Playground: https://playground.guard-core.com
* Dashboard: https://app.guard-core.com
* Use `uv` for package management and Ruff for linting when applicable.