---

title: Telemetry
description: OpenTelemetry, Logfire, and event/metric/log muting for FastAPI Guard

---

# Telemetry

FastAPI Guard emits security events and request metrics through a composable telemetry pipeline provided by [guard-core](https://github.com/rennf93/guard-core). Events can be muted, metrics can be muted, individual security-check logs can be muted, and exports to OpenTelemetry and Logfire are opt-in.

The middleware installs and tears down the telemetry pipeline automatically — you only set fields on `SecurityConfig`.

## Config surface

Nine `SecurityConfig` fields control telemetry:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `muted_event_types` | `set[str]` | `set()` | Suppress these event types from every exporter. |
| `muted_metric_types` | `set[str]` | `set()` | Suppress these metric types from every exporter. |
| `muted_check_logs` | `set[str]` | `set()` | Suppress pipeline + in-check log output for these checks. |
| `enable_otel` | `bool` | `False` | Enable OpenTelemetry span/metric export (requires `guard-core[otel]`). |
| `otel_service_name` | `str` | `"guard-core"` | Service name for OpenTelemetry resource. |
| `otel_exporter_endpoint` | `str \| None` | `None` | OTLP/HTTP endpoint. `None` uses OTel's default (`localhost:4318`). |
| `otel_resource_attributes` | `dict[str, str]` | `{}` | Extra OpenTelemetry resource attributes (e.g. `deployment.environment`, `service.version`). |
| `enable_logfire` | `bool` | `False` | Enable Logfire export (requires `guard-core[logfire]`). |
| `logfire_service_name` | `str` | `"guard-core"` | Service name for Logfire. |

All three mute fields validate their contents at config time. Unknown values raise `ValidationError` and the error message lists the valid values.

## Valid mute values

Drawn from constants in `guard_core.core.events.event_types`:

- **`muted_event_types`** — `access_denied`, `authentication_failed`, `behavior_violation`, `cloud_blocked`, `content_filtered`, `country_blocked`, `csp_violation`, `custom_request_check`, `decoding_error`, `decorator_violation`, `dynamic_rule_applied`, `dynamic_rule_updated`, `emergency_mode_activated`, `emergency_mode_block`, `geo_lookup_failed`, `https_enforced`, `ip_banned`, `ip_blocked`, `ip_unbanned`, `path_excluded`, `pattern_added`, `pattern_detected`, `pattern_removed`, `penetration_attempt`, `rate_limited`, `redis_connection`, `redis_error`, `security_bypass`, `security_headers_applied`, `user_agent_blocked`
- **`muted_metric_types`** — `error_rate`, `request_count`, `response_time`
- **`muted_check_logs`** — `authentication`, `cloud_ip_refresh`, `cloud_provider`, `custom_request`, `custom_validators`, `emergency_mode`, `https_enforcement`, `ip_security`, `rate_limit`, `referrer`, `request_logging`, `request_size_content`, `required_headers`, `route_config`, `suspicious_activity`, `time_window`, `user_agent`

## Muting events, metrics, and check logs

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

config = SecurityConfig(
    muted_event_types={"penetration_attempt"},
    muted_metric_types={"response_time"},
    muted_check_logs={"rate_limit", "user_agent"},
)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)
```

- `muted_event_types` short-circuits events before any exporter sees them.
- `muted_metric_types` short-circuits metrics before any exporter sees them.
- `muted_check_logs` suppresses both the pipeline's block/error log entries *and* the in-check `log_activity()` calls — both are gated on the same set.

## Enabling OpenTelemetry

=== "uv"

    ```bash
    uv add fastapi-guard "guard-core[otel]"
    ```

=== "poetry"

    ```bash
    poetry add fastapi-guard "guard-core[otel]"
    ```

=== "pip"

    ```bash
    pip install fastapi-guard "guard-core[otel]"
    ```

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

config = SecurityConfig(
    enable_otel=True,
    otel_service_name="guard-prod",
    otel_exporter_endpoint="http://otel-collector.internal:4318",
    otel_resource_attributes={
        "deployment.environment": "prod",
        "service.version": "1.2.0",
    },
)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)
```

If `otel_resource_attributes` contains a `service.name` key it overrides `otel_service_name` (last-write-wins). Prefer setting the service name via `otel_service_name` and use `otel_resource_attributes` only for environment/version/region tags.

Incoming W3C `traceparent` headers are continued automatically — guard spans become children of the caller's trace. `tracestate` headers are forwarded alongside when present.

Three instruments are emitted when OTel is enabled:

- `guard.request.duration` (histogram, seconds)
- `guard.request.count` (counter)
- `guard.error.count` (counter)

Any other metric type produces a one-line warning and is dropped.

## Enabling Logfire

=== "uv"

    ```bash
    uv add fastapi-guard "guard-core[logfire]"
    ```

=== "poetry"

    ```bash
    poetry add fastapi-guard "guard-core[logfire]"
    ```

=== "pip"

    ```bash
    pip install fastapi-guard "guard-core[logfire]"
    ```

```python
from fastapi import FastAPI
from guard import SecurityMiddleware, SecurityConfig

config = SecurityConfig(
    enable_logfire=True,
    logfire_service_name="guard-prod",
)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)
```

Events are emitted as `logfire.span("guard.event.<event_type>", ...)` and metrics as structured logs via `logfire.info("guard.metric.<metric_type>", value=..., endpoint=..., **tags)`. When both `enable_otel` and `enable_logfire` are set, Logfire also observes the OpenTelemetry instruments automatically via its OTel bridge.

## Incoming `traceparent`

When `enable_otel=True` and the request carries a W3C `traceparent` header, the guard event bus copies it into the event's metadata. The OTel handler extracts it with `TraceContextTextMapPropagator` and sets the resumed context as the parent of `guard.event.<event_type>` spans. This preserves the upstream trace across the guard layer.

## Troubleshooting

### Spans don't show up in your OTel backend

1. Verify `enable_otel=True` is set on `SecurityConfig`.
2. Check `python -c "import opentelemetry.sdk"` — if it raises `ImportError`, the handler logs `opentelemetry-sdk not installed, OTEL handler disabled` on startup.
3. Confirm `otel_exporter_endpoint` points to an OTLP/HTTP receiver on port `4318` (not `4317` — that's gRPC).
4. Confirm the middleware is installed via `app.add_middleware(SecurityMiddleware, config=config)` and not bypassed by a competing middleware.

### Events aren't muted even though `muted_event_types` is set

Confirm the value is in the **Valid mute values** list above. A typo silently fails validation if the field is used elsewhere — check the startup logs for a `ValidationError`.

### `logfire.info()` warning: "No logs or spans will be created until `logfire.configure()` has been called"

Guard Core configures Logfire inside the middleware startup lifecycle. If the warning appears at runtime, the middleware has not yet started — verify `enable_logfire=True` is on the `SecurityConfig` passed to `add_middleware`.

### `ValidationError` on startup mentioning an unknown check/event/metric

The error message lists the valid values. Common typos: `"suspicious"` instead of `"suspicious_activity"`, `"latency"` instead of `"response_time"`.

## Reference

The full field schema and pipeline behaviour is maintained in the [guard-core telemetry reference](https://github.com/rennf93/guard-core/blob/master/docs/architecture/telemetry.md).
