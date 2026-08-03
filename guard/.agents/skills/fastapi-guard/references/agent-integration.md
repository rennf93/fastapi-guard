# Guard Agent Integration

`enable_agent=True` ships security events and metrics to the Guard SaaS (`api.guard-core.com` by default). Requires the `guard-agent` package:

```bash
pip install fastapi-guard[agent]
```

## Required settings

```python
from guard import SecurityConfig

config = SecurityConfig(
    enable_agent=True,
    agent_api_key="gc_...",
    agent_project_id="proj_...",
)
```

If `guard-agent` is not installed, the middleware degrades to agent-off and logs a warning. Set `agent_strict=True` to raise at middleware init instead of degrading.

## Buffer and flush

```python
config = SecurityConfig(
    enable_agent=True,
    agent_api_key="...",
    agent_buffer_size=100,
    agent_flush_interval=30,
)
```

* `agent_buffer_size` (`int`, default `100`): number of events buffered before an automatic flush.
* `agent_flush_interval` (`int`, default `30`): seconds between automatic flushes.

A flush sends the whole buffer as a single POST to `/api/v1/events` (or `/api/v1/events/encrypted` when `agent_project_encryption_key` is set).

## Other agent fields

* `agent_endpoint` (`str`, default `https://api.guard-core.com`): SaaS ingestion endpoint.
* `agent_timeout` (`int`, default `30`): per-request HTTP timeout.
* `agent_retry_attempts` (`int`, default `3`): retries for transient failures.
* `agent_enable_events` / `agent_enable_metrics` (`bool`, default `True` each): toggle the two telemetry streams.
* `agent_project_encryption_key` (`str | None`, default `None`): base64 256-bit AES-256-GCM key. When set, payloads are encrypted client-side and posted to `/api/v1/events/encrypted`.
* `agent_guard_version` (`str | None`): wrapper version propagated for attribution. fastapi-guard sets this from `guard.__version__` at construction.
* `agent_status_interval` (`int`, default `300`, range 60..86400): seconds between status reports.
* `enable_dynamic_rules` / `dynamic_rule_interval` (`bool` / `int`, default `False` / `300`): pull rule updates from the SaaS.
* `on_error` (`Callable | None`): best-effort callback `(stage, exception, context)` for `agent_init`, `geoip`, `transport_send`, `encryption` failures.

## Buffer/flush footgun (413 requeue loop)

Do not raise `agent_buffer_size` toward thousands while shortening `agent_flush_interval`. The SaaS ingestion endpoint caps request bodies at 256 KiB, so a large buffer combined with a short interval produces a batch that always 413s. Keep the defaults (100 / 30s) or tune toward a smaller buffer and longer interval.

Mechanism, verified against `guard-agent`:

1. The transport layer treats 413 as non-retryable. `_NON_RETRYABLE_STATUS_CODES = (400, 404, 413, 422)`; a 413 raises `PermanentClientError` and `_send_with_retry` drops the batch within that call (logs "Dropping ... batch; non-retryable 413", returns `False`). It does not retry inside the transport.
2. The client layer treats that `False` as a partial failure: `requeue_events_in_memory` puts the whole batch back in the in-memory buffer and the Redis keys are retained, then a retry-after is set with backoff (capped at 300s).
3. On the next flush, the same oversized batch is serialized, encrypted, and POSTed again, 413s again, and is requeued again. There is no split and no client-side drop, so the batch recurs until the Redis TTL (3600s) evicts it.

So the loop is not infinite in the tight sense (backoff up to 300s, bounded by Redis TTL of 1h), but the batch is never split or dropped at the client, so each cycle wastes serialize + encrypt + POST and the events never land. The fix is sizing: pick a buffer small enough that a full batch stays under 256 KiB (the defaults do), and a `agent_flush_interval` long enough that the buffer fills gradually.