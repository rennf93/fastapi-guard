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

## Buffer/flush sizing vs the 256 KiB ingestion cap

Do not raise `agent_buffer_size` toward thousands while shortening `agent_flush_interval`. The SaaS ingestion endpoint caps request bodies at 256 KiB, so a large buffer combined with a short interval can produce a batch that exceeds the cap and 413s. Keep the defaults (100 / 30s) or tune toward a smaller buffer and longer interval so a full batch stays well under 256 KiB.

If a batch does 413, guard-agent no longer requeues it: the transport raises `PayloadTooLargeError`, and `send_events`/`send_metrics` split the batch in half and retry each half recursively until each sub-batch is under the cap, or drop a single still-over-cap item with a warning and fire the `on_error` hook. Other permanent rejections (400/404/422) are likewise dropped with a warning, not requeued. Dropped and split batches are confirmed, so their Redis keys are deleted and the client never re-flushes them. Transient failures still return `False` and requeue with capped backoff as before.

Before the split-or-drop fix, a 413 was flattened to a generic `False` and the client requeued the whole oversized batch on every flush (serialize, encrypt, POST, 413, requeue), bounded only by the Redis TTL of 1h, wasting CPU and never landing the events. Sizing is still the primary defense; split-or-drop is the safety net.
