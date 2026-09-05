import json
import re

from tests.live_smoke.driver import (
    ScenarioContext,
    run_in_app_container,
    send_slow_body,
)
from tests.live_smoke.registry import scenario

EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]

COMPILER_TIMEOUT_CONFIG = {"excluded_detection_headers": EXCLUDED_HEADERS}

_COMPILER_TIMEOUT_PROBE = """
import asyncio
import logging
import time

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")

from guard_core.handlers.suspatterns_handler import sus_patterns_handler


class _SmokeConfig:
    detection_compiler_timeout = 0.1


class _SlowPattern:
    pattern = "smoke-slow-pattern-probe"

    def search(self, content, pos=0):
        time.sleep(5)
        return None


sus_patterns_handler._config = _SmokeConfig()


async def main():
    start = time.monotonic()
    match, timed_out = await sus_patterns_handler._check_pattern_with_timeout(
        _SlowPattern(), "irrelevant", "203.0.113.9", start
    )
    elapsed = time.monotonic() - start
    print(f"SMOKE_COMPILER_TIMEOUT_PROBE match={match} timed_out={timed_out} "
          f"elapsed={elapsed:.3f}", flush=True)


asyncio.run(main())
"""


@scenario(covers={"detection_compiler_timeout"}, config=COMPILER_TIMEOUT_CONFIG)
def detection_compiler_timeout_cuts_off_a_slow_pattern_match(
    ctx: ScenarioContext,
) -> None:
    result = run_in_app_container(_COMPILER_TIMEOUT_PROBE, timeout=20.0)
    output = result.stdout + result.stderr

    assert "SMOKE_COMPILER_TIMEOUT_PROBE" in output, (
        f"the detection_compiler_timeout probe did not complete; output: {output!r}"
    )
    assert "timed_out=True" in output, (
        "detection_compiler_timeout=0.1 did not cut off a pattern match "
        f"whose search() call took 5s; probe output: {output!r}"
    )
    assert "elapsed=0.1" in output, (
        "the match should have been cut off close to the configured 0.1s "
        f"budget, not the full 5s search duration; probe output: {output!r}"
    )
    assert (
        "Regex timeout exceeded for pattern" in output
        or "Pattern timeout:" in output
        or "Pattern exceeded scan time budget" in output
    ), (
        "detection_compiler_timeout's cutoff did not produce its documented "
        f"warning log line; probe output: {output!r}"
    )


BODY_READ_TIMEOUT_CONFIG = {
    "body_read_timeout": 0.5,
    "excluded_detection_headers": EXCLUDED_HEADERS,
}


@scenario(covers={"body_read_timeout"}, config=BODY_READ_TIMEOUT_CONFIG)
def body_read_timeout_skips_detection_on_a_stalled_body(ctx: ScenarioContext) -> None:
    payload = b'{"note": "<script>alert(1)</script>"}'

    fast_status, _headers, _body = send_slow_body(
        "/basic/echo", {"Content-Type": "application/json"}, payload, stall_seconds=0.0
    )
    assert fast_status == 400, (
        "the same body without a stall should still be blocked by detection, "
        f"got {fast_status}"
    )

    slow_status, _headers, slow_body = send_slow_body(
        "/basic/echo", {"Content-Type": "application/json"}, payload, stall_seconds=2.0
    )
    assert slow_status == 200, (
        "body_read_timeout=0.5 with a 2s stalled body should let the request "
        "through: guard-core's own body read gives up and treats the body as "
        f"unavailable for detection; got {slow_status} body={slow_body!r}"
    )


_SYNC_CONCURRENCY_PROBE = """
import json
import threading
import time

from guard_core.sync._utils.body_reader import _safe_read

start = time.monotonic()
events = []
lock = threading.Lock()


def make_reader(tag):
    def reader():
        with lock:
            events.append((tag, "start", time.monotonic() - start))
        time.sleep(1.0)
        with lock:
            events.append((tag, "end", time.monotonic() - start))
        return b"x"

    return reader


def call(tag):
    _safe_read(make_reader(tag), timeout=10.0, max_concurrent=1)


t1 = threading.Thread(target=call, args=("A",))
t2 = threading.Thread(target=call, args=("B",))
t1.start()
time.sleep(0.2)
t2.start()
t1.join()
t2.join()

print("SMOKE_SYNC_PROBE " + json.dumps(events))
"""

_SYNC_PROBE_MARKER = re.compile(r"SMOKE_SYNC_PROBE (\[.*\])")


def _sync_concurrency_probe_events() -> list[tuple[str, str, float]] | None:
    result = run_in_app_container(_SYNC_CONCURRENCY_PROBE, timeout=20.0)
    match = _SYNC_PROBE_MARKER.search(result.stdout + result.stderr)
    if not match:
        return None
    events: list[tuple[str, str, float]] = json.loads(match.group(1))
    return events


@scenario(
    covers={"sync_body_read_max_concurrent"},
    config={"excluded_detection_headers": EXCLUDED_HEADERS},
)
def sync_body_read_max_concurrent_serializes_reads(ctx: ScenarioContext) -> None:
    events = _sync_concurrency_probe_events()
    assert events is not None, (
        "the sync_body_read_max_concurrent probe produced no parsable output"
    )

    by_tag = {(tag, kind): timestamp for tag, kind, timestamp in events}
    assert {"A", "B"} <= {tag for tag, _kind, _timestamp in events}, events

    a_end = by_tag[("A", "end")]
    b_start = by_tag[("B", "start")]
    assert b_start >= a_end - 0.2, (
        f"max_concurrent=1 should serialize the two reads; B started at "
        f"{b_start:.2f}s, before A finished at {a_end:.2f}s: {events}"
    )
