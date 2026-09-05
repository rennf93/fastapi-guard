import gzip
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

API_KEY = os.environ.get("SMOKE_AGENT_API_KEY", "smoke-agent-key")
PORT = int(os.environ.get("SMOKE_AGENT_PORT", "8090"))

_lock = threading.Lock()
_state: dict[str, list[Any]] = {
    "events": [],
    "metrics": [],
    "status": [],
    "requests": [],
}
_rule_version = 1
_rule_suspicious_patterns: list[str] | None = None
_delay_seconds = 0.0
_forced_status: int | None = None
_in_flight = 0
_high_water_mark = 0

_CONTROL_PATHS = {
    "/health",
    "/_debug/state",
    "/_debug/reset",
    "/_debug/delay",
    "/_debug/status",
    "/_debug/rules",
}
_FORCIBLE_PATHS = {"/api/v1/events", "/api/v1/metrics", "/api/v1/status"}
_ENVELOPE_FIELDS = (
    "project_id",
    "batch_id",
    "created_at",
    "agent_version",
    "guard_version",
    "guard_core_version",
)


def _read_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length else b""
    if handler.headers.get("Content-Encoding") == "gzip":
        raw = gzip.decompress(raw)
    if not raw:
        return {}
    return dict(json.loads(raw.decode("utf-8")))


def _send_json(
    handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]
) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _record_request(handler: BaseHTTPRequestHandler, body: dict[str, Any]) -> None:
    with _lock:
        _state["requests"].append(
            {
                "path": handler.path,
                "headers": dict(handler.headers.items()),
                "envelope": {field: body.get(field) for field in _ENVELOPE_FIELDS},
            }
        )


class _InFlightTracker:
    def __enter__(self) -> "_InFlightTracker":
        global _in_flight, _high_water_mark
        with _lock:
            _in_flight += 1
            _high_water_mark = max(_high_water_mark, _in_flight)
        return self

    def __exit__(self, *exc_info: object) -> None:
        global _in_flight
        with _lock:
            _in_flight -= 1


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def _authorized(self) -> bool:
        return self.headers.get("X-API-Key") == API_KEY

    def _maybe_delay(self) -> None:
        if self.path in _CONTROL_PATHS:
            return
        with _lock:
            delay = _delay_seconds
        if delay:
            time.sleep(delay)

    def _forced_status_for(self, path: str) -> int | None:
        if path not in _FORCIBLE_PATHS:
            return None
        with _lock:
            return _forced_status

    def do_GET(self) -> None:
        with _InFlightTracker():
            self._maybe_delay()
            self._handle_get()

    def _handle_get(self) -> None:
        if self.path == "/health":
            _send_json(self, 200, {"status": "ok"})
            return
        if self.path == "/_debug/state":
            self._handle_debug_state()
            return
        if self.path == "/api/v1/rules":
            self._handle_rules()
            return
        _send_json(self, 404, {"detail": "not found"})

    def _handle_debug_state(self) -> None:
        with _lock:
            snapshot = {
                "events": list(_state["events"]),
                "metrics": list(_state["metrics"]),
                "status": list(_state["status"]),
                "requests": list(_state["requests"]),
                "high_water_mark": _high_water_mark,
                "in_flight": _in_flight,
                "delay_seconds": _delay_seconds,
                "forced_status": _forced_status,
            }
        _send_json(self, 200, snapshot)

    def _handle_rules(self) -> None:
        if not self._authorized():
            _send_json(self, 401, {"detail": "unauthorized"})
            return
        forced = self._forced_status_for(self.path)
        if forced is not None:
            _send_json(self, forced, {"detail": "forced status"})
            return
        global _rule_version
        with _lock:
            version = _rule_version
            _rule_version += 1
            patterns = _rule_suspicious_patterns
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "rule_id": "smoke-rule",
            "version": version,
            "timestamp": now.isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "ttl": 300,
            "auto_ban_threshold": 9,
            "emergency_whitelist_only": True,
            "message": "smoke-live-agent-rule",
        }
        if patterns is not None:
            payload["suspicious_patterns"] = patterns
        _send_json(self, 200, payload)

    def do_POST(self) -> None:
        with _InFlightTracker():
            self._maybe_delay()
            self._handle_post()

    def _handle_post(self) -> None:
        debug_handlers = {
            "/_debug/reset": self._handle_debug_reset,
            "/_debug/delay": self._handle_debug_delay,
            "/_debug/status": self._handle_debug_status,
            "/_debug/rules": self._handle_debug_rules,
        }
        handler = debug_handlers.get(self.path)
        if handler is not None:
            handler()
            return
        self._handle_data_post()

    def _handle_data_post(self) -> None:
        if not self._authorized():
            _read_body(self)
            _send_json(self, 401, {"detail": "unauthorized"})
            return
        body = _read_body(self)
        _record_request(self, body)
        forced = self._forced_status_for(self.path)
        if forced is not None:
            _send_json(self, forced, {"detail": "forced status"})
            return
        if self.path == "/api/v1/events":
            with _lock:
                _state["events"].extend(body.get("events", []))
            _send_json(self, 200, {"success": True})
            return
        if self.path == "/api/v1/metrics":
            with _lock:
                _state["metrics"].extend(body.get("metrics", []))
            _send_json(self, 200, {"success": True})
            return
        if self.path == "/api/v1/status":
            with _lock:
                _state["status"].append(body)
            _send_json(self, 200, {"success": True})
            return
        _send_json(self, 404, {"detail": "not found"})

    def _handle_debug_reset(self) -> None:
        global _delay_seconds, _forced_status, _rule_suspicious_patterns
        global _high_water_mark
        with _lock:
            _state["events"].clear()
            _state["metrics"].clear()
            _state["status"].clear()
            _state["requests"].clear()
            _delay_seconds = 0.0
            _forced_status = None
            _rule_suspicious_patterns = None
            _high_water_mark = 0
        _send_json(self, 200, {"success": True})

    def _handle_debug_delay(self) -> None:
        global _delay_seconds
        payload = _read_body(self)
        with _lock:
            _delay_seconds = float(payload.get("seconds", 0.0))
        _send_json(self, 200, {"seconds": _delay_seconds})

    def _handle_debug_status(self) -> None:
        global _forced_status
        payload = _read_body(self)
        code = payload.get("code")
        with _lock:
            _forced_status = int(code) if code is not None else None
        _send_json(self, 200, {"code": _forced_status})

    def _handle_debug_rules(self) -> None:
        global _rule_suspicious_patterns
        payload = _read_body(self)
        with _lock:
            _rule_suspicious_patterns = payload.get("suspicious_patterns")
        _send_json(self, 200, {"suspicious_patterns": _rule_suspicious_patterns})


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
