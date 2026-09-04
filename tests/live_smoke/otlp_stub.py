import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("SMOKE_OTLP_STUB_PORT", "4318"))

_lock = threading.Lock()
_requests: list[dict[str, object]] = []


def _send_json(
    handler: BaseHTTPRequestHandler, status: int, payload: dict[str, object]
) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def _record_and_accept(self, method: str) -> None:
        raw = self._read_body()
        with _lock:
            _requests.append(
                {
                    "method": method,
                    "path": self.path,
                    "headers": dict(self.headers.items()),
                    "body_base64": base64.b64encode(raw).decode("ascii"),
                    "body_text": raw.decode("utf-8", errors="replace"),
                }
            )
        _send_json(self, 200, {"partialSuccess": {}})

    def do_GET(self) -> None:
        if self.path == "/_debug/state":
            with _lock:
                _send_json(self, 200, {"requests": list(_requests)})
            return
        self._record_and_accept("GET")

    def do_POST(self) -> None:
        if self.path == "/_debug/reset":
            with _lock:
                _requests.clear()
            _send_json(self, 200, {"success": True})
            return
        self._record_and_accept("POST")

    def do_PUT(self) -> None:
        self._record_and_accept("PUT")


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
