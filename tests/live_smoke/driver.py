from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import redis

STACK_DIR = Path(__file__).resolve().parent / "stack"
REPORT_DIR = Path(__file__).resolve().parent / "live-smoke-report"
PROJECT = os.environ.get("LIVE_SMOKE_PROJECT", "fastapi-guard-live-smoke")
CONFIG_FILE = STACK_DIR / "scenario_data" / f"config-{PROJECT}.json"
APP_SERVICE = "fastapi-guard-example"

NGINX_PORT = int(os.environ.get("LIVE_SMOKE_NGINX_PORT", "8089"))
AGENT_PORT = int(os.environ.get("LIVE_SMOKE_AGENT_PORT", "8091"))
REDIS_PORT = int(os.environ.get("LIVE_SMOKE_REDIS_PORT", "16379"))
OTLP_STUB_PORT = int(os.environ.get("LIVE_SMOKE_OTLP_STUB_PORT", "8092"))

BASE_URL = f"http://localhost:{NGINX_PORT}"
AGENT_URL = f"http://localhost:{AGENT_PORT}"
OTLP_STUB_URL = f"http://localhost:{OTLP_STUB_PORT}"


def _compose(
    *args: str,
    check: bool = True,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        "docker",
        "compose",
        "-p",
        PROJECT,
        "-f",
        str(STACK_DIR / "compose.yml"),
        *args,
    ]
    full_env = {**os.environ, "LIVE_SMOKE_PROJECT": PROJECT, **(env or {})}
    return subprocess.run(
        cmd,
        cwd=STACK_DIR,
        capture_output=True,
        text=True,
        check=check,
        env=full_env,
        timeout=timeout,
    )


class LogReader:
    def __init__(self, service: str = APP_SERVICE) -> None:
        self._service = service

    def mark(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def lines_since(self, mark: str, kind: str | None = None) -> list[str]:
        result = _compose(
            "logs", "--no-color", "--since", mark, self._service, check=False
        )
        lines = result.stdout.splitlines()
        if kind is None:
            return lines
        return [line for line in lines if kind in line]

    def full_text(self) -> str:
        result = _compose("logs", "--no-color", self._service, check=False)
        return result.stdout


def run_in_app_container(
    python_code: str, timeout: float = 30.0
) -> subprocess.CompletedProcess[str]:
    try:
        return _compose(
            "exec",
            "-T",
            APP_SERVICE,
            "python",
            "-c",
            python_code,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout
        return subprocess.CompletedProcess(
            args=exc.cmd,
            returncode=124,
            stdout=stdout or "",
            stderr=f"run_in_app_container timed out after {timeout}s",
        )


def _parse_http_response(raw: bytes) -> tuple[int, dict[str, str], bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1") if lines else ""
    parts = status_line.split(" ", 2)
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.decode("latin-1").partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return status_code, headers, body


def send_slow_body(
    path: str,
    headers: dict[str, str],
    body: bytes,
    stall_seconds: float,
    *,
    method: str = "POST",
    socket_timeout: float = 30.0,
) -> tuple[int, dict[str, str], bytes]:
    request_headers = {
        "Host": "localhost",
        "Content-Length": str(len(body)),
        "Connection": "close",
        **headers,
    }
    header_lines = "\r\n".join(
        f"{name}: {value}" for name, value in request_headers.items()
    )
    request_line = f"{method} {path} HTTP/1.1\r\n{header_lines}\r\n\r\n"

    sock = socket.create_connection(("localhost", NGINX_PORT), timeout=socket_timeout)
    try:
        sock.sendall(request_line.encode("latin-1"))
        time.sleep(stall_seconds)
        sock.sendall(body)
        sock.settimeout(socket_timeout)
        chunks: list[bytes] = []
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except TimeoutError:
            pass
    finally:
        sock.close()

    return _parse_http_response(b"".join(chunks))


class Stack:
    def __init__(self) -> None:
        self.logs = LogReader()
        self._current_config_key: str | None = None

    def up(self) -> None:
        _compose("up", "--build", "--wait")

    def dump_logs(self) -> None:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        (REPORT_DIR / "app.log").write_text(
            _compose("logs", "--no-color", APP_SERVICE, check=False).stdout,
            encoding="utf-8",
        )
        (REPORT_DIR / "all-services.log").write_text(
            _compose("logs", "--no-color", check=False).stdout, encoding="utf-8"
        )
        (REPORT_DIR / "ps.txt").write_text(
            _compose("ps", check=False).stdout, encoding="utf-8"
        )

    def down(self) -> None:
        self.dump_logs()
        _compose("down", "-v", "--remove-orphans", check=False)

    def container_file(self, path: str) -> str:
        result = _compose("exec", "-T", APP_SERVICE, "cat", path, check=False)
        if result.returncode != 0:
            raise FileNotFoundError(f"{path} in {APP_SERVICE}: {result.stderr.strip()}")
        return result.stdout

    def _wait_healthy(self, expected_nonce: str, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        last_stderr = ""
        check_cmd = (
            "import pathlib, urllib.request; "
            "urllib.request.urlopen('http://localhost:8000/health'); "
            "nonce = pathlib.Path('/tmp/smoke_nonce.txt').read_text(); "
            f"assert nonce == {expected_nonce!r}, nonce"
        )
        while time.monotonic() < deadline:
            result = _compose(
                "exec", "-T", APP_SERVICE, "python", "-c", check_cmd, check=False
            )
            if result.returncode == 0:
                return
            last_stderr = result.stderr.strip()
            time.sleep(0.5)
        raise RuntimeError(f"{APP_SERVICE} did not become healthy: {last_stderr}")

    def _flush_smoke_state(self) -> None:
        client = make_redis_client()
        try:
            keys = list(client.scan_iter(match="smoke:*"))
            if keys:
                client.delete(*keys)
        finally:
            client.close()

    def restart_with(self, config: dict[str, Any], force: bool = False) -> None:
        key = json.dumps(config, sort_keys=True, default=str)
        if not force and key == self._current_config_key:
            return
        self._flush_smoke_state()
        nonce = uuid.uuid4().hex
        payload = {**config, "smoke_nonce": nonce}
        CONFIG_FILE.write_text(json.dumps(payload), encoding="utf-8")
        _compose("restart", APP_SERVICE)
        self._wait_healthy(nonce)
        self._current_config_key = key


@dataclass
class ScenarioContext:
    stack: Stack
    client: httpx.Client
    agent: httpx.Client
    redis: redis.Redis
    otlp: httpx.Client


def make_redis_client(db: int = 0) -> redis.Redis:
    return redis.Redis(host="localhost", port=REDIS_PORT, db=db, decode_responses=True)


def make_http_client() -> httpx.Client:
    return httpx.Client(base_url=BASE_URL, timeout=10.0)


def make_agent_client() -> httpx.Client:
    return httpx.Client(base_url=AGENT_URL, timeout=10.0)


def make_otlp_client() -> httpx.Client:
    return httpx.Client(base_url=OTLP_STUB_URL, timeout=10.0)


def wait_until(predicate: Any, timeout: float = 15.0, interval: float = 0.5) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval)
    return last
