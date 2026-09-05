import base64
import os
import socket
import struct
from urllib.parse import quote

from tests.live_smoke.driver import NGINX_PORT, ScenarioContext
from tests.live_smoke.registry import scenario

EXCLUDED_HEADERS = ["x-real-ip", "x-forwarded-for"]
CLIENT_IP = "192.168.50.50"
_XSS_QUERY = quote("<script>alert(1)</script>")
_BASE_CONFIG = {"excluded_detection_headers": EXCLUDED_HEADERS}


def _parse_status_line(head: bytes) -> tuple[int, dict[str, str]]:
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1") if lines else ""
    parts = status_line.split(" ", 2)
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.decode("latin-1").partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return status_code, headers


def _open_handshake(
    path: str, timeout: float = 10.0
) -> tuple[int, dict[str, str], socket.socket | None]:
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request_headers = {
        "Host": "localhost",
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
    }
    header_lines = "\r\n".join(
        f"{name}: {value}" for name, value in request_headers.items()
    )
    request = f"GET {path} HTTP/1.1\r\n{header_lines}\r\n\r\n"

    sock = socket.create_connection(("localhost", NGINX_PORT), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(request.encode("latin-1"))

    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(65536)
        if not chunk:
            break
        raw += chunk
    head, _, _ = raw.partition(b"\r\n\r\n")
    status_code, headers = _parse_status_line(head)

    if status_code != 101:
        sock.close()
        return status_code, headers, None
    return status_code, headers, sock


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("websocket connection closed before expected data")
        data += chunk
    return data


def _send_text(sock: socket.socket, message: str) -> None:
    payload = message.encode("utf-8")
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)


def _recv_text(sock: socket.socket) -> str:
    first_two = _recv_exact(sock, 2)
    length = first_two[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", _recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", _recv_exact(sock, 8))[0]
    return _recv_exact(sock, length).decode("utf-8")


@scenario(
    covers={"suspicious_activity", "enable_penetration_detection"},
    config={**_BASE_CONFIG, "rate_limit_window": 61},
)
def websocket_handshake_with_attack_query_is_rejected_before_accept(
    ctx: ScenarioContext,
) -> None:
    status_code, _, sock = _open_handshake(f"/ws?q={_XSS_QUERY}")
    assert sock is None
    assert status_code == 403, status_code


@scenario(
    covers={"blacklist", "ip_security"},
    config={**_BASE_CONFIG, "blacklist": [CLIENT_IP], "rate_limit_window": 62},
)
def websocket_handshake_from_blacklisted_ip_is_rejected_before_accept(
    ctx: ScenarioContext,
) -> None:
    status_code, _, sock = _open_handshake("/ws")
    assert sock is None
    assert status_code == 403, status_code


@scenario(covers=set(), config={**_BASE_CONFIG, "rate_limit_window": 63})
def websocket_handshake_accepts_connects_echoes_and_closes_cleanly(
    ctx: ScenarioContext,
) -> None:
    status_code, _, sock = _open_handshake("/ws")
    assert status_code == 101, status_code
    assert sock is not None
    try:
        _send_text(sock, "smoke-echo")
        assert _recv_text(sock) == "smoke-echo"
    finally:
        sock.close()
