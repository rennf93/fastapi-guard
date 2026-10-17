"""Bypassed and excluded routes stream through the pure-ASGI middleware."""

import asyncio
import gc
import itertools
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.responses import FileResponse, Response
from guard_core.protocols.response_protocol import GuardResponse
from starlette.requests import ClientDisconnect, Request
from starlette.responses import StreamingResponse
from starlette.types import Message

from guard import (
    PureASGISecurityMiddleware,
    SecurityConfig,
    SecurityDecorator,
    SecurityMiddleware,
)
from guard.adapters import StarletteGuardResponse
from guard.asgi import _BodyCachingReceive, _InlineDownstream, _StreamedDownstream

_IP = itertools.count(1)


async def _leave_response_untouched(response: GuardResponse) -> GuardResponse:
    return response


@pytest.fixture(params=["inline", "task"])
def bypass_kwargs(request: pytest.FixtureRequest) -> dict[str, Any]:
    """No modifier runs the downstream inline; any modifier uses the task."""
    if request.param == "inline":
        return {}
    return {"custom_response_modifier": _leave_response_untouched}


def _unique_ip() -> str:
    n = next(_IP)
    return f"198.18.{n // 250}.{(n % 250) + 1}"


def _config(**overrides: Any) -> SecurityConfig:
    return SecurityConfig(enable_redis=False, **overrides)


def _build_app(
    middleware: type[SecurityMiddleware] | type[PureASGISecurityMiddleware],
    config: SecurityConfig,
    add_routes: Callable[..., None],
) -> FastAPI:
    app = FastAPI()
    guard = SecurityDecorator(config)
    app.state.guard_decorator = guard
    app.add_middleware(middleware, config=config)
    add_routes(app, guard)
    return app


def _scope(
    path: str,
    method: str = "GET",
    spec_version: str = "2.3",
    extra_headers: list[tuple[bytes, bytes]] | None = None,
    extensions: dict[str, Any] | None = None,
) -> dict:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": spec_version},
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"testserver"), *(extra_headers or [])],
        "client": (_unique_ip(), 50000),
        "server": ("testserver", 80),
        "scheme": "http",
    }
    if extensions is not None:
        scope["extensions"] = extensions
    return scope


async def _idle_receive() -> Message:
    await asyncio.Event().wait()
    raise AssertionError("unreachable")


def _request_then_idle_receive() -> Callable[[], Any]:
    """One empty request message, then block like a connected client."""
    pending = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive() -> Message:
        if pending:
            return pending.pop()
        return await _idle_receive()

    return receive


def _chunk(index: int) -> bytes:
    return f"chunk{index}".encode()


def _body_of(messages: list[Message]) -> bytes:
    return b"".join(m.get("body", b"") for m in messages if "body" in m)


def _start_of(messages: list[Message]) -> Message:
    return next(m for m in messages if m["type"] == "http.response.start")


async def _drive(
    app: Any,
    path: str,
    *,
    method: str = "GET",
    send: Callable[[Message], Any] | None = None,
    receive: Callable[[], Any] | None = None,
    spec_version: str = "2.3",
    extra_headers: list[tuple[bytes, bytes]] | None = None,
    extensions: dict[str, Any] | None = None,
) -> list[Message]:
    sent: list[Message] = []

    async def record(message: Message) -> None:
        sent.append(message)
        if send is not None:
            await send(message)

    await asyncio.wait_for(
        app(
            _scope(path, method, spec_version, extra_headers, extensions),
            receive or _request_then_idle_receive(),
            record,
        ),
        timeout=10,
    )
    return sent


def _no_pending_tasks() -> bool:
    return not (asyncio.all_tasks() - {asyncio.current_task()})


def _streaming_routes(app: FastAPI, guard: SecurityDecorator) -> None:
    @app.get("/stream")
    @guard.bypass(["all"])
    async def stream() -> StreamingResponse:
        async def gen() -> AsyncIterator[bytes]:
            for i in range(3):
                yield _chunk(i)

        return StreamingResponse(gen())


async def test_first_chunk_reaches_client_before_second_is_produced(
    bypass_kwargs: dict[str, Any],
) -> None:
    events: list[str] = []
    first_delivered = asyncio.Event()

    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.get("/stream")
        @guard.bypass(["all"])
        async def stream() -> StreamingResponse:
            async def gen() -> AsyncIterator[bytes]:
                yield b"first"
                await first_delivered.wait()
                events.append("second produced")
                yield b"second"

            return StreamingResponse(gen())

    async def client_send(message: Message) -> None:
        if message.get("body") == b"first":
            events.append("first delivered")
            first_delivered.set()

    app = _build_app(PureASGISecurityMiddleware, _config(**bypass_kwargs), add_routes)
    sent = await _drive(app, "/stream", send=client_send)
    assert events == ["first delivered", "second produced"]
    assert _body_of(sent) == b"firstsecond"
    assert sent[-1] == {"type": "http.response.body", "body": b"", "more_body": False}


async def test_middleware_never_holds_more_than_one_chunk(
    bypass_kwargs: dict[str, Any],
) -> None:
    delivered = 0
    held_when_producing: list[int] = []

    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.get("/stream")
        @guard.bypass(["all"])
        async def stream() -> StreamingResponse:
            async def gen() -> AsyncIterator[bytes]:
                for i in range(20):
                    # the app resumes once its previous send() returned: every
                    # chunk it has handed over and the client lacks is held
                    held_when_producing.append(i - delivered)
                    yield _chunk(i)

            return StreamingResponse(gen())

    app = _build_app(PureASGISecurityMiddleware, _config(**bypass_kwargs), add_routes)

    async def slow_client_send(message: Message) -> None:
        nonlocal delivered
        if message.get("body"):
            await asyncio.sleep(0.001)
            delivered += 1

    sent = await _drive(app, "/stream", send=slow_client_send)
    assert _body_of(sent) == b"".join(_chunk(i) for i in range(20))
    assert max(held_when_producing) <= 1


async def test_repeated_set_cookie_headers_survive_bypass(
    bypass_kwargs: dict[str, Any],
) -> None:
    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.get("/cookies")
        @guard.bypass(["all"])
        async def cookies() -> Response:
            response = Response("ok")
            response.set_cookie("a", "1")
            response.set_cookie("b", "2")
            return response

    app = _build_app(PureASGISecurityMiddleware, _config(**bypass_kwargs), add_routes)
    sent = await _drive(app, "/cookies")
    cookies = [v for k, v in _start_of(sent)["headers"] if k == b"set-cookie"]
    assert len(cookies) == 2


async def test_custom_response_modifier_runs_on_bypassed_streamed_route() -> None:
    async def modifier(response: GuardResponse) -> GuardResponse:
        response.headers["X-Modified"] = "yes"
        return response

    app = _build_app(
        PureASGISecurityMiddleware,
        _config(custom_response_modifier=modifier),
        _streaming_routes,
    )
    sent = await _drive(app, "/stream")
    start = _start_of(sent)
    assert start["status"] == 200
    assert (b"x-modified", b"yes") in start["headers"]
    assert _body_of(sent) == b"chunk0chunk1chunk2"


async def test_security_bypass_event_still_fires(
    bypass_kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(**bypass_kwargs)
    app = _build_app(PureASGISecurityMiddleware, config, _streaming_routes)
    events: list[str] = []
    app.middleware_stack = app.build_middleware_stack()
    middleware: Any = app.middleware_stack
    while not isinstance(middleware, PureASGISecurityMiddleware):
        middleware = middleware.app
    original = middleware._engine.event_bus.send_middleware_event

    async def spy(*args: Any, **kwargs: Any) -> None:
        events.append(kwargs["event_type"])
        await original(*args, **kwargs)

    monkeypatch.setattr(middleware._engine.event_bus, "send_middleware_event", spy)
    await _drive(app, "/stream")
    assert "security_bypass" in events


async def _failure_report(
    middleware: type,
    add_routes: Callable[..., None],
    path: str,
    config_kwargs: dict[str, Any],
) -> tuple[Any, ...]:
    app = _build_app(middleware, _config(**config_kwargs), add_routes)
    messages: list[Message] = []

    async def record(message: Message) -> None:
        messages.append(message)

    error: BaseException | None = None
    try:
        await asyncio.wait_for(
            app(_scope(path), _request_then_idle_receive(), record), timeout=10
        )
    except Exception as exc:
        error = exc
    status = _start_of(messages)["status"] if messages else None
    return type(error), str(error), status, _body_of(messages)


def _failing_routes(app: FastAPI, guard: SecurityDecorator) -> None:
    @app.get("/before")
    @guard.bypass(["all"])
    async def before() -> Response:
        raise ValueError("before start")

    @app.get("/after")
    @guard.bypass(["all"])
    async def after() -> StreamingResponse:
        async def gen() -> AsyncIterator[bytes]:
            yield b"partial"
            raise ValueError("after start")

        return StreamingResponse(gen())


@pytest.mark.parametrize("path", ["/before", "/after"])
async def test_downstream_exceptions_match_classic_middleware(
    path: str, bypass_kwargs: dict[str, Any]
) -> None:
    classic = await _failure_report(
        SecurityMiddleware, _failing_routes, path, bypass_kwargs
    )
    pure = await _failure_report(
        PureASGISecurityMiddleware, _failing_routes, path, bypass_kwargs
    )
    assert pure == classic
    assert pure[0] is ValueError


async def test_app_that_sends_no_response_matches_classic() -> None:
    async def silent(scope: Any, receive: Any, send: Any) -> None:
        return None

    config = _config(exclude_paths=["/silent"])
    with pytest.raises(RuntimeError) as classic:
        await _drive(SecurityMiddleware(silent, config=config), "/silent")

    pure = PureASGISecurityMiddleware(silent, config=config)
    scope = _scope("/silent")
    downstream = _StreamedDownstream(pure, scope, _BodyCachingReceive(_idle_receive))
    with pytest.raises(RuntimeError) as streamed:
        await downstream.call_next(Request(scope))
    await downstream.close()
    assert str(streamed.value) == str(classic.value) == "No response returned."
    assert _no_pending_tasks()


def _endless_routes(state: dict[str, Any]) -> Callable[..., None]:
    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.get("/endless")
        @guard.bypass(["all"])
        async def endless() -> StreamingResponse:
            async def gen() -> AsyncIterator[bytes]:
                try:
                    while True:
                        state["ticks"] = state.get("ticks", 0) + 1
                        yield b"tick"
                        await asyncio.sleep(0.001)
                finally:
                    state["generator_closed"] = True

            return StreamingResponse(gen())

    return add_routes


async def test_client_send_failure_stops_downstream_generator(
    bypass_kwargs: dict[str, Any],
) -> None:
    state: dict[str, Any] = {}
    app = _build_app(
        PureASGISecurityMiddleware, _config(**bypass_kwargs), _endless_routes(state)
    )
    deliveries = 0

    async def failing_send(message: Message) -> None:
        nonlocal deliveries
        if message.get("body"):
            deliveries += 1
            if deliveries == 3:
                raise OSError("client went away")

    with pytest.raises((OSError, ClientDisconnect)):
        await _drive(
            app,
            "/endless",
            send=failing_send,
            receive=_idle_receive,
            spec_version="2.4",
        )
    ticks_at_failure = state["ticks"]
    await asyncio.sleep(0.05)
    assert state["ticks"] == ticks_at_failure
    assert _no_pending_tasks()


async def test_http_disconnect_stops_downstream_generator(
    bypass_kwargs: dict[str, Any],
) -> None:
    state: dict[str, Any] = {}
    app = _build_app(
        PureASGISecurityMiddleware, _config(**bypass_kwargs), _endless_routes(state)
    )
    first_chunk = asyncio.Event()
    request_sent = False

    async def receive() -> Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await first_chunk.wait()
        return {"type": "http.disconnect"}

    async def client_send(message: Message) -> None:
        if message.get("body"):
            first_chunk.set()

    await _drive(app, "/endless", send=client_send, receive=receive)
    assert state["generator_closed"] is True
    assert _no_pending_tasks()


async def test_modifier_replacing_response_releases_downstream() -> None:
    state: dict[str, Any] = {}

    async def replace(response: GuardResponse) -> GuardResponse:
        return StarletteGuardResponse(Response("replaced", status_code=202))

    app = _build_app(
        PureASGISecurityMiddleware,
        _config(custom_response_modifier=replace),
        _endless_routes(state),
    )
    sent = await _drive(app, "/endless", receive=_idle_receive)
    assert _start_of(sent)["status"] == 202
    assert _body_of(sent) == b"replaced"
    ticks_at_release = state["ticks"]
    await asyncio.sleep(0.05)
    assert state["ticks"] == ticks_at_release
    assert _no_pending_tasks()


async def test_empty_body_and_head_on_bypassed_route(
    bypass_kwargs: dict[str, Any],
) -> None:
    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.api_route("/empty", methods=["GET", "HEAD"])
        @guard.bypass(["all"])
        async def empty() -> Response:
            return Response(b"", status_code=204)

    app = _build_app(PureASGISecurityMiddleware, _config(**bypass_kwargs), add_routes)
    for method in ("GET", "HEAD"):
        sent = await _drive(app, "/empty", method=method)
        assert _start_of(sent)["status"] == 204
        assert _body_of(sent) == b""
        assert not sent[-1].get("more_body", False)


async def test_guard_block_response_is_a_single_unchanged_body_message() -> None:
    blocked_ip = "203.0.113.9"
    config = _config(blacklist=(blocked_ip,))

    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.get("/plain")
        async def plain() -> dict[str, bool]:
            return {"ok": True}

    app = _build_app(PureASGISecurityMiddleware, config, add_routes)
    scope = _scope("/plain")
    scope["client"] = (blocked_ip, 50000)
    sent: list[Message] = []

    async def record(message: Message) -> None:
        sent.append(message)

    await app(scope, _request_then_idle_receive(), record)
    assert sent[1] == {"type": "http.response.body", "body": b"Forbidden"}
    assert sent[0]["status"] == 403
    assert sent[0]["headers"][:2] == [
        (b"content-length", b"9"),
        (b"content-type", b"text/plain; charset=utf-8"),
    ]
    assert len(sent) == 2


async def test_debug_messages_are_skipped_and_text_chunks_are_encoded() -> None:
    async def noisy(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.debug", "info": {"k": "v"}})
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.debug", "info": {"k": "v"}})
        await send({"type": "http.response.body", "body": b"data", "more_body": False})

    pure = PureASGISecurityMiddleware(noisy, config=_config())
    scope = _scope("/noisy")
    downstream = _StreamedDownstream(pure, scope, _BodyCachingReceive(_idle_receive))
    response = await downstream.call_next(Request(scope))
    assert isinstance(response, StreamingResponse)
    assert [c async for c in response.body_iterator] == [b"data"]
    await downstream.close()

    async def text_chunks(response: GuardResponse) -> GuardResponse:
        async def gen() -> AsyncIterator[str]:
            yield "café"

        return StarletteGuardResponse(StreamingResponse(gen()))

    app = _build_app(
        PureASGISecurityMiddleware,
        _config(custom_response_modifier=text_chunks),
        _streaming_routes,
    )
    sent = await _drive(app, "/stream")
    assert _body_of(sent) == "café".encode()


async def test_close_releases_app_blocked_in_send() -> None:
    entered = asyncio.Event()
    outcome: list[str] = []

    async def blocked_in_send(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        entered.set()
        try:
            await send({"type": "http.response.body", "body": b"x", "more_body": True})
        except OSError:
            outcome.append("released")
            raise

    pure = PureASGISecurityMiddleware(blocked_in_send, config=_config())
    scope = _scope("/blocked")
    downstream = _StreamedDownstream(pure, scope, _BodyCachingReceive(_idle_receive))
    await downstream.call_next(Request(scope))
    await entered.wait()
    await downstream.close()
    assert outcome == ["released"]
    assert _no_pending_tasks()


async def test_generator_is_finalized_after_disconnect_without_cyclic_gc(
    bypass_kwargs: dict[str, Any],
) -> None:
    state: dict[str, Any] = {}
    app = _build_app(
        PureASGISecurityMiddleware, _config(**bypass_kwargs), _endless_routes(state)
    )
    deliveries = 0

    async def failing_send(message: Message) -> None:
        nonlocal deliveries
        if message.get("body"):
            deliveries += 1
            if deliveries == 3:
                raise OSError("client went away")

    async def drive_and_drop_the_failure() -> bool:
        # Like a production server: no wait_for task (its result would hold
        # the exception) and the exception is dropped right away.
        try:
            await app(
                _scope("/endless", spec_version="2.4"), _idle_receive, failing_send
            )
        except (OSError, ClientDisconnect):
            return True
        return False

    gc.collect()
    gc.disable()
    try:
        assert await drive_and_drop_the_failure()
        await asyncio.sleep(0.05)
        assert state.get("generator_closed") is True
    finally:
        gc.enable()


async def test_app_exception_keeps_its_frame_locals(
    bypass_kwargs: dict[str, Any],
) -> None:
    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.get("/boom-regular")
        async def boom_regular() -> Response:
            secret_local = "kept"
            raise RuntimeError(secret_local)

        @app.get("/boom-bypassed")
        @guard.bypass(["all"])
        async def boom_bypassed() -> Response:
            secret_local = "kept"
            raise RuntimeError(secret_local)

    app = _build_app(PureASGISecurityMiddleware, _config(**bypass_kwargs), add_routes)
    kept = {}
    for path in ("/boom-regular", "/boom-bypassed"):
        with pytest.raises(RuntimeError) as info:
            await _drive(app, path)
        frame = info.tb.tb_next
        assert frame is not None
        while frame.tb_next is not None:
            frame = frame.tb_next
        # 3.13+ gives a FrameLocalsProxy (PEP 667); two never compare equal.
        kept[path] = dict(frame.tb_frame.f_locals)
    assert kept["/boom-bypassed"] == kept["/boom-regular"] == {"secret_local": "kept"}


async def test_cors_headers_replace_the_apps_of_the_same_name_and_keep_repeats(
    bypass_kwargs: dict[str, Any],
) -> None:
    config = _config(
        enable_cors=True,
        cors_allow_origins=["http://good.origin"],
        cors_allow_methods=["GET"],
        **bypass_kwargs,
    )

    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.get("/own")
        @guard.bypass(["all"])
        async def own() -> Response:
            response = Response("ok")
            response.headers.append("x-a", "1")
            response.headers.append("x-a", "2")
            return response

        @app.get("/overrides")
        @guard.bypass(["all"])
        async def overrides() -> Response:
            return Response("ok", headers={"Access-Control-Allow-Origin": "mine"})

    app = _build_app(PureASGISecurityMiddleware, config, add_routes)
    origin = [(b"origin", b"http://good.origin")]
    start = _start_of(await _drive(app, "/own", extra_headers=origin))
    assert (b"access-control-allow-origin", b"http://good.origin") in start["headers"]
    assert [v for k, v in start["headers"] if k == b"x-a"] == [b"1", b"2"]
    start = _start_of(await _drive(app, "/overrides", extra_headers=origin))
    allow_origin = [
        v for k, v in start["headers"] if k == b"access-control-allow-origin"
    ]
    assert allow_origin == [b"http://good.origin"]


async def test_pathsend_extension_inline_forwards_and_task_streams_the_file(
    bypass_kwargs: dict[str, Any], tmp_path: Path
) -> None:
    file = tmp_path / "payload.bin"
    file.write_bytes(b"file-body")

    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.get("/file")
        @guard.bypass(["all"])
        async def serve() -> FileResponse:
            return FileResponse(file)

    app = _build_app(PureASGISecurityMiddleware, _config(**bypass_kwargs), add_routes)
    sent = await _drive(app, "/file", extensions={"http.response.pathsend": {}})
    if bypass_kwargs:
        assert _body_of(sent) == b"file-body"
        assert all(m["type"] != "http.response.pathsend" for m in sent)
    else:
        pathsend = [m for m in sent if m["type"] == "http.response.pathsend"]
        assert [m["path"] for m in pathsend] == [str(file)]


async def test_inline_downstream_without_a_response_raises_like_classic() -> None:
    async def silent(scope: Any, receive: Any, send: Any) -> None:
        return None

    pure = PureASGISecurityMiddleware(silent, config=_config())
    scope = _scope("/silent")
    request = Request(scope)

    async def unused_send(message: Message) -> None:
        raise AssertionError("nothing may be sent")

    downstream = _InlineDownstream(
        pure, scope, _BodyCachingReceive(_idle_receive), request, unused_send
    )
    with pytest.raises(RuntimeError, match="No response returned."):
        await downstream.call_next(request)


async def test_close_drops_the_end_marker_of_a_finished_app() -> None:
    async def start_only(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 204, "headers": []})

    pure = PureASGISecurityMiddleware(start_only, config=_config())
    scope = _scope("/start-only")
    downstream = _StreamedDownstream(pure, scope, _BodyCachingReceive(_idle_receive))
    await downstream.call_next(Request(scope))
    await asyncio.sleep(0)
    await downstream.close()
    assert _no_pending_tasks()


async def test_regular_route_with_a_modifier_never_starts_the_handoff_task() -> None:
    def add_routes(app: FastAPI, guard: SecurityDecorator) -> None:
        @app.get("/plain")
        async def plain() -> Response:
            return Response("plain")

    app = _build_app(
        PureASGISecurityMiddleware,
        _config(custom_response_modifier=_leave_response_untouched),
        add_routes,
    )
    sent = await _drive(app, "/plain")
    assert _body_of(sent) == b"plain"
    assert _no_pending_tasks()
