from starlette.requests import Request
from starlette.responses import Response

from guard.adapters import (
    StarletteGuardRequest,
    StarletteGuardResponse,
    StarletteResponseFactory,
    unwrap_response,
)


async def test_starlette_guard_request_url_path():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.url_path == "/test"


async def test_starlette_guard_request_method():
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.method == "POST"


async def test_starlette_guard_request_client_host():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "client": ("127.0.0.1", 8000),
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.client_host == "127.0.0.1"


async def test_starlette_guard_request_no_client():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.client_host is None


async def test_starlette_guard_request_headers():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [(b"x-custom", b"value")],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.headers.get("x-custom") == "value"


async def test_starlette_guard_request_query_params():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"key=val",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.query_params.get("key") == "val"


async def test_starlette_guard_request_scheme():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
        "scheme": "https",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    assert guard_request.url_scheme == "https"


async def test_starlette_guard_response_properties():
    response = Response(content="test", status_code=200)
    guard_response = StarletteGuardResponse(response)
    assert guard_response.status_code == 200
    assert guard_response.body == b"test"


async def test_starlette_guard_response_headers():
    response = Response(content="test", status_code=200)
    guard_response = StarletteGuardResponse(response)
    guard_response.headers["X-Custom"] = "value"
    assert response.headers["X-Custom"] == "value"


async def test_starlette_response_factory_create():
    factory = StarletteResponseFactory()
    guard_resp = factory.create_response("error", 403)
    assert guard_resp.status_code == 403
    assert guard_resp.body == b"error"


async def test_starlette_response_factory_redirect():
    factory = StarletteResponseFactory()
    guard_resp = factory.create_redirect_response("https://example.com", 301)
    assert guard_resp.status_code == 301


async def test_unwrap_response_starlette():
    response = Response(content="test", status_code=200)
    guard_response = StarletteGuardResponse(response)
    unwrapped = unwrap_response(guard_response)
    assert unwrapped is response


async def test_unwrap_response_generic():
    from unittest.mock import MagicMock

    mock_resp = MagicMock()
    mock_resp.body = b"body"
    mock_resp.status_code = 404
    mock_resp.headers = {"X-Test": "val"}
    unwrapped = unwrap_response(mock_resp)
    assert unwrapped.status_code == 404


async def test_starlette_guard_request_scope():
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "query_string": b"",
        "headers": [],
        "server": ("localhost", 8000),
        "root_path": "",
    }
    request = Request(scope)
    guard_request = StarletteGuardRequest(request)
    result = guard_request.scope
    assert result["path"] == "/test"
    assert result["method"] == "GET"
