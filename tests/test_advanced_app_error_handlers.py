import json

import pytest
from fastapi import HTTPException, Request


def make_request() -> Request:
    return Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/behavior/return-monitor/404",
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


@pytest.mark.asyncio
async def test_http_exception_handler_returns_json_serializable_timestamp(
    advanced_app_main: object,
) -> None:
    response = await advanced_app_main.http_exception_handler(  # type: ignore[attr-defined]
        make_request(), HTTPException(status_code=404, detail="Not found")
    )

    assert response.status_code == 404
    body = json.loads(response.body)
    assert body["detail"] == "Not found"
    assert body["error_code"] == "HTTP_404"
    assert isinstance(body["timestamp"], str)


@pytest.mark.asyncio
async def test_general_exception_handler_returns_json_serializable_timestamp(
    advanced_app_main: object,
) -> None:
    response = await advanced_app_main.general_exception_handler(  # type: ignore[attr-defined]
        make_request(), RuntimeError("boom")
    )

    assert response.status_code == 500
    body = json.loads(response.body)
    assert body["detail"] == "Internal server error"
    assert body["error_code"] == "INTERNAL_ERROR"
    assert isinstance(body["timestamp"], str)
