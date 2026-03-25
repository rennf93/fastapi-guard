from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from typing import Any, cast

from guard_core.protocols.request_protocol import GuardRequest
from guard_core.protocols.response_protocol import GuardResponse
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response


class StarletteGuardRequest:
    def __init__(self, request: Request) -> None:
        self._request = request

    @property
    def url_path(self) -> str:
        return self._request.url.path

    @property
    def url_scheme(self) -> str:
        return self._request.url.scheme

    @property
    def url_full(self) -> str:
        return str(self._request.url)

    def url_replace_scheme(self, scheme: str) -> str:
        return str(self._request.url.replace(scheme=scheme))

    @property
    def method(self) -> str:
        return self._request.method

    @property
    def client_host(self) -> str | None:
        if self._request.client:
            return self._request.client.host
        return None

    @property
    def headers(self) -> Mapping[str, str]:
        return self._request.headers

    @property
    def query_params(self) -> Mapping[str, str]:
        return self._request.query_params

    async def body(self) -> bytes:
        return await self._request.body()

    @property
    def state(self) -> Any:
        return self._request.state

    @property
    def scope(self) -> dict[str, Any]:
        return cast(dict[str, Any], self._request.scope)


class StarletteGuardResponse:
    def __init__(self, response: Response) -> None:
        self._response = response

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def headers(self) -> MutableMapping[str, str]:
        return cast(MutableMapping[str, str], self._response.headers)

    @property
    def body(self) -> bytes | None:
        return self._response.body


class StarletteResponseFactory:
    def create_response(self, content: str, status_code: int) -> StarletteGuardResponse:
        return StarletteGuardResponse(
            Response(content=content, status_code=status_code)
        )

    def create_redirect_response(
        self, url: str, status_code: int
    ) -> StarletteGuardResponse:
        return StarletteGuardResponse(
            RedirectResponse(url=url, status_code=status_code)
        )


def wrap_call_next(
    call_next: Callable[[Request], Awaitable[Response]],
    starlette_request: Request,
) -> Callable[[GuardRequest], Awaitable[GuardResponse]]:
    async def wrapped(guard_request: GuardRequest) -> GuardResponse:
        response = await call_next(starlette_request)
        return StarletteGuardResponse(response)

    return wrapped


def unwrap_response(guard_response: GuardResponse) -> Response:
    if isinstance(guard_response, StarletteGuardResponse):
        return guard_response._response
    return Response(
        content=guard_response.body,
        status_code=guard_response.status_code,
        headers=dict(guard_response.headers),
    )
