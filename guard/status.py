from typing import Any

from starlette.responses import JSONResponse

from guard.lifespan import _find_security_middleware


def add_status_route(app: Any, path: str = "/_guard/status") -> None:
    middleware = _find_security_middleware(app)
    if middleware is None:
        raise RuntimeError(
            "add_status_route() must be called after "
            "app.add_middleware(SecurityMiddleware, config=...)"
        )

    async def guard_initialization_status() -> JSONResponse:
        return JSONResponse(middleware.get_initialization_status())

    app.add_route(
        path, guard_initialization_status, methods=["GET"], include_in_schema=False
    )
