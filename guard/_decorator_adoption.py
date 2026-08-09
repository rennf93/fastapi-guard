from __future__ import annotations

from typing import Any


def resolve_app_state_decorator(app: Any) -> Any:
    state = getattr(app, "state", None)
    return getattr(state, "guard_decorator", None)


def adopt_app_state_decorator(guard_decorator: Any, request: Any) -> Any:
    if guard_decorator is not None or request is None:
        return guard_decorator
    scope = getattr(request, "scope", None)
    if not isinstance(scope, dict):
        return guard_decorator
    return resolve_app_state_decorator(scope.get("app"))
