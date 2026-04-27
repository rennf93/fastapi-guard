def test_all_exports_importable() -> None:
    import guard

    for name in guard.__all__:
        assert hasattr(guard, name), f"{name} not found in guard module"


def test_security_middleware_importable() -> None:
    from guard.middleware import SecurityMiddleware

    assert SecurityMiddleware is not None


def test_adapters_importable() -> None:
    from guard.adapters import (
        StarletteGuardRequest,
        StarletteGuardResponse,
        StarletteResponseFactory,
    )

    assert StarletteGuardRequest is not None
    assert StarletteGuardResponse is not None
    assert StarletteResponseFactory is not None
