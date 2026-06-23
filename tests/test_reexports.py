import pytest


def test_all_exports_importable() -> None:
    import guard

    for name in guard.__all__:
        assert hasattr(guard, name), f"{name} not found in guard module"


def test_all_derives_from_guard_core_exports() -> None:
    import guard_core

    import guard

    assert set(guard.__all__) == {
        "__version__",
        "SecurityMiddleware",
        *guard_core.__all__,
    }


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


def test_version_exported_matches_package_metadata() -> None:
    from importlib.metadata import version

    from guard import __version__

    assert __version__ == version("fastapi-guard")
    assert __version__ != "0.0.0+unknown"


def test_version_falls_back_when_package_metadata_missing(
    monkeypatch: "pytest.MonkeyPatch",
) -> None:
    import importlib
    from importlib.metadata import PackageNotFoundError

    import guard

    def _raise(name: str) -> str:
        raise PackageNotFoundError(name)

    monkeypatch.setattr("importlib.metadata.version", _raise)
    reloaded = importlib.reload(guard)
    try:
        assert reloaded.__version__ == "0.0.0+unknown"
    finally:
        importlib.reload(guard)
