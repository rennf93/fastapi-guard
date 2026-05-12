from unittest.mock import MagicMock

from guard_core.models import SecurityConfig

from guard.middleware import SecurityMiddleware


def test_mark_initialized_marks_pipeline_as_ready() -> None:
    config = SecurityConfig(enable_redis=False)
    app = MagicMock()
    middleware = SecurityMiddleware(app, config=config)

    assert middleware._is_initialized() is False
    middleware.mark_initialized()
    assert middleware._is_initialized() is True


def test_mark_initialized_is_idempotent() -> None:
    config = SecurityConfig(enable_redis=False)
    app = MagicMock()
    middleware = SecurityMiddleware(app, config=config)
    middleware.mark_initialized()
    middleware.mark_initialized()
    assert middleware._is_initialized() is True
