from guard.middleware import SecurityMiddleware


async def test_middleware_builds_pipeline_via_factory(
    security_middleware: SecurityMiddleware,
) -> None:
    security_middleware._build_security_pipeline()

    assert security_middleware.security_pipeline is not None
    check_names = security_middleware.security_pipeline.get_check_names()
    assert len(check_names) == 17
    assert "ip_security" in check_names
    assert "rate_limit" in check_names
    assert "suspicious_activity" in check_names


def test_build_default_pipeline_symbol_is_importable() -> None:
    from guard_core.core.checks import build_default_pipeline

    assert callable(build_default_pipeline)
