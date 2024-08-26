import pytest
from guard.models import SecurityConfig
from guard.middleware import SecurityMiddleware
from guard.utils import reset_global_state
from config.sus_patterns import SusPatterns


@pytest.fixture(autouse=True)
async def reset_state():
    await reset_global_state()
    SusPatterns._instance = None
    yield


@pytest.fixture
def security_config():
    """
    Fixture to create a SecurityConfig object for testing.

    Returns:
        SecurityConfig: A configured SecurityConfig object.
    """
    return SecurityConfig(
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_countries=["CN"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture
async def security_middleware():
    config = SecurityConfig(
        whitelist=[], blacklist=[], auto_ban_threshold=10, auto_ban_duration=300
    )
    middleware = SecurityMiddleware(app=None, config=config)
    await middleware.setup_logger()
    yield middleware
    await middleware.reset()
