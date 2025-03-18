import os

import pytest

from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ipban_handler import reset_global_state
from guard.handlers.redis_handler import RedisManager
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.sus_patterns import SusPatterns

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
REDIS_URL = os.getenv("REDIS_URL")
REDIS_PREFIX = os.getenv("REDIS_PREFIX")


@pytest.fixture(autouse=True)
async def reset_state():
    await reset_global_state()
    original_patterns = SusPatterns.patterns.copy()
    SusPatterns._instance = None
    cloud_handler.ip_ranges = {}
    cloud_handler.last_refresh = 0
    yield
    SusPatterns.patterns = original_patterns.copy()
    SusPatterns._instance = None


@pytest.fixture
def security_config():
    """
    Fixture to create a SecurityConfig object for testing.

    Returns:
        SecurityConfig: A configured SecurityConfig object.
    """
    return SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        enable_redis=False,
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
        ipinfo_token=IPINFO_TOKEN,
        whitelist=[],
        blacklist=[],
        auto_ban_threshold=10,
        auto_ban_duration=300,
    )
    middleware = SecurityMiddleware(app=None, config=config)
    await middleware.setup_logger()
    yield middleware
    await middleware.reset()


@pytest.fixture(scope="session")
def ipinfo_db_path(tmp_path_factory):
    """Shared temporary path for IPInfo database"""
    return tmp_path_factory.mktemp("ipinfo_data") / "country_asn.mmdb"


@pytest.fixture
def security_config_redis(ipinfo_db_path):
    """SecurityConfig with Redis enabled"""
    return SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
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


@pytest.fixture(autouse=True)
async def redis_cleanup():
    """Clean Redis test keys before each test"""
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
    )
    handler = RedisManager(config)
    await handler.initialize()
    try:
        async with handler.get_connection() as conn:
            keys = await conn.keys(f"{REDIS_PREFIX}*")
            if keys:
                await conn.delete(*keys)
    finally:
        await handler.close()
