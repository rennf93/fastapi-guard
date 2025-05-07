import os
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from fastapi import FastAPI
from pytest import TempPathFactory

from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ipban_handler import reset_global_state
from guard.handlers.ipinfo_handler import IPInfoManager
from guard.handlers.ratelimit_handler import rate_limit_handler
from guard.handlers.redis_handler import RedisManager
from guard.handlers.suspatterns_handler import sus_patterns_handler
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))
REDIS_URL = str(os.getenv("REDIS_URL"))
REDIS_PREFIX = str(os.getenv("REDIS_PREFIX"))


@pytest.fixture(autouse=True)
async def reset_state() -> AsyncGenerator[None, None]:
    # Reset IPBanManager
    await reset_global_state()

    # Reset SusPatternsManager
    original_patterns = sus_patterns_handler.patterns.copy()
    sus_patterns_handler._instance = None

    # Reset CloudManager
    cloud_instance = cloud_handler._instance
    if cloud_instance:
        cloud_instance.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
        cloud_instance.redis_handler = None

    # Reset IPInfoManager
    if IPInfoManager._instance:
        if IPInfoManager._instance.reader:
            IPInfoManager._instance.reader.close()
        IPInfoManager._instance = None

    yield
    sus_patterns_handler.patterns = original_patterns.copy()
    sus_patterns_handler._instance = None


@pytest.fixture
def security_config() -> SecurityConfig:
    """
    Fixture to create a SecurityConfig object for testing.

    Returns:
        SecurityConfig: A configured SecurityConfig object.
    """
    return SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN, None),
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
async def security_middleware() -> AsyncGenerator[SecurityMiddleware, None]:
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        whitelist=[],
        blacklist=[],
        auto_ban_threshold=10,
        auto_ban_duration=300,
    )
    app = FastAPI()
    middleware = SecurityMiddleware(app=app, config=config)
    await middleware.setup_logger()
    yield middleware
    await middleware.reset()


@pytest.fixture(scope="session")
def ipinfo_db_path(tmp_path_factory: TempPathFactory) -> Path:
    """Shared temporary path for IPInfo database"""
    return tmp_path_factory.mktemp("ipinfo_data") / "country_asn.mmdb"


@pytest.fixture
def security_config_redis(ipinfo_db_path: Path) -> SecurityConfig:
    """SecurityConfig with Redis enabled"""
    return SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN, ipinfo_db_path),
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
async def redis_cleanup() -> None:
    """Clean Redis test keys before each test"""
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN, None),
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
    )
    redis_handler = RedisManager(config)
    await redis_handler.initialize()
    try:
        await redis_handler.delete_pattern(f"{REDIS_PREFIX}*")
    finally:
        await redis_handler.close()


@pytest.fixture(autouse=True)
async def reset_rate_limiter() -> None:
    """Reset rate limiter between tests to avoid interference"""
    config = SecurityConfig(geo_ip_handler=IPInfoManager(IPINFO_TOKEN, None))
    rate_limit = rate_limit_handler(config)
    await rate_limit.reset()
