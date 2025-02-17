import asyncio
from fastapi import FastAPI, status
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.handlers.ipban_handler import IPBanManager, ip_ban_manager
from guard.handlers.redis_handler import RedisManager
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
import os
import pytest
import time


IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")


@pytest.mark.asyncio
async def test_ip_ban_manager(reset_state):
    """
    Test the IPBanManager.
    """
    manager = IPBanManager()
    ip = "192.168.1.1"

    assert await manager.is_ip_banned(ip) == False

    await manager.ban_ip(ip, 1)
    assert await manager.is_ip_banned(ip) == True

    await asyncio.sleep(1.1)
    assert await manager.is_ip_banned(ip) == False


@pytest.mark.asyncio
async def test_automatic_ip_ban(reset_state):
    """
    Test the automatic IP banning.
    """
    app = FastAPI()
    config = SecurityConfig(
        ipinfo_token=IPINFO_TOKEN,
        enable_ip_banning=True,
        enable_penetration_detection=True,
        auto_ban_threshold=3,
        auto_ban_duration=300
    )
    app.add_middleware(SecurityMiddleware, config=config)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as client:
        for _ in range(config.auto_ban_threshold):
            await client.get(
                "/test",
                params={"input": "<script>alert(1)</script>"},
                headers={"X-Forwarded-For": "192.168.1.2"}
            )

        response = await client.get(
            "/",
            headers={"X-Forwarded-For": "192.168.1.2"}
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_reset_ip_ban_manager():
    """
    Test the IPBanManager reset method.
    """
    await ip_ban_manager.ban_ip("test_ip", 3600)
    await ip_ban_manager.reset()
    assert await ip_ban_manager.is_ip_banned("test_ip") == False


@pytest.mark.asyncio
async def test_ban_ip_concurrent_access():
    manager = IPBanManager()
    ip = "192.168.1.100"
    await asyncio.gather(
        *[manager.ban_ip(ip, 1) for _ in range(10)]
    )
    assert await manager.is_ip_banned(ip)


@pytest.mark.asyncio
async def test_ip_ban_manager_with_redis(security_config_redis):
    """Test IPBanManager with Redis integration"""
    manager = IPBanManager()
    redis_mgr = RedisManager(security_config_redis)
    await redis_mgr.initialize()
    await manager.initialize_redis(redis_mgr)

    ip = "192.168.1.1"
    duration = 2

    # Test banning
    await manager.ban_ip(ip, duration)
    assert await manager.is_ip_banned(ip) == True

    # Test Redis persistence
    new_manager = IPBanManager()
    await new_manager.initialize_redis(redis_mgr)
    assert await new_manager.is_ip_banned(ip) == True

    # Test expiration
    await asyncio.sleep(2.1)
    assert await manager.is_ip_banned(ip) == False
    assert await new_manager.is_ip_banned(ip) == False

    await redis_mgr.close()


@pytest.mark.asyncio
async def test_ip_ban_manager_redis_reset(security_config_redis):
    """Test IPBanManager reset with Redis"""
    manager = IPBanManager()
    redis_mgr = RedisManager(security_config_redis)
    await redis_mgr.initialize()
    await manager.initialize_redis(redis_mgr)

    # Ban multiple IPs
    ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    for ip in ips:
        await manager.ban_ip(ip, 3600)
        assert await manager.is_ip_banned(ip) == True

    # Reset and verify
    await manager.reset()
    for ip in ips:
        assert await manager.is_ip_banned(ip) == False
        # Verify Redis keys are also cleared
        assert await redis_mgr.exists("banned_ips", ip) == False

    await redis_mgr.close()


@pytest.mark.asyncio
async def test_ip_ban_manager_redis_expired_cleanup(security_config_redis):
    """Test cleanup of expired bans in Redis"""
    manager = IPBanManager()
    redis_mgr = RedisManager(security_config_redis)
    await redis_mgr.initialize()
    await manager.initialize_redis(redis_mgr)

    ip = "192.168.1.1"
    duration = 1

    # Ban the IP
    await manager.ban_ip(ip, duration)
    assert await manager.is_ip_banned(ip) == True

    # Clear local cache and manually set expired time in Redis
    manager.banned_ips.clear()  # Clear local cache
    past_expiry = str(time.time() - 10)  # 10 seconds in the past
    await redis_mgr.set_key("banned_ips", ip, past_expiry)

    # Check ban status - this should trigger the cleanup
    assert await manager.is_ip_banned(ip) == False

    # Verify the key was deleted from Redis
    assert await redis_mgr.exists("banned_ips", ip) == False

    await redis_mgr.close()
