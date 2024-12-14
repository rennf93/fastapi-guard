import asyncio
from fastapi import FastAPI, status
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.handlers.ipban_handler import IPBanManager, ip_ban_manager
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
import os
import pytest


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
