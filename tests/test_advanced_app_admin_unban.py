import importlib

import pytest
from fastapi import BackgroundTasks
from guard_core.handlers.ipban_handler import ip_ban_manager

BANNED_IP = "203.0.113.5"


@pytest.mark.asyncio
async def test_unban_ip_route_actually_unbans(advanced_app_main: object) -> None:
    admin_module = importlib.import_module("app.routes.admin")

    await ip_ban_manager.ban_ip(BANNED_IP, duration=300, reason="test")
    assert await ip_ban_manager.is_ip_banned(BANNED_IP)

    response = await admin_module.unban_ip_address(
        ip=BANNED_IP, background_tasks=BackgroundTasks()
    )

    assert response.message == f"IP {BANNED_IP} has been unbanned"
    assert not await ip_ban_manager.is_ip_banned(BANNED_IP)
