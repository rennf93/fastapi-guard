# guard/handlers/ipban_handler.py
import logging
import time
from datetime import datetime, timezone
from typing import Any

from cachetools import TTLCache


class IPBanManager:
    """
    A class for managing IP bans.
    """

    _instance = None
    banned_ips: TTLCache
    redis_handler: Any = None
    agent_handler: Any = None

    def __new__(cls: type["IPBanManager"]) -> "IPBanManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.banned_ips = TTLCache(maxsize=10000, ttl=3600)
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
        return cls._instance

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    async def initialize_agent(self, agent_handler: Any) -> None:
        """Initialize agent integration."""
        self.agent_handler = agent_handler

    async def ban_ip(
        self, ip: str, duration: int, reason: str = "threshold_exceeded"
    ) -> None:
        """
        Ban an IP address for
        a specified duration.
        """
        expiry = time.time() + duration
        self.banned_ips[ip] = expiry

        if self.redis_handler:
            await self.redis_handler.set_key(
                "banned_ips", ip, str(expiry), ttl=duration
            )

        # Send event to agent
        if self.agent_handler:
            await self._send_ban_event(ip, duration, reason)

    async def _send_ban_event(self, ip: str, duration: int, reason: str) -> None:
        """Send IP ban event to agent."""
        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address=ip,
                action_taken="banned",
                reason=reason,
                metadata={"duration": duration},
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            # Don't let agent errors break the ban functionality
            logging.getLogger("fastapi_guard.handlers.ipban").error(
                f"Failed to send ban event to agent: {e}"
            )

    async def unban_ip(self, ip: str) -> None:
        """
        Unban an IP address (remove from ban list).
        """
        # Remove from local cache
        if ip in self.banned_ips:
            del self.banned_ips[ip]

        # Remove from Redis
        if self.redis_handler:
            await self.redis_handler.delete("banned_ips", ip)

        # Send event to agent
        if self.agent_handler:
            await self._send_unban_event(ip)

    async def _send_unban_event(self, ip: str) -> None:
        """Send IP unban event to agent."""
        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_unbanned",
                ip_address=ip,
                action_taken="unbanned",
                reason="dynamic_rule_whitelist",
                metadata={"action": "unban"},
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            # Don't let agent errors break the unban functionality
            logging.getLogger("fastapi_guard.handlers.ipban").error(
                f"Failed to send unban event to agent: {e}"
            )

    async def is_ip_banned(self, ip: str) -> bool:
        """
        Check if an IP
        address is banned.
        """
        current_time = time.time()

        if ip in self.banned_ips:
            if current_time > self.banned_ips[ip]:
                del self.banned_ips[ip]
                return False
            return True

        if self.redis_handler:
            expiry = await self.redis_handler.get_key("banned_ips", ip)
            if expiry:
                expiry_time = float(expiry)
                if current_time <= expiry_time:
                    self.banned_ips[ip] = expiry_time
                    return True
                await self.redis_handler.delete("banned_ips", ip)

        return False

    async def reset(self) -> None:
        """
        Reset the banned IPs.
        """
        self.banned_ips.clear()
        if self.redis_handler:
            async with self.redis_handler.get_connection() as conn:
                keys = await conn.keys(
                    f"{self.redis_handler.config.redis_prefix}banned_ips:*"
                )
                if keys:
                    await conn.delete(*keys)


# Instance
ip_ban_manager = IPBanManager()


async def reset_global_state() -> None:
    """
    Reset all global state.
    """
    global ip_ban_manager
    ip_ban_manager = IPBanManager()
