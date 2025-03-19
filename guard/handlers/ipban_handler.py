import time
from typing import Any

from cachetools import TTLCache


class IPBanManager:
    """
    A class for managing IP bans.
    """

    def __init__(self) -> None:
        """
        Initialize the IPBanManager.
        """
        self.banned_ips: TTLCache = TTLCache(maxsize=10000, ttl=3600)
        self.redis_handler: Any | None = None

    async def initialize_redis(self, redis_handler: Any) -> None:
        self.redis_handler = redis_handler

    async def ban_ip(self, ip: str, duration: int) -> None:
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


ip_ban_manager = IPBanManager()


async def reset_global_state() -> None:
    """
    Reset all global state.
    """
    global ip_ban_manager
    ip_ban_manager = IPBanManager()
