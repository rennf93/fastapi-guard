from cachetools import TTLCache
import time


class IPBanManager:
    """
    A class for managing IP bans.
    """

    def __init__(self):
        """
        Initialize the IPBanManager.
        """
        self.banned_ips = TTLCache(
            maxsize=10000,
            ttl=3600
        )

    async def ban_ip(
        self,
        ip: str,
        duration: int
    ):
        """
        Ban an IP address for
        a specified duration.
        """
        self.banned_ips[ip] = time.time() + duration

    async def is_ip_banned(
        self,
        ip: str
    ) -> bool:
        """
        Check if an IP
        address is banned.
        """
        if ip in self.banned_ips:
            if time.time() > self.banned_ips[ip]:
                del self.banned_ips[ip]
                return False
            return True
        return False

    async def reset(self):
        """
        Reset the banned IPs.
        """
        self.banned_ips.clear()


ip_ban_manager = IPBanManager()


async def reset_global_state():
    """
    Reset all global state.
    """
    global ip_ban_manager
    ip_ban_manager = IPBanManager()
