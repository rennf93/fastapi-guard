import aiohttp
import maxminddb
import os
from pathlib import Path
import time
from typing import Optional


class IPInfoManager:
    """Handler for IPInfo's IP to Country ASN database"""

    def __init__(
        self,
        token: str
    ):
        if not token:
            raise ValueError("IPInfo token is required!")

        self.token = token
        self.db_path = Path("data/ipinfo/country_asn.mmdb")
        self.reader: Optional[maxminddb.Reader] = None

    async def initialize(self):
        """Initialize the database"""
        os.makedirs(
            self.db_path.parent,
            exist_ok=True
        )

        if not self.db_path.exists() or self._is_db_outdated():
            await self._download_database()

        self.reader = maxminddb.open_database(str(self.db_path))

    async def _download_database(self):
        """Download the latest database from IPInfo"""
        base_url = "https://ipinfo.io/data/free/country_asn.mmdb"
        url = f"{base_url}?token={self.token}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                response.raise_for_status()
                with open(self.db_path, 'wb') as f:
                    f.write(await response.read())

    def _is_db_outdated(self) -> bool:
        """Check if database needs updating (older than 24h)"""
        if not self.db_path.exists():
            return True

        age = time.time() - self.db_path.stat().st_mtime
        return age > 86400  # 24 hours

    def get_country(self, ip: str) -> Optional[str]:
        """Get country code for an IP address"""
        if not self.reader:
            raise RuntimeError("Database not initialized")

        try:
            result = self.reader.get(ip)
            return result.get('country') if result else None
        except Exception:
            return None

    def close(self):
        """Close the database connection"""
        if self.reader:
            self.reader.close()
