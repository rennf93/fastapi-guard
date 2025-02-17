import aiohttp
import asyncio
import maxminddb
import os
from pathlib import Path
import time
from typing import Optional


class IPInfoManager:
    """Handler for IPInfo's IP to Country ASN database"""

    def __init__(
        self,
        token: str,
        db_path: Optional[Path] = None
    ):
        if not token:
            raise ValueError("IPInfo token is required!")

        self.token = token
        self.db_path = db_path or Path(
            "data/ipinfo/country_asn.mmdb"
        )
        self.reader: Optional[maxminddb.Reader] = None
        self.redis_handler = None

    async def initialize(self):
        """Initialize the database"""
        os.makedirs(
            self.db_path.parent,
            exist_ok=True
        )

        # Check Redis first if available
        if self.redis_handler:
            cached_db = await self.redis_handler.get_key(
                "ipinfo",
                "database"
            )
            if cached_db:
                with open(self.db_path, 'wb') as f:
                    f.write(
                        cached_db
                        if isinstance(cached_db, bytes)
                        else cached_db.encode('latin-1')
                    )
                self.reader = maxminddb.open_database(
                    str(self.db_path)
                )
                return

        try:
            if not self.db_path.exists() or self._is_db_outdated():
                await self._download_database()
        except Exception:
            if self.db_path.exists():
                self.db_path.unlink()
            self.reader = None
            return

        if self.db_path.exists():
            self.reader = maxminddb.open_database(
                str(self.db_path)
            )

    async def _download_database(self):
        """Download the latest database from IPInfo"""
        base_url = "https://ipinfo.io/data/free/country_asn.mmdb"
        url = f"{base_url}?token={self.token}"
        retries = 3
        backoff = 1

        async with aiohttp.ClientSession() as session:
            for attempt in range(retries):
                try:
                    async with session.get(url) as response:
                        await response.raise_for_status()
                        with open(self.db_path, 'wb') as f:
                            f.write(await response.read())

                        if self.redis_handler and self.db_path.exists():
                            with open(self.db_path, 'rb') as f:
                                db_content = f.read().decode('latin-1')
                            await self.redis_handler.set_key(
                                "ipinfo",
                                "database",
                                db_content,
                                ttl=86400  # 24 hours
                            )
                        return
                except Exception:
                    if attempt == retries - 1:
                        raise
                    await asyncio.sleep(backoff)
                    backoff *= 2

    def _is_db_outdated(self) -> bool:
        """Check if database needs updating (older than 24h)"""
        if not self.db_path.exists():
            return True

        age = time.time() - self.db_path.stat().st_mtime
        return age > 86400

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

    async def initialize_redis(self, redis_handler):
        """Align with other handlers' initialization pattern"""
        self.redis_handler = redis_handler
        await self.initialize()
