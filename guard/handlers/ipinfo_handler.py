import asyncio
import os
import time
from pathlib import Path
from typing import Any

import aiohttp
import maxminddb


class IPInfoManager:
    """Handler for IPInfo's IP to Country ASN database"""

    def __init__(self, token: str, db_path: Path | None = None):
        if not token:
            raise ValueError("IPInfo token is required!")

        self.token = token
        self.db_path = db_path or Path("data/ipinfo/country_asn.mmdb")
        self.reader: maxminddb.Reader | None = None
        self.redis_handler: Any = None

    async def initialize(self) -> None:
        """Initialize the database"""
        os.makedirs(self.db_path.parent, exist_ok=True)

        if self.redis_handler:
            cached_db = await self.redis_handler.get_key("ipinfo", "database")
            if cached_db:
                with open(self.db_path, "wb") as f:
                    f.write(
                        cached_db
                        if isinstance(cached_db, bytes)
                        else cached_db.encode("latin-1")
                    )
                self.reader = maxminddb.open_database(str(self.db_path))
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
            self.reader = maxminddb.open_database(str(self.db_path))

    async def _download_database(self) -> None:
        """Download the latest database from IPInfo"""
        base_url = "https://ipinfo.io/data/free/country_asn.mmdb"
        url = f"{base_url}?token={self.token}"
        retries = 3
        backoff = 1

        async with aiohttp.ClientSession() as session:
            for attempt in range(retries):
                try:
                    async with session.get(url) as response:
                        response.raise_for_status()
                        with open(self.db_path, "wb") as f:
                            f.write(await response.read())

                        if self.redis_handler is not None:
                            with open(self.db_path, "rb") as f:
                                db_content = f.read().decode("latin-1")
                            await self.redis_handler.set_key(
                                "ipinfo",
                                "database",
                                db_content,
                                ttl=86400,  # 24 hours
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

    def get_country(self, ip: str) -> str | None:
        """Get country code for an IP address"""
        if not self.reader:
            raise RuntimeError("Database not initialized")

        try:
            result = self.reader.get(ip)
            if isinstance(result, dict) and "country" in result:
                country = result.get("country")
                return str(country) if country is not None else None
            return None
        except Exception:
            return None

    def close(self) -> None:
        """Close the database connection"""
        if self.reader:
            self.reader.close()

    async def initialize_redis(self, redis_handler: Any) -> None:
        """Align with other handlers' initialization pattern"""
        self.redis_handler = redis_handler
        await self.initialize()
