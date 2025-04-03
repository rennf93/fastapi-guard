import html
import ipaddress
import logging
import re
from typing import Any

import requests


def fetch_aws_ip_ranges() -> set[ipaddress.IPv4Network]:
    try:
        response = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json")
        response.raise_for_status()
        data = response.json()
        return {
            ipaddress.IPv4Network(ip_range["ip_prefix"])
            for ip_range in data["prefixes"]
            if ip_range["service"] == "AMAZON"
        }
    except Exception as e:
        logging.error(f"Failed to fetch AWS IP ranges: {str(e)}")
        return set()


def fetch_gcp_ip_ranges() -> set[ipaddress.IPv4Network]:
    try:
        response = requests.get("https://www.gstatic.com/ipranges/cloud.json")
        response.raise_for_status()
        data = response.json()
        return {
            ipaddress.IPv4Network(ip_range["ipv4Prefix"])
            for ip_range in data["prefixes"]
            if "ipv4Prefix" in ip_range
        }
    except Exception as e:
        logging.error(f"Failed to fetch GCP IP ranges: {str(e)}")
        return set()


def fetch_azure_ip_ranges() -> set[ipaddress.IPv4Network]:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/91.0.4472.124 Safari/537.36"
        }
        route = "/download/details.aspx?id=56519"
        response = requests.get(
            f"https://www.microsoft.com/en-us{route}", headers=headers
        )
        response.raise_for_status()

        decoded_html = html.unescape(response.text)
        pattern = (
            r'href=["\'](https://download\.microsoft\.com/'
            r'.*?\.json)["\']'
        )
        match = re.search(pattern, decoded_html)

        if not match:
            raise ValueError("Could not find Azure IP ranges download URL")

        download_url = match.group(1)
        response = requests.get(download_url)
        response.raise_for_status()
        data = response.json()

        return {
            ipaddress.IPv4Network(ip_range)
            for ip_range in data["values"][0]["properties"]["addressPrefixes"]
            if ":" not in ip_range
        }
    except Exception as e:
        logging.error(f"Failed to fetch Azure IP ranges: {str(e)}")
        return set()


class CloudManager:
    """Manages cloud provider IP ranges with optional Redis caching."""

    _instance = None
    ip_ranges: dict[str, set[ipaddress.IPv4Network]]
    redis_handler: Any = None
    logger: logging.Logger

    def __new__(cls: type["CloudManager"]) -> "CloudManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.ip_ranges = {
                "AWS": set(),
                "GCP": set(),
                "Azure": set(),
            }
            cls._instance.redis_handler = None
            cls._instance.logger = logging.getLogger(__name__)
            cls._instance._initial_refresh()
        return cls._instance

    def _initial_refresh(self) -> None:
        """Perform initial synchronous refresh if Redis is not used."""
        if self.redis_handler is None:
            self._refresh_sync()

    def _refresh_sync(self) -> None:
        """Synchronous refresh of cloud IP ranges."""
        for provider, fetch_func in [
            ("AWS", fetch_aws_ip_ranges),
            ("GCP", fetch_gcp_ip_ranges),
            ("Azure", fetch_azure_ip_ranges),
        ]:
            try:
                ranges = fetch_func()
                if ranges:
                    self.ip_ranges[provider] = ranges
            except Exception as e:
                self.logger.error(f"Failed to fetch {provider} IP ranges: {str(e)}")
                self.ip_ranges[provider] = set()

    async def initialize_redis(self, redis_handler: Any) -> None:
        """Initialize Redis connection and load cached ranges."""
        self.redis_handler = redis_handler
        await self.refresh_async()

    def refresh(self) -> None:
        """Synchronous refresh method for backward compatibility."""
        if self.redis_handler is None:
            self._refresh_sync()
        else:
            raise RuntimeError("Use async refresh() when Redis is enabled")

    async def refresh_async(self) -> None:
        """Asynchronous refresh method for Redis-enabled operation."""
        if self.redis_handler is None:
            self._refresh_sync()
            return

        for provider in ["AWS", "GCP", "Azure"]:
            try:
                cached_ranges = await self.redis_handler.get_key(
                    "cloud_ranges", provider
                )
                if cached_ranges:
                    self.ip_ranges[provider] = {
                        ipaddress.IPv4Network(ip) for ip in cached_ranges.split(",")
                    }
                    continue

                fetch_func = {
                    "AWS": fetch_aws_ip_ranges,
                    "GCP": fetch_gcp_ip_ranges,
                    "Azure": fetch_azure_ip_ranges,
                }[provider]

                ranges = fetch_func()
                if ranges:
                    self.ip_ranges[provider] = ranges

                    await self.redis_handler.set_key(
                        "cloud_ranges",
                        provider,
                        ",".join(str(ip) for ip in ranges),
                        ttl=3600,
                    )

            except Exception as e:
                self.logger.error(f"Failed to refresh {provider} IP ranges: {str(e)}")
                if provider not in self.ip_ranges:
                    self.ip_ranges[provider] = set()

    def is_cloud_ip(self, ip: str, providers: set[str]) -> bool:
        """
        Check if an IP belongs to specified cloud providers.

        Args:
            ip: IP address to check
            providers: Set of cloud provider names to check against

        Returns:
            bool: True if IP belongs to any specified provider
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(
                any(ip_obj in network for network in self.ip_ranges[provider])
                for provider in providers
                if provider in self.ip_ranges
            )
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return False


# Instance
cloud_handler = CloudManager()
