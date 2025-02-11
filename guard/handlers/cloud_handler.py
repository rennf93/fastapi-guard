import html
import ipaddress
import logging
import requests
import re
from typing import (
    Dict,
    Set
)


def fetch_aws_ip_ranges() -> Set[ipaddress.IPv4Network]:
    try:
        response = requests.get(
            "https://ip-ranges.amazonaws.com/ip-ranges.json"
        )
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


def fetch_gcp_ip_ranges() -> Set[ipaddress.IPv4Network]:
    try:
        response = requests.get(
            "https://www.gstatic.com/ipranges/cloud.json"
        )
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


def fetch_azure_ip_ranges() -> Set[ipaddress.IPv4Network]:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/91.0.4472.124 Safari/537.36"
        }

        route = "/download/confirmation.aspx?id=56519"
        response = requests.get(
            f"https://www.microsoft.com{route}", 
            headers=headers
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
    def __init__(self):
        self.ip_ranges: Dict[str, Set[ipaddress.IPv4Network]] = {}
        self.refresh()

    def refresh(self):
        self.ip_ranges = {}
        for provider, fetch_func in [
            ("AWS", fetch_aws_ip_ranges),
            ("GCP", fetch_gcp_ip_ranges),
            ("Azure", fetch_azure_ip_ranges),
        ]:
            try:
                self.ip_ranges[provider] = fetch_func()
            except Exception as e:
                logging.error(
                    f"Failed to fetch {provider} IP ranges: {str(e)}"
                )
                self.ip_ranges[provider] = set()

    def is_cloud_ip(
        self,
        ip: str,
        providers: Set[str]
    ) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(
                any(
                    ip_obj in network
                    for network in self.ip_ranges[provider]
                )
                for provider in providers
                if provider in self.ip_ranges
            )
        except ValueError:
            logging.error(f"Invalid IP address: {ip}")
            return False


cloud_handler = CloudManager()
