import asyncio
from datetime import datetime, timezone
from IP2Location import IP2Location
import logging
import os
import requests
import zipfile

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guard.models import SecurityConfig

IP2_CONFIG_PATH = "./config/ip2/files"
DB_FILENAME = "IP2LOCATION-LITE-DB1.IPV6.BIN"
DOWNLOAD_URL = f"https://download.ip2location.com/lite/{DB_FILENAME}.ZIP"
VERSION_FILE = f"{IP2_CONFIG_PATH}/ip2location_version.txt"

ip2location_db = None


def get_ip2location_database(
    config: "SecurityConfig"
) -> IP2Location:
    """
    Get the IP2Location database object.
    """
    global ip2location_db
    if ip2location_db is None:
        db_path = config.ip2location_db_path or os.path.join(
            IP2_CONFIG_PATH, DB_FILENAME
        )
        try:
            ip2location_db = IP2Location(db_path)
        except Exception as e:
            message = "Error loading IP2Location database"
            reason_message = f"Reason: {str(e)}"
            logging.error(f"{message} - {reason_message}")
            ip2location_db = None
    return ip2location_db


def check_for_updates() -> bool:
    """
    Check if there's a new version
    of the IP2Location database available.

    Returns:
        bool: True if an update is
        available, False otherwise.
    """
    response = requests.head(DOWNLOAD_URL)
    if response.status_code != 200:
        message = "Failed to check for updates"
        reason_message = f"Status code: {response.status_code}"
        logging.error(f"{message} - {reason_message}")
        return False

    last_modified = datetime.strptime(
        response.headers[
            "Last-Modified"
        ], "%a, %d %b %Y %H:%M:%S GMT"
    ).replace(tzinfo=timezone.utc)

    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, "r") as f:
            current_version = datetime.fromisoformat(
                f.read().strip()
            ).replace(
                tzinfo=timezone.utc
            )

        if last_modified <= current_version:
            print("Database is up to date.")
            return False

    print("New version available. Updating...")
    return True


def download_ip2location_database(
    config: "SecurityConfig"
):
    """
    Download and extract the latest IP2Location
    database if an update is available.
    """
    if not config.ip2location_auto_download:
        return

    if not check_for_updates():
        return

    response = requests.get(DOWNLOAD_URL)

    if response.status_code == 200:
        zip_path = os.path.join(IP2_CONFIG_PATH, f"{DB_FILENAME}.ZIP")
        with open(zip_path, "wb") as f:
            f.write(response.content)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(IP2_CONFIG_PATH)

        os.remove(zip_path)

        with open(VERSION_FILE, "w") as f:
            f.write(
                datetime.now(
                    timezone.utc
                ).isoformat()
            )

        logging.info("IP2Location db downloaded successfully.")
    else:
        message = "Failed to download IP2Location database"
        reason_message = f"Status code: {response.status_code}"
        logging.error(f"{message} - {reason_message}")


async def periodic_update_check(
    interval_hours: int = 24
):
    """
    Periodically check for updates
    and download the new database if available.
    """
    while True:
        try:
            await asyncio.sleep(interval_hours * 3600)
            if check_for_updates():
                download_ip2location_database()

                global ip2location_db
                ip2location_db = None
        except asyncio.CancelledError:
            break


async def start_periodic_update_check(
    config: "SecurityConfig"
):
    """
    Start the periodic update
    check in the background.
    """
    if not config.ip2location_auto_update:
        return None

    task = asyncio.create_task(
        periodic_update_check(
            config.ip2location_update_interval
        )
    )

    def handle_task_done(future):
        try:
            future.result()
        except asyncio.CancelledError:
            pass

    task.add_done_callback(handle_task_done)
    return task
