import asyncio
from datetime import datetime, timezone
from IP2Location import IP2Location
import os
import requests
import zipfile

IP2_CONFIG_PATH = "./config/ip2/files"
DOWNLOAD_URL = "https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.IPV6.BIN.ZIP"
DB_FILENAME = "IP2LOCATION-LITE-DB1.IPV6.BIN"
VERSION_FILE = f"{IP2_CONFIG_PATH}/ip2location_version.txt"



ip2location_db = None



def get_ip2location_database():
    """
    Get the IP2Location database object.
    """
    global ip2location_db
    if ip2location_db is None:
        db_path = os.path.join(IP2_CONFIG_PATH, DB_FILENAME)
        ip2location_db = IP2Location(db_path)
    return ip2location_db



def check_for_updates():
    """
    Check if there's a new version of the IP2Location database available.

    Returns:
        bool: True if an update is available, False otherwise.
    """
    response = requests.head(DOWNLOAD_URL)
    if response.status_code != 200:
        print(f"Failed to check for updates. Status code: {response.status_code}")
        return False

    last_modified = datetime.strptime(response.headers['Last-Modified'], "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)

    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, 'r') as f:
            current_version = datetime.fromisoformat(f.read().strip()).replace(tzinfo=timezone.utc)

        if last_modified <= current_version:
            print("Database is up to date.")
            return False

    print("New version available. Updating...")
    return True



def download_ip2location_database():
    """
    Download and extract the latest IP2Location database if an update is available.
    """
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

        with open(VERSION_FILE, 'w') as f:
            f.write(datetime.now(timezone.utc).isoformat())

        print("IP2Location database downloaded and extracted successfully.")
    else:
        print(f"Failed to download IP2Location database. Status code: {response.status_code}")



async def periodic_update_check(interval_hours=24):
    """
    Periodically check for updates and download the new database if available.
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



async def start_periodic_update_check(interval_hours=24):
    """
    Start the periodic update check in the background.
    """
    task = asyncio.create_task(periodic_update_check(interval_hours))

    def handle_task_done(future):
        try:
            future.result()
        except asyncio.CancelledError:
            pass

    task.add_done_callback(handle_task_done)
    return task