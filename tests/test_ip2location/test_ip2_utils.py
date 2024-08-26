from config.ip2.ip2location_config import (
    download_ip2location_database,
    IP2_CONFIG_PATH,
    DB_FILENAME,
)
from guard.models import SecurityConfig
import unittest
from unittest.mock import patch, mock_open, MagicMock


class TestIP2Utils(unittest.TestCase):

    @patch("config.ip2.ip2location_config.requests.get")
    @patch("config.ip2.ip2location_config.check_for_updates")
    @patch("config.ip2.ip2location_config.zipfile.ZipFile")
    @patch("config.ip2.ip2location_config.os.remove")
    @patch("builtins.open", new_callable=mock_open)
    def test_download_ip2location_database(
        self, mock_file, mock_remove, mock_zipfile, mock_check, mock_get
    ):
        mock_check.return_value = True
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        config = SecurityConfig(use_ip2location=True, ip2location_auto_download=True)

        download_ip2location_database(config=config)

        mock_get.assert_called_once()
        mock_file.assert_called()
        mock_zipfile.assert_called_once()
        mock_remove.assert_called_once_with(f"{IP2_CONFIG_PATH}/{DB_FILENAME}.ZIP")
        mock_file().write.assert_called()

    @patch("config.ip2.ip2location_config.check_for_updates")
    def test_download_ip2location_database_auto_download_disabled(self, mock_check):
        config = SecurityConfig(use_ip2location=True, ip2location_auto_download=False)

        download_ip2location_database(config=config)

        mock_check.assert_not_called()

    @patch("config.ip2.ip2location_config.check_for_updates")
    def test_download_ip2location_database_no_update_available(self, mock_check):
        mock_check.return_value = False
        config = SecurityConfig(use_ip2location=True, ip2location_auto_download=True)

        download_ip2location_database(config=config)

        mock_check.assert_called_once()
