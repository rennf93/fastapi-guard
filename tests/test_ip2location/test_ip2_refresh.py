from config.ip2.ip2location_config import (
    check_for_updates,
    download_ip2location_database,
)
from datetime import datetime, timedelta, timezone
from guard.models import SecurityConfig
import unittest
from unittest.mock import patch, mock_open, MagicMock


class TestIP2Refresh(unittest.TestCase):

    @patch("config.ip2.ip2location_config.requests.head")
    def test_check_for_updates_new_version(self, mock_head):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Last-Modified": (datetime.now(timezone.utc) + timedelta(days=1)).strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            )
        }
        mock_head.return_value = mock_response

        with patch(
            "builtins.open", mock_open(read_data=datetime.now(timezone.utc).isoformat())
        ):
            self.assertTrue(check_for_updates())

    @patch("config.ip2.ip2location_config.requests.head")
    def test_check_for_updates_current_version(self, mock_head):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Last-Modified": (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            )
        }
        mock_head.return_value = mock_response

        with patch(
            "builtins.open", mock_open(read_data=datetime.now(timezone.utc).isoformat())
        ):
            self.assertFalse(check_for_updates())

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
        mock_remove.assert_called_once()
        mock_file().write.assert_called()
