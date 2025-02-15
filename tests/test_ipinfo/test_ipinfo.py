from guard.handlers.ipinfo_handler import IPInfoManager
import pytest
from unittest.mock import patch, Mock
from unittest.mock import AsyncMock



@pytest.mark.asyncio
async def test_ipinfo_db():
    """Test IPInfoManager functionality."""
    db = IPInfoManager(token="test_token")

    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock()
    mock_response.read = AsyncMock()

    with patch("aiohttp.ClientSession.get", return_value=mock_response), \
         patch("maxminddb.open_database"), \
         patch("builtins.open", Mock()), \
         patch("os.makedirs"):
        await db.initialize()

        db.reader = Mock()
        db.reader.get.return_value = {"country": "US"}
        assert db.get_country("1.1.1.1") == "US"


def test_ipinfo_missing_token():
    with pytest.raises(ValueError):
        IPInfoManager(token="")


async def test_ipinfo_download_failure():
    db = IPInfoManager(token="test")
    with patch("aiohttp.ClientSession.get", side_effect=Exception("Download failed")), \
         patch.object(IPInfoManager, "_is_db_outdated", return_value=True):
        await db.initialize()
        assert db.reader is None
        assert not db.db_path.exists()


@pytest.mark.asyncio
async def test_db_initialization_retry():
    db = IPInfoManager(token="test")
    with patch("aiohttp.ClientSession.get", side_effect=Exception("First fail")), \
         patch("asyncio.sleep") as mock_sleep, \
         patch("builtins.open", Mock()):
        await db.initialize()
        assert mock_sleep.call_count == 2
        assert db.reader is None
