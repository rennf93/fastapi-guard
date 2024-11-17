from handlers.ipinfo_handler import IPInfoDB
import pytest
from unittest.mock import patch, Mock



@pytest.mark.asyncio
async def test_ipinfo_db():
    """Test IPInfoDB functionality."""
    db = IPInfoDB(token="test_token")

    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.__aenter__ = Mock(return_value=mock_response)
    mock_response.__aexit__ = Mock()

    with patch("aiohttp.ClientSession.get", return_value=mock_response), \
         patch("maxminddb.open_database"), \
         patch("builtins.open", Mock()), \
         patch("os.makedirs"):
        await db.initialize()

        db.reader = Mock()
        db.reader.get.return_value = {"country": "US"}
        assert db.get_country("1.1.1.1") == "US"
