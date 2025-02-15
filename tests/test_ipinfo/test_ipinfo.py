from guard.handlers.ipinfo_handler import IPInfoManager
import maxminddb
import pytest
import time
from unittest.mock import AsyncMock, patch, Mock



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


@pytest.mark.asyncio
async def test_database_retry_success():
    """Test successful download after retry"""
    db = IPInfoManager(token="test")
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock()
    mock_response.read = AsyncMock(return_value=b"test data")

    # Use Mock's side_effect as a callable instead of a list
    def side_effect(*args, **kwargs):
        side_effect.calls = getattr(side_effect, 'calls', 0) + 1
        if side_effect.calls == 1:
            raise Exception("First fail")
        return mock_response

    mock_file = Mock()
    mock_file_context = Mock()
    mock_file_context.__enter__ = Mock(return_value=mock_file)
    mock_file_context.__exit__ = Mock(return_value=None)
    mock_open = Mock(return_value=mock_file_context)

    with patch("aiohttp.ClientSession.get", side_effect=side_effect) as mock_get, \
         patch("builtins.open", mock_open), \
         patch("os.makedirs"), \
         patch("asyncio.sleep") as mock_sleep:

        await db._download_database()

        assert mock_get.call_count == 2
        mock_file.write.assert_called_with(b"test data")
        mock_sleep.assert_called_once_with(1)


def test_db_age_check():
    """Test database age detection"""
    db = IPInfoManager(token="test")

    with patch("pathlib.Path.stat") as mock_stat:
        # Test outdated database
        mock_stat.return_value.st_mtime = time.time() - 86401
        assert db._is_db_outdated() is True

        # Test current database
        mock_stat.return_value.st_mtime = time.time() - 100
        assert db._is_db_outdated() is False


@pytest.mark.asyncio
async def test_get_country_exception_handling():
    """Test exception handling in get_country"""
    db = IPInfoManager(token="test")
    db.reader = Mock()
    db.reader.get.side_effect = Exception("DB error")

    assert db.get_country("1.1.1.1") is None


@pytest.mark.asyncio
async def test_corrupted_db_removal():
    """Test corrupted database removal on download failure"""
    db = IPInfoManager(token="test")
    db.db_path.touch()  # Create empty file

    with patch("aiohttp.ClientSession.get", side_effect=Exception("Download failed")), \
         patch.object(IPInfoManager, "_is_db_outdated", return_value=True):
        await db.initialize()
        assert not db.db_path.exists()


def test_db_age_check_missing_db():
    """Test database age detection when file is missing"""
    db = IPInfoManager(token="test")
    with patch("pathlib.Path.exists", return_value=False):
        assert db._is_db_outdated() is True


@pytest.mark.asyncio
async def test_real_database_initialization(ipinfo_db):
    """Integration test with real database initialization"""
    assert ipinfo_db.reader is not None
    assert ipinfo_db.db_path.exists()

    # Test actual database query
    country = ipinfo_db.get_country("8.8.8.8")  # Google DNS
    assert country == "US"


@pytest.mark.asyncio
async def test_invalid_token_handling():
    """Test real API error handling with invalid token"""
    db = IPInfoManager(token="invalid_token")

    with pytest.raises(Exception) as exc_info:
        await db._download_database()

    assert "401" in str(exc_info.value)  # Unauthorized


def test_file_operations(tmp_path):
    """Test real file system operations"""
    test_path = tmp_path / "test.mmdb"
    test_path.touch()

    mock_reader = Mock()
    mock_reader.__enter__ = Mock(return_value=mock_reader)
    mock_reader.__exit__ = Mock(return_value=None)

    with patch("maxminddb.open_database", return_value=mock_reader):
        with maxminddb.open_database(str(test_path)) as reader:
            assert reader is not None


@pytest.mark.asyncio
async def test_get_country_without_init():
    """Test get_country when reader is not initialized"""
    db = IPInfoManager(token="test")
    with pytest.raises(RuntimeError, match="Database not initialized"):
        db.get_country("1.1.1.1")
