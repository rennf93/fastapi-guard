from guard.handlers.ipinfo_handler import IPInfoManager
import maxminddb
import pytest
import time
from unittest.mock import AsyncMock, patch, Mock



@pytest.mark.asyncio
async def test_ipinfo_db(tmp_path):
    """Test IPInfoManager functionality."""
    db = IPInfoManager(token="test_token", db_path=tmp_path/"test.mmdb")

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


async def test_ipinfo_download_failure(tmp_path):
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")
    with patch("aiohttp.ClientSession.get", side_effect=Exception("Download failed")), \
         patch.object(IPInfoManager, "_is_db_outdated", return_value=True):
        await db.initialize()
        assert db.reader is None
        assert not db.db_path.exists()


@pytest.mark.asyncio
async def test_db_initialization_retry(tmp_path):
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")
    with patch("aiohttp.ClientSession.get", side_effect=Exception("First fail")), \
         patch("asyncio.sleep") as mock_sleep, \
         patch("builtins.open", Mock()):
        await db.initialize()
        assert mock_sleep.call_count == 2
        assert db.reader is None


@pytest.mark.asyncio
async def test_database_retry_success(tmp_path):
    """Test successful download after retry"""
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")
    mock_response = Mock()
    mock_response.raise_for_status = AsyncMock()
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock()
    mock_response.read = AsyncMock(return_value=b"test data")

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


def test_db_age_check(tmp_path):
    """Test database age detection"""
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")

    with patch("pathlib.Path.stat") as mock_stat:
        mock_stat.return_value.st_mtime = time.time() - 86401
        assert db._is_db_outdated() is True

        mock_stat.return_value.st_mtime = time.time() - 100
        assert db._is_db_outdated() is False


@pytest.mark.asyncio
async def test_get_country_exception_handling(tmp_path):
    """Test exception handling in get_country"""
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")
    db.reader = Mock()
    db.reader.get.side_effect = Exception("DB error")

    assert db.get_country("1.1.1.1") is None


def test_db_age_check_missing_db(tmp_path):
    """Test database age detection when file is missing"""
    db = IPInfoManager(token="test", db_path=tmp_path/"missing.mmdb")
    with patch("pathlib.Path.exists", return_value=False):
        assert db._is_db_outdated() is True


@pytest.mark.asyncio
async def test_real_database_initialization(ipinfo_db_path):
    """Integration test with real database initialization"""
    ipinfo_db_path.parent.mkdir(parents=True, exist_ok=True)
    with open(ipinfo_db_path, 'wb') as f:
        f.write(b'dummy data')

    db = IPInfoManager(token="test_token", db_path=ipinfo_db_path)

    with patch("maxminddb.open_database") as mock_open_db:
        mock_reader = Mock()
        mock_open_db.return_value = mock_reader
        mock_reader.get.return_value = {"country": "US"}

        await db.initialize()
        assert db.reader is not None
        assert db.db_path.exists()

        country = db.get_country("8.8.8.8")
        assert country == "US"
        db.close()


@pytest.mark.asyncio
async def test_invalid_token_handling(tmp_path):
    """Test real API error handling with invalid token"""
    db = IPInfoManager(token="invalid_token", db_path=tmp_path/"test.mmdb")

    with pytest.raises(Exception) as exc_info:
        await db._download_database()

    assert "401" in str(exc_info.value)


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
async def test_get_country_without_init(tmp_path):
    """Test get_country when reader is not initialized"""
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")
    with pytest.raises(RuntimeError, match="Database not initialized"):
        db.get_country("1.1.1.1")


@pytest.mark.asyncio
async def test_corrupted_db_removal(tmp_path):
    """Test corrupted database removal on download failure"""
    test_db_path = tmp_path / "country_asn.mmdb"
    db = IPInfoManager(token="test", db_path=test_db_path)
    db.db_path.touch()

    with patch("aiohttp.ClientSession.get", side_effect=Exception("Download failed")), \
         patch.object(IPInfoManager, "_is_db_outdated", return_value=True):
        await db.initialize()
        assert not db.db_path.exists()


@pytest.mark.asyncio
async def test_download_exhausts_retries(tmp_path):
    """Test that download raises after exhausting retries"""
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")

    with patch("aiohttp.ClientSession.get", side_effect=Exception("Download failed")), \
         patch("asyncio.sleep"):
        with pytest.raises(Exception, match="Download failed"):
            await db._download_database()


@pytest.mark.asyncio
async def test_close_with_reader(tmp_path):
    """Test close method when reader exists"""
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")
    mock_reader = Mock()
    db.reader = mock_reader

    db.close()
    mock_reader.close.assert_called_once()


@pytest.mark.asyncio
async def test_redis_cache_hit(tmp_path):
    """Test database initialization from Redis cache"""
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")
    db.redis_handler = AsyncMock()
    db.redis_handler.get_key.return_value = b"mock_db_data"  # Raw bytes

    mock_reader = Mock()
    mock_reader.get.return_value = {"country": "US"}

    with patch("maxminddb.open_database", return_value=mock_reader) as mock_open:
        await db.initialize()

        # Verify Redis cache check
        db.redis_handler.get_key.assert_awaited_once_with("ipinfo", "database")

        # Verify file write with proper bytes handling
        with open(db.db_path, 'rb') as f:
            assert f.read() == b"mock_db_data"

        # Verify database initialization
        mock_open.assert_called_once_with(str(db.db_path))
        assert db.reader is mock_reader


@pytest.mark.asyncio
async def test_redis_cache_update(tmp_path):
    """Test database storage in Redis after download"""
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")
    db.redis_handler = AsyncMock()

    mock_response = AsyncMock()
    mock_response.__aenter__.return_value = mock_response
    mock_response.read.return_value = b"new_db_data"

    with patch("aiohttp.ClientSession.get", return_value=mock_response), \
         patch("maxminddb.open_database"):
        await db._download_database()

        # Verify Redis storage with raw bytes
        db.redis_handler.set_key.assert_awaited_once_with(
            "ipinfo",
            "database",
            b"new_db_data".decode('latin-1'),
            ttl=86400
        )


@pytest.mark.asyncio
async def test_redis_initialization_flow(tmp_path):
    """Test Redis handler initialization pattern"""
    db = IPInfoManager(token="test", db_path=tmp_path/"test.mmdb")
    mock_redis = AsyncMock()

    # Verify initialization sequence
    with patch.object(db, 'initialize', new_callable=AsyncMock) as mock_init:
        await db.initialize_redis(mock_redis)

        assert db.redis_handler is mock_redis
        mock_init.assert_awaited_once()
