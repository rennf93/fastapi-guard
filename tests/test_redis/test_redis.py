import pytest
from fastapi import FastAPI, status, HTTPException
from guard.handlers.redis_handler import RedisManager
from guard.models import SecurityConfig
from redis.exceptions import ConnectionError
from httpx import AsyncClient
from httpx._transports.asgi import ASGITransport
import asyncio


@pytest.mark.asyncio
async def test_redis_basic_operations(security_config_redis):
    """Test basic Redis operations"""
    app = FastAPI()
    handler = RedisManager(security_config_redis)
    await handler.initialize()

    @app.get("/")
    async def read_root():
        # Test set and get
        await handler.set_key("test", "key1", "value1")
        value = await handler.get_key("test", "key1")
        assert value == "value1"

        # Test exists
        exists = await handler.exists("test", "key1")
        assert exists is True

        # Test delete
        await handler.delete("test", "key1")
        exists = await handler.exists("test", "key1")
        assert exists is False

        return {"message": "success"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

    await handler.close()


@pytest.mark.asyncio
async def test_redis_disabled(security_config):
    """Test Redis operations when disabled"""
    app = FastAPI()
    handler = RedisManager(security_config)
    await handler.initialize()

    @app.get("/")
    async def read_root():
        assert not security_config.enable_redis
        assert handler._redis is None
        result = await handler.set_key("test", "key1", "value1")
        assert result is None
        value = await handler.get_key("test", "key1")
        assert value is None
        return {"message": "success"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_redis_error_handling(security_config_redis):
    """Test Redis error handling"""
    app = FastAPI()
    handler = RedisManager(security_config_redis)
    await handler.initialize()

    @app.get("/")
    async def read_root():
        async def _fail_operation(conn):
            raise ConnectionError("Test connection error")

        with pytest.raises(HTTPException) as exc_info:
            await handler.safe_operation(_fail_operation)
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"message": "success"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

    await handler.close()


@pytest.mark.asyncio
async def test_redis_connection_retry(security_config_redis, mocker):
    """Test Redis connection retry mechanism"""
    app = FastAPI()
    handler = RedisManager(security_config_redis)
    await handler.initialize()

    async def mock_get(*args, **kwargs):
        raise ConnectionError("Test connection error")

    handler._redis.get = mock_get

    @app.get("/")
    async def read_root():
        with pytest.raises(HTTPException) as exc_info:
            await handler.get_key("test", "retry")
        assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        return {"message": "success"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_redis_ttl_operations(security_config_redis):
    """Test Redis TTL operations"""
    app = FastAPI()
    handler = RedisManager(security_config_redis)
    await handler.initialize()

    @app.get("/")
    async def read_root():
        # Test set with TTL
        await handler.set_key("test", "ttl_key", "value", ttl=1)
        value = await handler.get_key("test", "ttl_key")
        assert value == "value"

        # Wait for TTL to expire
        await asyncio.sleep(1.1)
        value = await handler.get_key("test", "ttl_key")
        assert value is None
        return {"message": "success"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

    await handler.close()


@pytest.mark.asyncio
async def test_redis_increment_operations(security_config_redis):
    """Test Redis increment operations"""
    app = FastAPI()
    handler = RedisManager(security_config_redis)
    await handler.initialize()

    @app.get("/")
    async def read_root():
        # Test increment without TTL
        value = await handler.incr("test", "counter")
        assert value == 1
        value = await handler.incr("test", "counter")
        assert value == 2

        # Test increment with TTL
        value = await handler.incr("test", "ttl_counter", ttl=1)
        assert value == 1
        await asyncio.sleep(1.1)
        exists = await handler.exists("test", "ttl_counter")
        assert not exists

        return {"message": "success"}

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")
        assert response.status_code == status.HTTP_200_OK

    await handler.close()


@pytest.mark.asyncio
async def test_redis_connection_context(security_config_redis):
    """Test Redis connection context manager"""
    handler = RedisManager(security_config_redis)
    await handler.initialize()

    # Test normal connection usage
    async with handler.get_connection() as conn:
        await conn.set("test:key", "value")
        value = await conn.get("test:key")
        assert value == "value"

    # Test connection error handling
    await handler.close()
    with pytest.raises(HTTPException) as exc_info:
        async with handler.get_connection() as conn:
            await conn.get("test:key")
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    await handler.close()


@pytest.mark.asyncio
async def test_redis_connection_failures(security_config_redis):
    """Test Redis connection failure scenarios"""
    # Test initialization failure
    bad_config = SecurityConfig(
        **{**security_config_redis.model_dump(),
           "redis_url": "redis://nonexistent:6379"}
    )
    handler = RedisManager(bad_config)
    with pytest.raises(HTTPException) as exc_info:
        await handler.initialize()
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert handler._redis is None

    # Test with valid config but force connection failure
    handler = RedisManager(security_config_redis)
    await handler.initialize()

    # Test operation after connection drop
    await handler.close()
    with pytest.raises(HTTPException) as exc_info:
        await handler.get_key("test", "key")
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    # Test safe_operation with null connection
    handler._redis = None
    with pytest.raises(HTTPException) as exc_info:
        await handler.safe_operation(lambda conn: conn.get("test:key"))
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR


@pytest.mark.asyncio
async def test_redis_disabled_operations(security_config_redis):
    """Test Redis operations when Redis is disabled"""
    security_config_redis.enable_redis = False
    handler = RedisManager(security_config_redis)

    # All operations should return None when Redis is disabled
    assert await handler.get_key("test", "key") is None
    assert await handler.set_key("test", "key", "value") is None
    assert await handler.incr("test", "counter") is None
    assert await handler.exists("test", "key") is None
    assert await handler.delete("test", "key") is None


@pytest.mark.asyncio
async def test_redis_failed_initialization_operations(security_config_redis):
    """Test operations after failed initialization"""
    bad_config = SecurityConfig(
        **{**security_config_redis.model_dump(),
           "redis_url": "redis://invalid:6379"}
    )
    handler = RedisManager(bad_config)

    with pytest.raises(HTTPException) as exc_info:
        await handler.get_key("test", "key")
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR

    with pytest.raises(HTTPException) as exc_info:
        await handler.set_key("test", "key", "value")
    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
