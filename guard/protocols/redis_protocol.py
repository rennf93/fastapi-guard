from typing import Any, Protocol, runtime_checkable

from redis.asyncio import Redis
from typing_extensions import AsyncContextManager


@runtime_checkable
class RedisHandlerProtocol(Protocol):
    """Protocol for Redis handlers."""

    async def get_key(self, namespace: str, key: str) -> Any: ...
    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None: ...
    def get_connection(self) -> AsyncContextManager[Redis]: ...

    async def initialize(self) -> None: ...
