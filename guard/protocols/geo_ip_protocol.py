from typing import Protocol, runtime_checkable

from guard.protocols.redis_protocol import RedisHandlerProtocol


@runtime_checkable
class GeoIPHandler(Protocol):
    """Protocol for geographical IP handler."""

    @property
    def is_initialized(self) -> bool: ...
    async def initialize(self) -> None: ...
    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...
    def get_country(self, ip: str) -> str | None: ...
