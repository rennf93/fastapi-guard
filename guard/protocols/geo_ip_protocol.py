# guard/protocols/geo_ip_protocol.py
from typing import Protocol, runtime_checkable

from guard.protocols.agent_protocol import AgentHandlerProtocol
from guard.protocols.redis_protocol import RedisHandlerProtocol


@runtime_checkable
class GeoIPHandler(Protocol):
    """Protocol for geographical IP handler."""

    @property
    def is_initialized(self) -> bool: ...
    async def initialize(self) -> None: ...
    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...
    async def initialize_agent(self, agent_handler: AgentHandlerProtocol) -> None: ...
    def get_country(self, ip: str) -> str | None: ...
