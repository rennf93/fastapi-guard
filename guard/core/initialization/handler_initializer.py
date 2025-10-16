from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from guard.models import SecurityConfig


class HandlerInitializer:
    """Centralized handler initialization for middleware."""

    def __init__(
        self,
        config: "SecurityConfig",
        redis_handler: Any = None,
        agent_handler: Any = None,
        geo_ip_handler: Any = None,
        rate_limit_handler: Any = None,
        guard_decorator: Any = None,
    ):
        """
        Initialize the HandlerInitializer.

        Args:
            config: Security configuration
            redis_handler: Optional Redis handler instance
            agent_handler: Optional agent handler instance
            geo_ip_handler: Optional GeoIP handler instance
            rate_limit_handler: Optional rate limit handler instance
            guard_decorator: Optional guard decorator instance
        """
        self.config = config
        self.redis_handler = redis_handler
        self.agent_handler = agent_handler
        self.geo_ip_handler = geo_ip_handler
        self.rate_limit_handler = rate_limit_handler
        self.guard_decorator = guard_decorator

    async def initialize_redis_handlers(self) -> None:
        """Initialize Redis for all handlers that support it."""
        if not (self.config.enable_redis and self.redis_handler):
            return

        await self.redis_handler.initialize()

        # Import handlers
        from guard.handlers.cloud_handler import cloud_handler
        from guard.handlers.ipban_handler import ip_ban_manager
        from guard.handlers.suspatterns_handler import sus_patterns_handler

        # Initialize cloud handler with Redis if cloud providers are blocked
        if self.config.block_cloud_providers:
            await cloud_handler.initialize_redis(
                self.redis_handler, self.config.block_cloud_providers
            )

        # Initialize core handlers
        await ip_ban_manager.initialize_redis(self.redis_handler)
        if self.geo_ip_handler is not None:
            await self.geo_ip_handler.initialize_redis(self.redis_handler)
        if self.rate_limit_handler is not None:
            await self.rate_limit_handler.initialize_redis(self.redis_handler)
        await sus_patterns_handler.initialize_redis(self.redis_handler)

    async def initialize_agent_for_handlers(self) -> None:
        """Initialize agent in all handlers that support it."""
        if not self.agent_handler:
            return

        # Import handlers
        from guard.handlers.cloud_handler import cloud_handler
        from guard.handlers.ipban_handler import ip_ban_manager
        from guard.handlers.suspatterns_handler import sus_patterns_handler

        # Initialize core handlers
        await ip_ban_manager.initialize_agent(self.agent_handler)
        if self.rate_limit_handler is not None:
            await self.rate_limit_handler.initialize_agent(self.agent_handler)
        await sus_patterns_handler.initialize_agent(self.agent_handler)

        # Initialize cloud handler if enabled
        if self.config.block_cloud_providers:
            await cloud_handler.initialize_agent(self.agent_handler)

        # Initialize geo IP handler if it has agent support
        if self.geo_ip_handler and hasattr(self.geo_ip_handler, "initialize_agent"):
            await self.geo_ip_handler.initialize_agent(self.agent_handler)

    async def initialize_dynamic_rule_manager(self) -> None:
        """Initialize dynamic rule manager if enabled."""
        if not (self.agent_handler and self.config.enable_dynamic_rules):
            return

        from guard.handlers.dynamic_rule_handler import DynamicRuleManager

        dynamic_rule_manager = DynamicRuleManager(self.config)
        await dynamic_rule_manager.initialize_agent(self.agent_handler)

        if self.redis_handler:
            await dynamic_rule_manager.initialize_redis(self.redis_handler)

    async def initialize_agent_integrations(self) -> None:
        """Initialize agent and its integrations with Redis and decorators."""
        if not self.agent_handler:
            return

        await self.agent_handler.start()

        # Connect agent to Redis if available
        if self.redis_handler:
            await self.agent_handler.initialize_redis(self.redis_handler)
            await self.redis_handler.initialize_agent(self.agent_handler)

        # Initialize agent in all handlers
        await self.initialize_agent_for_handlers()

        # Initialize agent in decorator handler if it exists
        if self.guard_decorator and hasattr(self.guard_decorator, "initialize_agent"):
            await self.guard_decorator.initialize_agent(self.agent_handler)

        # Initialize dynamic rule manager if enabled
        await self.initialize_dynamic_rule_manager()
