from unittest.mock import AsyncMock, Mock, patch

import pytest

from guard.core.initialization.handler_initializer import HandlerInitializer
from guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create a security config."""
    config = SecurityConfig()
    config.enable_redis = True
    config.enable_agent = True
    config.enable_dynamic_rules = False
    config.block_cloud_providers = set()
    return config


@pytest.fixture
def mock_redis_handler() -> Mock:
    """Create mock Redis handler."""
    handler = Mock()
    handler.initialize = AsyncMock()
    handler.initialize_agent = AsyncMock()
    return handler


@pytest.fixture
def mock_agent_handler() -> Mock:
    """Create mock agent handler."""
    handler = Mock()
    handler.start = AsyncMock()
    handler.initialize_redis = AsyncMock()
    return handler


@pytest.fixture
def mock_geo_ip_handler() -> Mock:
    """Create mock GeoIP handler."""
    handler = Mock()
    handler.initialize_redis = AsyncMock()
    handler.initialize_agent = AsyncMock()
    return handler


@pytest.fixture
def mock_rate_limit_handler() -> Mock:
    """Create mock rate limit handler."""
    handler = Mock()
    handler.initialize_redis = AsyncMock()
    handler.initialize_agent = AsyncMock()
    return handler


@pytest.fixture
def mock_guard_decorator() -> Mock:
    """Create mock guard decorator."""
    decorator = Mock()
    decorator.initialize_agent = AsyncMock()
    return decorator


@pytest.fixture
def initializer(
    security_config: SecurityConfig,
    mock_redis_handler: Mock,
    mock_agent_handler: Mock,
    mock_geo_ip_handler: Mock,
    mock_rate_limit_handler: Mock,
    mock_guard_decorator: Mock,
) -> HandlerInitializer:
    """Create HandlerInitializer instance."""
    return HandlerInitializer(
        config=security_config,
        redis_handler=mock_redis_handler,
        agent_handler=mock_agent_handler,
        geo_ip_handler=mock_geo_ip_handler,
        rate_limit_handler=mock_rate_limit_handler,
        guard_decorator=mock_guard_decorator,
    )


class TestHandlerInitializer:
    """Test HandlerInitializer class."""

    def test_init(
        self,
        initializer: HandlerInitializer,
        security_config: SecurityConfig,
        mock_redis_handler: Mock,
    ) -> None:
        """Test initializer initialization."""
        assert initializer.config == security_config
        assert initializer.redis_handler == mock_redis_handler

    @pytest.mark.asyncio
    async def test_initialize_redis_handlers_disabled(
        self, security_config: SecurityConfig
    ) -> None:
        """Test Redis initialization when disabled."""
        security_config.enable_redis = False
        initializer = HandlerInitializer(config=security_config)

        # Should return early
        await initializer.initialize_redis_handlers()

    @pytest.mark.asyncio
    async def test_initialize_redis_handlers_no_handler(
        self, security_config: SecurityConfig
    ) -> None:
        """Test Redis initialization when no handler provided."""
        initializer = HandlerInitializer(config=security_config, redis_handler=None)

        # Should return early
        await initializer.initialize_redis_handlers()

    @pytest.mark.asyncio
    async def test_initialize_redis_handlers_basic(
        self,
        initializer: HandlerInitializer,
        mock_redis_handler: Mock,
        mock_geo_ip_handler: Mock,
        mock_rate_limit_handler: Mock,
    ) -> None:
        """Test basic Redis handler initialization."""
        with (
            patch("guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
            patch(
                "guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_redis = AsyncMock()
            mock_ipban.initialize_redis = AsyncMock()
            mock_sus.initialize_redis = AsyncMock()

            await initializer.initialize_redis_handlers()

            # Verify Redis was initialized
            mock_redis_handler.initialize.assert_called_once()

            # Verify core handlers were initialized
            mock_ipban.initialize_redis.assert_called_once_with(mock_redis_handler)
            mock_geo_ip_handler.initialize_redis.assert_called_once_with(
                mock_redis_handler
            )
            mock_rate_limit_handler.initialize_redis.assert_called_once_with(
                mock_redis_handler
            )
            mock_sus.initialize_redis.assert_called_once_with(mock_redis_handler)

    @pytest.mark.asyncio
    async def test_initialize_redis_handlers_with_cloud(
        self,
        initializer: HandlerInitializer,
        security_config: SecurityConfig,
        mock_redis_handler: Mock,
    ) -> None:
        """Test Redis initialization with cloud providers blocked."""
        security_config.block_cloud_providers = {"aws", "gcp"}

        with (
            patch("guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
            patch(
                "guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_redis = AsyncMock()
            mock_ipban.initialize_redis = AsyncMock()
            mock_sus.initialize_redis = AsyncMock()

            await initializer.initialize_redis_handlers()

            # Verify cloud handler was initialized with Redis
            mock_cloud.initialize_redis.assert_called_once_with(
                mock_redis_handler, security_config.block_cloud_providers
            )

    @pytest.mark.asyncio
    async def test_initialize_redis_handlers_no_optional_handlers(
        self, security_config: SecurityConfig, mock_redis_handler: Mock
    ) -> None:
        """Test Redis initialization without optional handlers."""
        initializer = HandlerInitializer(
            config=security_config,
            redis_handler=mock_redis_handler,
            geo_ip_handler=None,
            rate_limit_handler=None,
        )

        with (
            patch("guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
            patch(
                "guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_redis = AsyncMock()
            mock_ipban.initialize_redis = AsyncMock()
            mock_sus.initialize_redis = AsyncMock()

            await initializer.initialize_redis_handlers()

            # Should not crash without optional handlers
            mock_redis_handler.initialize.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_agent_for_handlers_no_agent(
        self, security_config: SecurityConfig
    ) -> None:
        """Test agent initialization when no agent provided."""
        initializer = HandlerInitializer(config=security_config, agent_handler=None)

        # Should return early
        await initializer.initialize_agent_for_handlers()

    @pytest.mark.asyncio
    async def test_initialize_agent_for_handlers_basic(
        self,
        initializer: HandlerInitializer,
        mock_agent_handler: Mock,
        mock_rate_limit_handler: Mock,
    ) -> None:
        """Test basic agent handler initialization."""
        with (
            patch("guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
            patch(
                "guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_agent = AsyncMock()
            mock_ipban.initialize_agent = AsyncMock()
            mock_sus.initialize_agent = AsyncMock()

            await initializer.initialize_agent_for_handlers()

            # Verify core handlers were initialized
            mock_ipban.initialize_agent.assert_called_once_with(mock_agent_handler)
            mock_rate_limit_handler.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )
            mock_sus.initialize_agent.assert_called_once_with(mock_agent_handler)

    @pytest.mark.asyncio
    async def test_initialize_agent_for_handlers_with_cloud(
        self,
        initializer: HandlerInitializer,
        security_config: SecurityConfig,
        mock_agent_handler: Mock,
    ) -> None:
        """Test agent initialization with cloud providers."""
        security_config.block_cloud_providers = {"aws"}

        with (
            patch("guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
            patch(
                "guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_agent = AsyncMock()
            mock_ipban.initialize_agent = AsyncMock()
            mock_sus.initialize_agent = AsyncMock()

            await initializer.initialize_agent_for_handlers()

            # Verify cloud handler was initialized
            mock_cloud.initialize_agent.assert_called_once_with(mock_agent_handler)

    @pytest.mark.asyncio
    async def test_initialize_agent_for_handlers_with_geoip(
        self,
        initializer: HandlerInitializer,
        mock_agent_handler: Mock,
        mock_geo_ip_handler: Mock,
    ) -> None:
        """Test agent initialization with GeoIP handler."""
        with (
            patch("guard.handlers.cloud_handler.cloud_handler") as mock_cloud,
            patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ipban,
            patch(
                "guard.handlers.suspatterns_handler.sus_patterns_handler"
            ) as mock_sus,
        ):
            mock_cloud.initialize_agent = AsyncMock()
            mock_ipban.initialize_agent = AsyncMock()
            mock_sus.initialize_agent = AsyncMock()

            await initializer.initialize_agent_for_handlers()

            # Verify geo IP handler was initialized
            mock_geo_ip_handler.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )

    @pytest.mark.asyncio
    async def test_initialize_dynamic_rule_manager_disabled(
        self, security_config: SecurityConfig
    ) -> None:
        """Test dynamic rule manager when disabled."""
        initializer = HandlerInitializer(config=security_config)

        # Should return early (no agent or disabled)
        await initializer.initialize_dynamic_rule_manager()

    @pytest.mark.asyncio
    async def test_initialize_dynamic_rule_manager_no_agent(
        self, security_config: SecurityConfig
    ) -> None:
        """Test dynamic rule manager when no agent."""
        security_config.enable_dynamic_rules = True
        initializer = HandlerInitializer(config=security_config, agent_handler=None)

        # Should return early
        await initializer.initialize_dynamic_rule_manager()

    @pytest.mark.asyncio
    async def test_initialize_dynamic_rule_manager_enabled(
        self,
        initializer: HandlerInitializer,
        security_config: SecurityConfig,
        mock_agent_handler: Mock,
        mock_redis_handler: Mock,
    ) -> None:
        """Test dynamic rule manager initialization."""
        security_config.enable_dynamic_rules = True

        with patch("guard.handlers.dynamic_rule_handler.DynamicRuleManager") as MockDRM:
            mock_drm_instance = Mock()
            mock_drm_instance.initialize_agent = AsyncMock()
            mock_drm_instance.initialize_redis = AsyncMock()
            MockDRM.return_value = mock_drm_instance

            await initializer.initialize_dynamic_rule_manager()

            # Verify DRM was created and initialized
            MockDRM.assert_called_once_with(security_config)
            mock_drm_instance.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )
            mock_drm_instance.initialize_redis.assert_called_once_with(
                mock_redis_handler
            )

    @pytest.mark.asyncio
    async def test_initialize_dynamic_rule_manager_no_redis(
        self, security_config: SecurityConfig, mock_agent_handler: Mock
    ) -> None:
        """Test dynamic rule manager without Redis."""
        security_config.enable_dynamic_rules = True
        initializer = HandlerInitializer(
            config=security_config,
            agent_handler=mock_agent_handler,
            redis_handler=None,
        )

        with patch("guard.handlers.dynamic_rule_handler.DynamicRuleManager") as MockDRM:
            mock_drm_instance = Mock()
            mock_drm_instance.initialize_agent = AsyncMock()
            mock_drm_instance.initialize_redis = AsyncMock()
            MockDRM.return_value = mock_drm_instance

            await initializer.initialize_dynamic_rule_manager()

            # Redis initialization should not be called
            mock_drm_instance.initialize_redis.assert_not_called()

    @pytest.mark.asyncio
    async def test_initialize_agent_integrations_no_agent(
        self, security_config: SecurityConfig
    ) -> None:
        """Test agent integrations when no agent."""
        initializer = HandlerInitializer(config=security_config, agent_handler=None)

        # Should return early
        await initializer.initialize_agent_integrations()

    @pytest.mark.asyncio
    async def test_initialize_agent_integrations_full(
        self,
        initializer: HandlerInitializer,
        mock_agent_handler: Mock,
        mock_redis_handler: Mock,
        mock_guard_decorator: Mock,
    ) -> None:
        """Test full agent integrations initialization."""
        mock_init_handlers = AsyncMock()
        mock_init_drm = AsyncMock()
        with (
            patch.object(
                initializer, "initialize_agent_for_handlers", mock_init_handlers
            ),
            patch.object(initializer, "initialize_dynamic_rule_manager", mock_init_drm),
        ):
            await initializer.initialize_agent_integrations()

            # Verify agent was started
            mock_agent_handler.start.assert_called_once()

            # Verify Redis integration
            mock_agent_handler.initialize_redis.assert_called_once_with(
                mock_redis_handler
            )
            mock_redis_handler.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )

            # Verify handlers were initialized
            mock_init_handlers.assert_called_once()

            # Verify decorator was initialized
            mock_guard_decorator.initialize_agent.assert_called_once_with(
                mock_agent_handler
            )

            # Verify dynamic rules were initialized
            mock_init_drm.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_agent_integrations_no_redis(
        self, security_config: SecurityConfig, mock_agent_handler: Mock
    ) -> None:
        """Test agent integrations without Redis."""
        initializer = HandlerInitializer(
            config=security_config,
            agent_handler=mock_agent_handler,
            redis_handler=None,
        )

        with (
            patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
            patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
        ):
            await initializer.initialize_agent_integrations()

            # Redis integration should not be called
            mock_agent_handler.initialize_redis.assert_not_called()

    @pytest.mark.asyncio
    async def test_initialize_agent_integrations_no_decorator(
        self, security_config: SecurityConfig, mock_agent_handler: Mock
    ) -> None:
        """Test agent integrations without decorator."""
        initializer = HandlerInitializer(
            config=security_config,
            agent_handler=mock_agent_handler,
            guard_decorator=None,
        )

        with (
            patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
            patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
        ):
            await initializer.initialize_agent_integrations()

            # Should not crash without decorator
            mock_agent_handler.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_agent_integrations_decorator_no_method(
        self, security_config: SecurityConfig, mock_agent_handler: Mock
    ) -> None:
        """Test agent integrations with decorator lacking initialize_agent."""
        decorator_no_method = Mock(spec=[])  # No initialize_agent method
        initializer = HandlerInitializer(
            config=security_config,
            agent_handler=mock_agent_handler,
            guard_decorator=decorator_no_method,
        )

        with (
            patch.object(initializer, "initialize_agent_for_handlers", AsyncMock()),
            patch.object(initializer, "initialize_dynamic_rule_manager", AsyncMock()),
        ):
            await initializer.initialize_agent_integrations()

            # Should not crash when decorator lacks method
            mock_agent_handler.start.assert_called_once()
