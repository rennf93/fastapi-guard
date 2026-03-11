from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request, Response

from guard.core.checks.implementations.rate_limit import RateLimitCheck
from guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config."""
    config = SecurityConfig()
    config.passive_mode = False
    config.endpoint_rate_limits = {"/api/test": (5, 60)}
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
    """Create mock middleware."""
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Response(status_code=429))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.redis_handler = None
    middleware.rate_limit_handler = Mock()
    middleware.rate_limit_handler.check_rate_limit = AsyncMock(return_value=None)
    return middleware


@pytest.fixture
def rate_limit_check(mock_middleware: Mock) -> RateLimitCheck:
    """Create RateLimitCheck instance."""
    return RateLimitCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock(spec=Request)
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.url = Mock()
    request.url.path = "/api/test"
    return request


class TestRateLimitEdgeCases:
    """Test RateLimitCheck edge cases."""

    @pytest.mark.asyncio
    async def test_apply_rate_limit_check_passive_mode(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _apply_rate_limit_check returns None in passive mode."""
        # return None in passive mode
        security_config.passive_mode = True

        with patch.object(
            rate_limit_check, "_create_rate_handler"
        ) as mock_create_handler:
            mock_handler = Mock()
            mock_handler.check_rate_limit = AsyncMock(
                return_value=Response(status_code=429)
            )
            mock_create_handler.return_value = mock_handler

            result = await rate_limit_check._apply_rate_limit_check(
                mock_request,
                "1.2.3.4",
                5,
                60,
                "test_event",
                {"reason": "test"},
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_check_global_rate_limit_passive_mode(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_global_rate_limit returns None in passive mode."""
        # return None in passive mode
        security_config.passive_mode = True

        # Mock rate limit handler to return a response (exceeded)
        mock_handler = Mock()
        mock_handler.check_rate_limit = AsyncMock(
            return_value=Response(status_code=429)
        )
        rate_limit_check.middleware.rate_limit_handler = mock_handler

        result = await rate_limit_check._check_global_rate_limit(
            mock_request, "1.2.3.4"
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_check_no_client_ip(
        self, rate_limit_check: RateLimitCheck, mock_request: Mock
    ) -> None:
        """Test check returns None when client_ip is None."""
        # return None when client_ip is None
        mock_request.state.client_ip = None

        result = await rate_limit_check.check(mock_request)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_global_rate_limit_not_exceeded(
        self, rate_limit_check: RateLimitCheck, mock_request: Mock
    ) -> None:
        """Test _check_global_rate_limit when rate limit not exceeded."""
        # Should return None when rate limit handler returns None
        mock_handler = Mock()
        mock_handler.check_rate_limit = AsyncMock(return_value=None)
        rate_limit_check.middleware.rate_limit_handler = mock_handler

        result = await rate_limit_check._check_global_rate_limit(
            mock_request, "1.2.3.4"
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_check_global_rate_limit_exceeded_active_mode(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_global_rate_limit returns response in active mode."""
        security_config.passive_mode = False

        # Mock rate limit exceeded
        response = Response(status_code=429)
        mock_handler = Mock()
        mock_handler.check_rate_limit = AsyncMock(return_value=response)
        rate_limit_check.middleware.rate_limit_handler = mock_handler

        result = await rate_limit_check._check_global_rate_limit(
            mock_request, "1.2.3.4"
        )
        assert result == response

    @pytest.mark.asyncio
    async def test_apply_rate_limit_check_active_mode_exceeded(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _apply_rate_limit_check returns response in active mode."""
        security_config.passive_mode = False

        with patch.object(
            rate_limit_check, "_create_rate_handler"
        ) as mock_create_handler:
            mock_handler = Mock()
            response = Response(status_code=429)
            mock_handler.check_rate_limit = AsyncMock(return_value=response)
            mock_create_handler.return_value = mock_handler

            result = await rate_limit_check._apply_rate_limit_check(
                mock_request,
                "1.2.3.4",
                5,
                60,
                "test_event",
                {"reason": "test"},
            )
            assert result == response

    @pytest.mark.asyncio
    async def test_apply_rate_limit_check_not_exceeded(
        self, rate_limit_check: RateLimitCheck, mock_request: Mock
    ) -> None:
        """Test _apply_rate_limit_check when rate limit not exceeded."""
        with patch.object(
            rate_limit_check, "_create_rate_handler"
        ) as mock_create_handler:
            mock_handler = Mock()
            mock_handler.check_rate_limit = AsyncMock(return_value=None)
            mock_create_handler.return_value = mock_handler

            result = await rate_limit_check._apply_rate_limit_check(
                mock_request,
                "1.2.3.4",
                5,
                60,
                "test_event",
                {"reason": "test"},
            )
            assert result is None

    @pytest.mark.asyncio
    async def test_check_geo_rate_limit_no_geo_handler(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_geo_rate_limit returns None when geo_handler is None."""
        security_config.geo_ip_handler = None
        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60)}

        result = await rate_limit_check._check_geo_rate_limit(
            mock_request, "1.2.3.4", route_config
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_check_geo_rate_limit_country_match(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_geo_rate_limit when country matches geo limits."""
        geo_handler = Mock()
        geo_handler.get_country.return_value = "US"
        security_config.geo_ip_handler = geo_handler

        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60)}

        response = Response(status_code=429)
        with patch.object(
            rate_limit_check, "_apply_rate_limit_check", new_callable=AsyncMock
        ) as mock_apply:
            mock_apply.return_value = response
            result = await rate_limit_check._check_geo_rate_limit(
                mock_request, "1.2.3.4", route_config
            )
            assert result == response
            mock_apply.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_check_geo_rate_limit_wildcard_match(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """
        Test _check_geo_rate_limit falls back to wildcard when country not in limits.
        """
        geo_handler = Mock()
        geo_handler.get_country.return_value = "FR"
        security_config.geo_ip_handler = geo_handler

        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60), "*": (5, 30)}

        response = Response(status_code=429)
        with patch.object(
            rate_limit_check, "_apply_rate_limit_check", new_callable=AsyncMock
        ) as mock_apply:
            mock_apply.return_value = response
            result = await rate_limit_check._check_geo_rate_limit(
                mock_request, "1.2.3.4", route_config
            )
            assert result == response
            # Verify wildcard limits were used
            call_args = mock_apply.call_args
            assert call_args[0][2] == 5  # rate_limit
            assert call_args[0][3] == 30  # window

    @pytest.mark.asyncio
    async def test_check_geo_rate_limit_no_match(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_geo_rate_limit returns None when no country or wildcard match."""
        geo_handler = Mock()
        geo_handler.get_country.return_value = "FR"
        security_config.geo_ip_handler = geo_handler

        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60)}

        result = await rate_limit_check._check_geo_rate_limit(
            mock_request, "1.2.3.4", route_config
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_check_geo_rate_limit_no_country(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_geo_rate_limit with wildcard when country is None."""
        geo_handler = Mock()
        geo_handler.get_country.return_value = None
        security_config.geo_ip_handler = geo_handler

        route_config = Mock()
        route_config.geo_rate_limits = {"*": (5, 30)}

        response = Response(status_code=429)
        with patch.object(
            rate_limit_check, "_apply_rate_limit_check", new_callable=AsyncMock
        ) as mock_apply:
            mock_apply.return_value = response
            result = await rate_limit_check._check_geo_rate_limit(
                mock_request, "1.2.3.4", route_config
            )
            assert result == response

    @pytest.mark.asyncio
    async def test_check_returns_geo_rate_limit_response(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test check() returns geo rate limit response at priority 3."""
        # Set up request state with route_config
        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60)}
        route_config.rate_limit = None  # No route rate limit (priority 2 passes)
        mock_request.state.route_config = route_config
        mock_request.state.is_whitelisted = False

        # No endpoint rate limit match (priority 1 passes)
        security_config.endpoint_rate_limits = {}

        geo_response = Response(status_code=429)
        with patch.object(
            rate_limit_check, "_check_geo_rate_limit", new_callable=AsyncMock
        ) as mock_geo:
            mock_geo.return_value = geo_response
            result = await rate_limit_check.check(mock_request)
            assert result == geo_response
