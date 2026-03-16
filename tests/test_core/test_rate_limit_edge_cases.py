from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request, Response

from guard.core.checks.implementations.rate_limit import RateLimitCheck
from guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    config = SecurityConfig()
    config.passive_mode = False
    config.endpoint_rate_limits = {"/api/test": (5, 60)}
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
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
    return RateLimitCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    request = Mock(spec=Request)
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = None
    request.state.is_whitelisted = False
    request.url = Mock()
    request.url.path = "/api/test"
    return request


class TestRateLimitEdgeCases:
    @pytest.mark.asyncio
    async def test_apply_rate_limit_check_passive_mode(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        security_config.passive_mode = True

        rate_limit_check.middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=Response(status_code=429)
        )

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
        security_config.passive_mode = True

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
        mock_request.state.client_ip = None

        result = await rate_limit_check.check(mock_request)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_global_rate_limit_not_exceeded(
        self, rate_limit_check: RateLimitCheck, mock_request: Mock
    ) -> None:
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
        security_config.passive_mode = False

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
        security_config.passive_mode = False

        response = Response(status_code=429)
        rate_limit_check.middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=response
        )

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
        rate_limit_check.middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=None
        )

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
            call_kwargs = mock_apply.call_args[1]
            assert call_kwargs["endpoint_path"] == "/api/test"

    @pytest.mark.asyncio
    async def test_check_geo_rate_limit_wildcard_match(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
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
            call_args = mock_apply.call_args
            assert call_args[0][2] == 5
            assert call_args[0][3] == 30
            assert call_args[1]["endpoint_path"] == "/api/test"

    @pytest.mark.asyncio
    async def test_check_geo_rate_limit_no_match(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
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
        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60)}
        route_config.rate_limit = None
        mock_request.state.route_config = route_config
        mock_request.state.is_whitelisted = False

        security_config.endpoint_rate_limits = {}

        geo_response = Response(status_code=429)
        with patch.object(
            rate_limit_check, "_check_geo_rate_limit", new_callable=AsyncMock
        ) as mock_geo:
            mock_geo.return_value = geo_response
            result = await rate_limit_check.check(mock_request)
            assert result == geo_response

    @pytest.mark.asyncio
    async def test_apply_rate_limit_passes_endpoint_path(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
    ) -> None:
        rate_limit_check.middleware.rate_limit_handler.check_rate_limit = AsyncMock(
            return_value=None
        )

        await rate_limit_check._apply_rate_limit_check(
            mock_request,
            "1.2.3.4",
            5,
            60,
            "test_event",
            {"reason": "test"},
            endpoint_path="/api/test",
        )

        call_kwargs = (
            rate_limit_check.middleware.rate_limit_handler.check_rate_limit.call_args[1]
        )
        assert call_kwargs["endpoint_path"] == "/api/test"
        assert call_kwargs["rate_limit"] == 5
        assert call_kwargs["rate_limit_window"] == 60

    @pytest.mark.asyncio
    async def test_endpoint_rate_limit_passes_path(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        security_config.endpoint_rate_limits = {"/api/test": (5, 60)}

        with patch.object(
            rate_limit_check, "_apply_rate_limit_check", new_callable=AsyncMock
        ) as mock_apply:
            mock_apply.return_value = None
            await rate_limit_check._check_endpoint_rate_limit(
                mock_request, "1.2.3.4", "/api/test"
            )
            call_kwargs = mock_apply.call_args[1]
            assert call_kwargs["endpoint_path"] == "/api/test"

    @pytest.mark.asyncio
    async def test_route_rate_limit_passes_path(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
    ) -> None:
        route_config = Mock()
        route_config.rate_limit = 10
        route_config.rate_limit_window = 30

        with patch.object(
            rate_limit_check, "_apply_rate_limit_check", new_callable=AsyncMock
        ) as mock_apply:
            mock_apply.return_value = None
            await rate_limit_check._check_route_rate_limit(
                mock_request, "1.2.3.4", route_config
            )
            call_kwargs = mock_apply.call_args[1]
            assert call_kwargs["endpoint_path"] == "/api/test"

    @pytest.mark.asyncio
    async def test_global_rate_limit_has_no_endpoint_path(
        self,
        rate_limit_check: RateLimitCheck,
        mock_request: Mock,
    ) -> None:
        mock_handler = Mock()
        mock_handler.check_rate_limit = AsyncMock(return_value=None)
        rate_limit_check.middleware.rate_limit_handler = mock_handler

        await rate_limit_check._check_global_rate_limit(mock_request, "1.2.3.4")

        mock_handler.check_rate_limit.assert_awaited_once_with(
            mock_request, "1.2.3.4", rate_limit_check.middleware.create_error_response
        )
