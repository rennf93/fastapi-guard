from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request

from guard.core.checks.implementations.ip_security import IpSecurityCheck
from guard.decorators.base import RouteConfig
from guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config."""
    config = SecurityConfig()
    config.passive_mode = False
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
    """Create mock middleware."""
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_middleware_event = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.geo_ip_handler = Mock()
    return middleware


@pytest.fixture
def ip_security_check(mock_middleware: Mock) -> IpSecurityCheck:
    """Create IpSecurityCheck instance."""
    return IpSecurityCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock(spec=Request)
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = None
    return request


class TestIpSecurityEdgeCases:
    """Test IpSecurityCheck edge cases."""

    @pytest.mark.asyncio
    async def test_check_banned_ip_bypass(
        self, ip_security_check: IpSecurityCheck, mock_request: Mock
    ) -> None:
        """Test _check_banned_ip when ip_ban check is bypassed."""
        # return None when should_bypass_check returns True
        route_config = RouteConfig()
        # Replace route_resolver with new mock
        ip_security_check.middleware.route_resolver = Mock()
        ip_security_check.middleware.route_resolver.should_bypass_check = Mock(
            return_value=True
        )

        result = await ip_security_check._check_banned_ip(
            mock_request, "1.2.3.4", route_config
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_check_banned_ip_passive_mode(
        self,
        ip_security_check: IpSecurityCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_banned_ip in passive mode returns None."""
        # return None in passive mode
        security_config.passive_mode = True

        with patch(
            "guard.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban_mgr:
            mock_ban_mgr.is_ip_banned = AsyncMock(return_value=True)

            with patch(
                "guard.core.checks.implementations.ip_security.log_activity"
            ) as mock_log:
                mock_log.return_value = AsyncMock()

                result = await ip_security_check._check_banned_ip(
                    mock_request, "1.2.3.4", None
                )
                assert result is None

    @pytest.mark.asyncio
    async def test_check_route_ip_restrictions_passive_mode(
        self,
        ip_security_check: IpSecurityCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_route_ip_restrictions in passive mode returns None."""
        # return None in passive mode
        security_config.passive_mode = True
        route_config = RouteConfig()

        with patch(
            "guard.core.checks.implementations.ip_security.check_route_ip_access"
        ) as mock_check:
            # Return False to trigger IP not allowed path
            mock_check.return_value = False

            with patch(
                "guard.core.checks.implementations.ip_security.log_activity"
            ) as mock_log:
                mock_log.return_value = None

                result = await ip_security_check._check_route_ip_restrictions(
                    mock_request, "1.2.3.4", route_config
                )
                assert result is None

    @pytest.mark.asyncio
    async def test_check_no_client_ip(
        self, ip_security_check: IpSecurityCheck, mock_request: Mock
    ) -> None:
        """Test check when client_ip is None."""
        # return None when client_ip is None
        mock_request.state.client_ip = None

        result = await ip_security_check.check(mock_request)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_global_ip_restrictions_passive_mode(
        self,
        ip_security_check: IpSecurityCheck,
        mock_request: Mock,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_global_ip_restrictions in passive mode."""
        # return None in passive mode
        security_config.passive_mode = True

        with patch(
            "guard.core.checks.implementations.ip_security.is_ip_allowed"
        ) as mock_allowed:
            mock_allowed.return_value = AsyncMock(return_value=False)

            with patch(
                "guard.core.checks.implementations.ip_security.log_activity"
            ) as mock_log:
                mock_log.return_value = AsyncMock()

                result = await ip_security_check._check_global_ip_restrictions(
                    mock_request, "1.2.3.4"
                )
                assert result is None

    @pytest.mark.asyncio
    async def test_check_with_bypass_ip_check(
        self, ip_security_check: IpSecurityCheck, mock_request: Mock
    ) -> None:
        """Test check when ip check is bypassed."""
        # Setup to bypass IP ban check first
        with patch(
            "guard.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban_mgr:
            mock_ban_mgr.is_ip_banned = AsyncMock(return_value=False)

            # Now bypass the main IP check - recreate the mock properly
            mock_bypass = Mock(side_effect=lambda check, config: check == "ip")
            # Replace route_resolver with new mock
            ip_security_check.middleware.route_resolver = Mock()
            ip_security_check.middleware.route_resolver.should_bypass_check = (
                mock_bypass
            )

            result = await ip_security_check.check(mock_request)
            assert result is None

    @pytest.mark.asyncio
    async def test_full_flow_with_route_config(
        self, ip_security_check: IpSecurityCheck, mock_request: Mock
    ) -> None:
        """Test full flow with route config."""
        route_config = RouteConfig()
        mock_request.state.route_config = route_config

        with patch(
            "guard.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban_mgr:
            mock_ban_mgr.is_ip_banned = AsyncMock(return_value=False)

            with patch(
                "guard.core.checks.implementations.ip_security.check_route_ip_access"
            ) as mock_check:
                mock_check.return_value = AsyncMock(return_value=True)

                result = await ip_security_check.check(mock_request)
                assert result is None
