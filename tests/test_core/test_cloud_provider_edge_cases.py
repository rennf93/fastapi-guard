from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request

from guard.core.checks.implementations.cloud_provider import CloudProviderCheck
from guard.decorators.base import RouteConfig
from guard.models import SecurityConfig


@pytest.fixture
def mock_middleware() -> Mock:
    """Create mock middleware."""
    config = SecurityConfig()
    config.block_cloud_providers = {"aws", "gcp"}
    config.passive_mode = False

    middleware = Mock()
    middleware.config = config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_cloud_detection_events = AsyncMock()
    middleware.create_error_response = AsyncMock(return_value=Mock(status_code=403))
    middleware.route_resolver = Mock()
    middleware.route_resolver.should_bypass_check = Mock(return_value=False)
    middleware.route_resolver.get_cloud_providers_to_check = Mock(
        return_value=["aws", "gcp"]
    )
    return middleware


@pytest.fixture
def cloud_check(mock_middleware: Mock) -> CloudProviderCheck:
    """Create CloudProviderCheck instance."""
    return CloudProviderCheck(mock_middleware)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock(spec=Request)
    request.state = Mock()
    request.state.client_ip = "1.2.3.4"
    request.state.route_config = None
    return request


class TestCloudProviderEdgeCases:
    """Test CloudProviderCheck edge cases."""

    @pytest.mark.asyncio
    async def test_check_no_client_ip(
        self, cloud_check: CloudProviderCheck, mock_request: Mock
    ) -> None:
        """Test check returns None when client_ip is None."""
        # return None when client_ip is None
        mock_request.state.client_ip = None

        result = await cloud_check.check(mock_request)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_bypass_clouds_check(
        self, cloud_check: CloudProviderCheck, mock_request: Mock
    ) -> None:
        """Test check returns None when clouds check is bypassed."""
        # return None when should_bypass_check returns True
        route_config = RouteConfig()
        mock_request.state.route_config = route_config
        # Replace route_resolver with new mock
        cloud_check.middleware.route_resolver = Mock()
        cloud_check.middleware.route_resolver.should_bypass_check = Mock(
            return_value=True
        )
        cloud_check.middleware.route_resolver.get_cloud_providers_to_check = Mock(
            return_value=["aws", "gcp"]
        )

        result = await cloud_check.check(mock_request)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_passive_mode(
        self,
        cloud_check: CloudProviderCheck,
        mock_request: Mock,
    ) -> None:
        """Test check returns None in passive mode."""
        # return None in passive mode
        cloud_check.config.passive_mode = True

        with patch(
            "guard.core.checks.implementations.cloud_provider.cloud_handler"
        ) as mock_cloud_handler:
            mock_cloud_handler.is_cloud_ip.return_value = True

            with patch(
                "guard.core.checks.implementations.cloud_provider.log_activity"
            ) as mock_log:
                mock_log.return_value = AsyncMock()

                result = await cloud_check.check(mock_request)
                assert result is None

    @pytest.mark.asyncio
    async def test_check_no_cloud_providers_to_check(
        self, cloud_check: CloudProviderCheck, mock_request: Mock
    ) -> None:
        """Test check returns None when no cloud providers to check."""
        # Should return None when get_cloud_providers_to_check returns None
        # Replace route_resolver with new mock
        cloud_check.middleware.route_resolver = Mock()
        cloud_check.middleware.route_resolver.should_bypass_check = Mock(
            return_value=False
        )
        cloud_check.middleware.route_resolver.get_cloud_providers_to_check = Mock(
            return_value=None
        )

        result = await cloud_check.check(mock_request)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_not_cloud_ip(
        self, cloud_check: CloudProviderCheck, mock_request: Mock
    ) -> None:
        """Test check returns None when IP is not from blocked cloud provider."""
        with patch(
            "guard.core.checks.implementations.cloud_provider.cloud_handler"
        ) as mock_cloud_handler:
            mock_cloud_handler.is_cloud_ip.return_value = False

            result = await cloud_check.check(mock_request)
            assert result is None

    @pytest.mark.asyncio
    async def test_check_cloud_ip_active_mode(
        self,
        cloud_check: CloudProviderCheck,
        mock_request: Mock,
    ) -> None:
        """Test check returns error response in active mode for cloud IP."""
        cloud_check.config.passive_mode = False

        with patch(
            "guard.core.checks.implementations.cloud_provider.cloud_handler"
        ) as mock_cloud_handler:
            mock_cloud_handler.is_cloud_ip.return_value = True

            with patch(
                "guard.core.checks.implementations.cloud_provider.log_activity"
            ) as mock_log:
                mock_log.return_value = AsyncMock()

                result = await cloud_check.check(mock_request)
                assert result is not None
                assert result.status_code == 403
