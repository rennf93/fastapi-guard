from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request

from guard.core.checks.implementations.authentication import AuthenticationCheck
from guard.core.checks.implementations.emergency_mode import EmergencyModeCheck
from guard.core.checks.implementations.https_enforcement import HttpsEnforcementCheck
from guard.core.checks.implementations.referrer import ReferrerCheck
from guard.core.checks.implementations.request_size_content import (
    RequestSizeContentCheck,
)
from guard.core.checks.implementations.required_headers import RequiredHeadersCheck
from guard.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from guard.decorators.base import RouteConfig
from guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config."""
    config = SecurityConfig()
    config.enforce_https = True
    config.trust_x_forwarded_proto = True
    config.trusted_proxies = ["192.168.1.0/24", "10.0.0.1"]
    return config


@pytest.fixture
def mock_middleware(security_config: SecurityConfig) -> Mock:
    """Create mock middleware."""
    middleware = Mock()
    middleware.config = security_config
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.event_bus.send_https_violation_event = AsyncMock()
    middleware.response_factory = Mock()
    middleware.response_factory.create_https_redirect = AsyncMock(
        return_value=Mock(status_code=301)
    )
    return middleware


@pytest.fixture
def https_check(mock_middleware: Mock) -> HttpsEnforcementCheck:
    """Create HttpsEnforcementCheck instance."""
    return HttpsEnforcementCheck(mock_middleware)


class TestHttpsEnforcementEdgeCases:
    """Test HttpsEnforcementCheck edge cases."""

    def test_is_trusted_proxy_cidr_match(
        self, https_check: HttpsEnforcementCheck
    ) -> None:
        """Test _is_trusted_proxy with CIDR range match."""
        # CIDR comparison returns True
        result = https_check._is_trusted_proxy("192.168.1.100")
        assert result is True

    def test_is_trusted_proxy_cidr_no_match(
        self, https_check: HttpsEnforcementCheck
    ) -> None:
        """Test _is_trusted_proxy with CIDR range no match."""
        # return False when no proxy matches
        result = https_check._is_trusted_proxy("172.16.0.1")
        assert result is False

    def test_is_trusted_proxy_single_ip_no_match(
        self, https_check: HttpsEnforcementCheck
    ) -> None:
        """Test _is_trusted_proxy with single IP that doesn't match."""
        # return False when single IP doesn't match
        result = https_check._is_trusted_proxy("10.0.0.2")
        assert result is False

    @pytest.mark.asyncio
    async def test_check_passive_mode_no_redirect(
        self, https_check: HttpsEnforcementCheck, security_config: SecurityConfig
    ) -> None:
        """Test check in passive mode returns None instead of redirect."""
        # return None in passive mode
        security_config.passive_mode = True

        request = Mock(spec=Request)
        request.url = Mock()
        request.url.scheme = "http"
        request.client = Mock()
        request.client.host = "1.2.3.4"
        request.headers = {}
        request.state = Mock()
        request.state.route_config = None

        result = await https_check.check(request)
        assert result is None

    @pytest.mark.asyncio
    async def test_check_with_cidr_trusted_proxy_https_forwarded(
        self, https_check: HttpsEnforcementCheck
    ) -> None:
        """Test check with CIDR-matched proxy forwarding HTTPS."""
        # CIDR match allows X-Forwarded-Proto
        request = Mock(spec=Request)
        request.url = Mock()
        request.url.scheme = "http"
        request.client = Mock()
        request.client.host = "192.168.1.50"  # Within CIDR range
        request.headers = {"X-Forwarded-Proto": "https"}
        request.state = Mock()
        request.state.route_config = None

        # Should pass because trusted proxy forwarded HTTPS
        result = await https_check.check(request)
        assert result is None

    @pytest.mark.parametrize(
        "connecting_ip,expected",
        [
            ("192.168.1.1", True),  # In CIDR range
            ("192.168.1.255", True),  # In CIDR range
            ("192.168.2.1", False),  # Outside CIDR range
            ("10.0.0.1", True),  # Exact single IP match
            ("10.0.0.2", False),  # Different single IP
            ("8.8.8.8", False),  # Completely different IP
        ],
    )
    def test_is_trusted_proxy_various_ips(
        self, https_check: HttpsEnforcementCheck, connecting_ip: str, expected: bool
    ) -> None:
        """Test _is_trusted_proxy with various IPs covering all branches."""
        result = https_check._is_trusted_proxy(connecting_ip)
        assert result == expected


class TestReferrerCheckPassiveModeUnit:
    """Unit tests for ReferrerCheck passive mode."""

    @pytest.mark.asyncio
    async def test_handle_missing_referrer_passive_mode_unit(self) -> None:
        """Test _handle_missing_referrer returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()

        check = ReferrerCheck(middleware)
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        request = Mock()
        request.state = Mock()

        with patch(
            "guard.core.checks.implementations.referrer.log_activity",
            return_value=AsyncMock(),
        ):
            result = await check._handle_missing_referrer(request, route_config)
            assert result is None

    @pytest.mark.asyncio
    async def test_handle_invalid_referrer_passive_mode_unit(self) -> None:
        """Test _handle_invalid_referrer returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()

        check = ReferrerCheck(middleware)
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        request = Mock()
        request.state = Mock()

        with patch(
            "guard.core.checks.implementations.referrer.log_activity",
            return_value=AsyncMock(),
        ):
            result = await check._handle_invalid_referrer(
                request, "https://evil.com", route_config
            )
            assert result is None


class TestAuthenticationCheckPassiveModeUnit:
    """Unit test for AuthenticationCheck passive mode."""

    @pytest.mark.asyncio
    async def test_authentication_check_passive_mode_unit(self) -> None:
        """Test authentication check returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()

        check = AuthenticationCheck(middleware)
        route_config = RouteConfig()
        route_config.auth_required = "bearer"

        request = Mock()
        request.state = Mock()
        request.state.route_config = route_config
        request.headers = {}

        with patch(
            "guard.core.checks.implementations.authentication.log_activity",
            return_value=AsyncMock(),
        ):
            result = await check.check(request)
            assert result is None


class TestEmergencyModeCheckPassiveModeUnit:
    """Unit test for EmergencyModeCheck passive mode."""

    @pytest.mark.asyncio
    async def test_emergency_mode_check_no_client_ip_extracts_unit(self) -> None:
        """Test emergency mode extracts IP when client_ip is None - UNIT TEST."""
        # client_ip extracted when None
        config = SecurityConfig()
        config.emergency_mode = True
        config.emergency_whitelist = ["192.168.1.1"]

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()
        middleware.agent_handler = None
        middleware.create_error_response = AsyncMock(return_value=Mock(status_code=503))

        check = EmergencyModeCheck(middleware)

        request = Mock()
        request.state = Mock()
        request.state.client_ip = None  # No client IP in state

        with patch(
            "guard.core.checks.implementations.emergency_mode.extract_client_ip",
            return_value="8.8.8.8",  # Extracted IP not in whitelist
        ):
            with patch(
                "guard.core.checks.implementations.emergency_mode.log_activity",
                return_value=AsyncMock(),
            ):
                result = await check.check(request)
                assert result is not None  # Blocked because not in whitelist

    @pytest.mark.asyncio
    async def test_emergency_mode_check_passive_mode_unit(self) -> None:
        """Test emergency mode check returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True
        config.emergency_mode = True

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()

        check = EmergencyModeCheck(middleware)

        request = Mock()
        request.state = Mock()
        request.state.client_ip = "8.8.8.8"  # Not in whitelist

        with patch(
            "guard.core.checks.implementations.emergency_mode.log_activity",
            return_value=AsyncMock(),
        ):
            result = await check.check(request)
            assert result is None


class TestRequestSizeContentCheckPassiveModeUnit:
    """Unit tests for RequestSizeContentCheck passive mode."""

    @pytest.mark.asyncio
    async def test_check_request_size_limit_passive_mode_unit(self) -> None:
        """Test _check_request_size_limit returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()

        check = RequestSizeContentCheck(middleware)
        route_config = RouteConfig()
        route_config.max_request_size = 100

        request = Mock()
        request.state = Mock()
        request.headers = {"content-length": "1000"}

        with patch(
            "guard.core.checks.implementations.request_size_content.log_activity",
            return_value=AsyncMock(),
        ):
            result = await check._check_request_size_limit(request, route_config)
            assert result is None

    @pytest.mark.asyncio
    async def test_check_content_type_allowed_passive_mode_unit(self) -> None:
        """Test _check_content_type_allowed returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()

        check = RequestSizeContentCheck(middleware)
        route_config = RouteConfig()
        route_config.allowed_content_types = ["application/json"]

        request = Mock()
        request.state = Mock()
        request.headers = {"content-type": "text/html"}

        with patch(
            "guard.core.checks.implementations.request_size_content.log_activity",
            return_value=AsyncMock(),
        ):
            result = await check._check_content_type_allowed(request, route_config)
            assert result is None


class TestRequiredHeadersCheckPassiveModeUnit:
    """Unit test for RequiredHeadersCheck passive mode."""

    @pytest.mark.asyncio
    async def test_required_headers_check_passive_mode_unit(self) -> None:
        """Test required headers check returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()

        check = RequiredHeadersCheck(middleware)
        route_config = RouteConfig()
        route_config.required_headers = {"X-API-Key": "required"}

        request = Mock()
        request.state = Mock()
        request.state.route_config = route_config
        request.headers = {}

        with patch(
            "guard.core.checks.implementations.required_headers.log_activity",
            return_value=AsyncMock(),
        ):
            result = await check.check(request)
            assert result is None


class TestSuspiciousActivityCheckPassiveModeUnit:
    """Unit test for SuspiciousActivityCheck passive mode."""

    @pytest.mark.asyncio
    async def test_suspicious_activity_check_no_client_ip_unit(self) -> None:
        """Test suspicious activity check returns None when no client_ip - UNIT TEST."""
        # return None when client_ip is None
        config = SecurityConfig()
        config.passive_mode = False
        config.enable_penetration_detection = True

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()
        middleware.route_resolver = Mock()
        middleware.route_resolver.should_bypass_check = Mock(return_value=False)

        check = SuspiciousActivityCheck(middleware)

        request = Mock()
        request.state = Mock()
        request.state.route_config = None
        request.state.client_ip = None  # No client IP

        result = await check.check(request)
        assert result is None

    @pytest.mark.asyncio
    async def test_suspicious_activity_check_passive_mode_unit(self) -> None:
        """Test suspicious activity check returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True
        config.enable_penetration_detection = True

        middleware = Mock()
        middleware.config = config
        middleware.logger = Mock()
        middleware.event_bus = Mock()
        middleware.event_bus.send_middleware_event = AsyncMock()
        middleware.route_resolver = Mock()
        middleware.route_resolver.should_bypass_check = Mock(return_value=False)
        middleware.suspicious_request_counts = {}  # Dict, not Mock

        check = SuspiciousActivityCheck(middleware)

        request = Mock()
        request.state = Mock()
        request.state.route_config = None
        request.state.client_ip = "1.2.3.4"

        with patch(
            "guard.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
            return_value=(True, "SQL injection"),
        ):
            with patch(
                "guard.core.checks.implementations.suspicious_activity.log_activity",
                return_value=AsyncMock(),
            ):
                result = await check.check(request)
                assert result is None
                # Verify count was incremented
                assert middleware.suspicious_request_counts["1.2.3.4"] == 1
