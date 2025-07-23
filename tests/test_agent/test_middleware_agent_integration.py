# tests/test_agent/test_middleware_agent_integration.py
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request
from starlette.types import ASGIApp

from guard.decorators.base import RouteConfig
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig


class TestMiddlewareAgentIntegration:
    """Test agent integration within SecurityMiddleware."""

    def test_agent_initialization_success(self, config: SecurityConfig) -> None:
        """Test successful agent initialization in middleware."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)

        # Verify agent was initialized (mock_guard_agent fixture provides the mock)
        assert middleware.agent_handler is not None

    def test_agent_initialization_import_error(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        """Test agent initialization when guard_agent not installed."""
        # Override the guard_agent mock to raise ImportError
        with patch("guard.middleware.guard_agent", side_effect=ImportError):
            app = MagicMock(spec=ASGIApp)
            middleware = SecurityMiddleware(app, config=config)

            # Verify warning logged and agent_handler is None
            assert middleware.agent_handler is None
            assert "guard_agent package not installed" in caplog.text

    def test_agent_initialization_exception(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        """Test agent initialization with general exception."""
        # Override the guard_agent mock to raise general exception
        with patch(
            "guard.middleware.guard_agent", side_effect=Exception("Connection failed")
        ):
            app = MagicMock(spec=ASGIApp)
            middleware = SecurityMiddleware(app, config=config)

            # Verify error logged and agent_handler is None
            assert middleware.agent_handler is None
            assert "Failed to initialize Guard Agent" in caplog.text

    def test_agent_initialization_invalid_config(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test agent initialization with invalid config."""
        # Create config with agent disabled (simulates invalid config)
        invalid_config = SecurityConfig(enable_agent=False)

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=invalid_config)

        # Should not initialize agent when disabled
        assert middleware.agent_handler is None

    def test_agent_disabled(self, config: SecurityConfig) -> None:
        """Test that agent is not initialized when disabled."""
        config = SecurityConfig(enable_agent=False)

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)

        # Agent should not be initialized
        assert middleware.agent_handler is None

    @pytest.mark.asyncio
    async def test_send_middleware_event_success(self, config: SecurityConfig) -> None:
        """Test successful event sending."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        # Mock request
        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-agent"}

        # Mock extract_client_ip
        with patch(
            "guard.middleware.extract_client_ip",
            AsyncMock(return_value="192.168.1.100"),
        ):
            await middleware._send_middleware_event(
                "config_violation", request, "blocked", "test reason", extra="data"
            )

            # Verify event was sent to agent handler
            middleware.agent_handler.send_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_middleware_event_disabled(self) -> None:
        """Test event not sent when disabled."""
        # Create config with events disabled
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-api-key",
            agent_enable_events=False
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        request = MagicMock(spec=Request)

        await middleware._send_middleware_event(
            "config_violation", request, "blocked", "test reason"
        )

        # Should not send event
        middleware.agent_handler.send_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_middleware_event_no_agent(self, config: SecurityConfig) -> None:
        """Test event sending without agent handler."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = None  # No agent

        request = MagicMock(spec=Request)

        # Should not raise any errors
        await middleware._send_middleware_event(
            "config_violation", request, "blocked", "test reason"
        )

    @pytest.mark.asyncio
    async def test_send_middleware_event_with_geo_handler(
        self, config: SecurityConfig
    ) -> None:
        """Test event sending with geo IP handler."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        # Mock geo IP handler
        mock_geo_handler = MagicMock()
        mock_geo_handler.get_country.return_value = "US"
        middleware.geo_ip_handler = mock_geo_handler

        # Mock request
        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        request.method = "POST"
        request.headers = {"User-Agent": "test-agent"}

        # Mock extract_client_ip
        with patch(
            "guard.middleware.extract_client_ip",
            AsyncMock(return_value="192.168.1.100"),
        ):
            await middleware._send_middleware_event(
                "country_blocked", request, "allowed", "from US"
            )

            # Verify event was sent to agent handler
            middleware.agent_handler.send_event.assert_called_once()

            # Verify the event was created with the correct data
            sent_event = middleware.agent_handler.send_event.call_args[0][0]
            assert sent_event.country == "US"
            assert sent_event.ip_address == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_send_middleware_event_geo_handler_failure(
        self, config: SecurityConfig
    ) -> None:
        """Test event sending when geo handler fails."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        # Mock geo IP handler that raises exception
        mock_geo_handler = MagicMock()
        mock_geo_handler.get_country.side_effect = Exception("Geo lookup failed")
        middleware.geo_ip_handler = mock_geo_handler

        # Mock request
        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-agent"}

        # Mock extract_client_ip
        with patch(
            "guard.middleware.extract_client_ip",
            AsyncMock(return_value="192.168.1.100"),
        ):
            await middleware._send_middleware_event(
                "config_violation", request, "blocked", "test reason"
            )

            # Verify event was sent to agent handler
            middleware.agent_handler.send_event.assert_called_once()

            # Verify the event was created without country
            sent_event = middleware.agent_handler.send_event.call_args[0][0]
            assert sent_event.country is None
            assert sent_event.ip_address == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_send_middleware_event_agent_failure(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        """Test event sending when agent fails."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()
        middleware.agent_handler.send_event.side_effect = Exception("Network error")

        # Mock request
        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-agent"}

        # Mock extract_client_ip
        with patch(
            "guard.middleware.extract_client_ip",
            AsyncMock(return_value="192.168.1.100"),
        ):
            # Mock SecurityEvent
            with patch("guard_agent.models.SecurityEvent"):
                await middleware._send_middleware_event(
                    "config_violation", request, "blocked", "test reason"
                )

                # Should log error but not raise
                assert "Failed to send security event to agent" in caplog.text

    @pytest.mark.asyncio
    async def test_send_security_metric_success(self, config: SecurityConfig) -> None:
        """Test successful metric sending."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        await middleware._send_security_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        # Verify metric was sent to agent handler
        middleware.agent_handler.send_metric.assert_called_once()

        # Verify the metric was created with the correct data
        sent_metric = middleware.agent_handler.send_metric.call_args[0][0]
        assert sent_metric.metric_type == "response_time"
        assert sent_metric.value == 123.45
        assert sent_metric.tags == {"endpoint": "/api/test"}

    @pytest.mark.asyncio
    async def test_send_security_metric_disabled(self) -> None:
        """Test metric not sent when disabled."""
        # Create config with metrics disabled
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-api-key",
            agent_enable_metrics=False
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        await middleware._send_security_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        # Should not send metric
        middleware.agent_handler.send_metric.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_security_metric_no_agent(self, config: SecurityConfig) -> None:
        """Test metric sending without agent."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = None  # No agent

        # Should not raise any errors
        await middleware._send_security_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

    @pytest.mark.asyncio
    async def test_send_security_metric_agent_failure(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        """Test metric sending when agent fails."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()
        middleware.agent_handler.send_metric.side_effect = Exception("Network error")

        await middleware._send_security_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        # Should log error but not raise
        assert "Failed to send metric to agent" in caplog.text

    @pytest.mark.asyncio
    async def test_send_security_metric_no_tags(self, config: SecurityConfig) -> None:
        """Test metric sending without tags."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        await middleware._send_security_metric("request_count", 1.0)

        # Verify metric was sent to agent handler
        middleware.agent_handler.send_metric.assert_called_once()

        # Verify the metric was created with empty tags
        sent_metric = middleware.agent_handler.send_metric.call_args[0][0]
        assert sent_metric.tags == {}

    @pytest.mark.asyncio
    async def test_collect_request_metrics(self, config: SecurityConfig) -> None:
        """Test request metrics collection."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        request.method = "GET"

        # Mock _send_security_metric
        with patch.object(
            middleware, "_send_security_metric", AsyncMock()
        ) as mock_send:
            await middleware._collect_request_metrics(request, 50.5, 200)

            # Should send response_time and request_count metrics
            assert mock_send.call_count == 2

            # Check response_time metric
            mock_send.assert_any_call(
                "response_time",
                50.5,
                {"endpoint": "/api/test", "method": "GET", "status": "200"},
            )

            # Check request_count metric
            mock_send.assert_any_call(
                "request_count", 1.0, {"endpoint": "/api/test", "method": "GET"}
            )

    @pytest.mark.asyncio
    async def test_collect_request_metrics_disabled(self) -> None:
        """Test request metrics not collected when disabled."""
        # Create config with metrics disabled
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-api-key",
            agent_enable_metrics=False
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        request.method = "GET"

        # Should return early without sending metrics
        await middleware._collect_request_metrics(request, 50.5, 200)

        # No metrics should be sent
        middleware.agent_handler.send_metric.assert_not_called()

    @pytest.mark.asyncio
    async def test_collect_request_metrics_no_agent(
        self, config: SecurityConfig
    ) -> None:
        """Test request metrics collection without agent."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = None  # No agent

        request = MagicMock(spec=Request)
        request.url.path = "/api/test"
        request.method = "GET"

        # Should not raise any errors
        await middleware._collect_request_metrics(request, 50.5, 200)

    @pytest.mark.asyncio
    async def test_collect_request_metrics_different_status_codes(
        self, config: SecurityConfig
    ) -> None:
        """Test request metrics with different status codes."""
        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        request = MagicMock(spec=Request)
        request.url.path = "/api/secure"
        request.method = "POST"

        # Mock _send_security_metric
        with patch.object(
            middleware, "_send_security_metric", AsyncMock()
        ) as mock_send:
            # Test with 403 status
            await middleware._collect_request_metrics(request, 25.3, 403)

            # Check response_time metric with 403 status
            mock_send.assert_any_call(
                "response_time",
                25.3,
                {"endpoint": "/api/secure", "method": "POST", "status": "403"},
            )

            # Test with 500 status
            await middleware._collect_request_metrics(request, 100.2, 500)

            # Check response_time metric with 500 status
            mock_send.assert_any_call(
                "response_time",
                100.2,
                {"endpoint": "/api/secure", "method": "POST", "status": "500"},
            )

    async def test_agent_init_invalid_config_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test warning when agent enabled but config is invalid"""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key"  # Valid key to pass validation
        )

        # Mock to_agent_config to return None to simulate invalid config
        with patch.object(SecurityConfig, 'to_agent_config', return_value=None):
            app = MagicMock(spec=ASGIApp)
            middleware = SecurityMiddleware(app, config=config)

        # Check warning was logged
        assert "Agent enabled but configuration is invalid" in caplog.text
        assert middleware.agent_handler is None

    @pytest.mark.asyncio
    async def test_emergency_mode_block_with_event(
        self, config: SecurityConfig
    ) -> None:
        """Test emergency mode blocks non-whitelisted IPs and sends event"""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            emergency_mode=True,
            emergency_whitelist=["192.168.1.1"]
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        request = MagicMock(spec=Request)
        request.client = MagicMock(host="10.0.0.1")  # Not in whitelist
        request.url = MagicMock(path="/test")
        request.headers = {}
        request.method = "GET"
        request.scope = {"app": app}

        async def call_next(_):
            return MagicMock(status_code=200)

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 503
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "emergency_mode_block"
        assert event.action_taken == "request_blocked"

    @pytest.mark.asyncio
    async def test_emergency_mode_allow_whitelist_with_logging(
        self,
    ) -> None:
        """Test emergency mode allows whitelisted IPs with logging"""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            emergency_mode=True,
            emergency_whitelist=["192.168.1.1"]
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        request = MagicMock(spec=Request)
        request.client = MagicMock(host="192.168.1.1")  # In whitelist
        request.url = MagicMock(path="/test")
        request.headers = {}
        request.method = "GET"
        request.scope = {"app": app}

        call_next = AsyncMock(return_value=MagicMock(status_code=200))

        # Mock log_activity to avoid async issues
        with patch('guard.middleware.log_activity', new_callable=AsyncMock):
            await middleware.dispatch(request, call_next)

        # Verify call_next was called (request was allowed)
        call_next.assert_called_once()

    @pytest.mark.asyncio
    async def test_generic_auth_requirement_failure(self) -> None:
        """Test generic auth requirement without header"""

        route_config = RouteConfig()
        route_config.auth_required = "custom"

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(
            app,
            config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, '_get_route_decorator_config', return_value=route_config
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test")
            request.headers = {}  # No authorization header
            request.method = "GET"
            request.scope = {"app": app}

            response = await middleware.dispatch(request, lambda _: AsyncMock())

        assert response.status_code == 401
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert "Missing custom authentication" in event.reason

    @pytest.mark.asyncio
    async def test_missing_referrer_with_event(self) -> None:
        """Test missing referrer header sends decorator violation event"""


        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(
            app,
            config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, '_get_route_decorator_config', return_value=route_config
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test")
            request.headers = {}  # No referer header
            request.method = "GET"

            response = await middleware.dispatch(request, lambda _: AsyncMock())

        assert response.status_code == 403
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "require_referrer"

    @pytest.mark.asyncio
    async def test_referrer_parsing_exception(self) -> None:
        """Test referrer parsing exception handling"""


        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(
            app,
            config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, '_get_route_decorator_config', return_value=route_config
        ):
            with patch('urllib.parse.urlparse', side_effect=Exception("Parse error")):
                request = MagicMock(spec=Request)
                request.client = MagicMock(host="127.0.0.1")
                request.url = MagicMock(path="/test")
                request.headers = {"referer": "invalid://url"}
                request.method = "GET"
                request.scope = {"app": app}

                response = await middleware.dispatch(request, lambda _: AsyncMock())

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_invalid_referrer_domain_with_event(self) -> None:
        """Test invalid referrer domain sends decorator violation event"""


        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(
            app,
            config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, '_get_route_decorator_config', return_value=route_config
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test")
            request.headers = {"referer": "https://evil.com/page"}
            request.method = "GET"
            request.scope = {"app": app}

            response = await middleware.dispatch(request, lambda _: AsyncMock())

        assert response.status_code == 403
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert "not in allowed domains" in event.reason

    @pytest.mark.asyncio
    async def test_route_specific_user_agent_block_event(self) -> None:
        """Test route-specific user agent block sends decorator violation event"""


        route_config = RouteConfig()
        route_config.blocked_user_agents = ["BadBot"]

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(
            app,
            config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, '_get_route_decorator_config', return_value=route_config
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test")
            request.headers = {"User-Agent": "BadBot/1.0"}
            request.method = "GET"
            request.scope = {"app": app}

            response = await middleware.dispatch(request, lambda _: AsyncMock())

        assert response.status_code == 403
        # Should send decorator violation event for route-specific block
        calls = middleware.agent_handler.send_event.call_args_list
        assert len(calls) >= 1
        event = calls[0][0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "user_agent"

    @pytest.mark.asyncio
    async def test_suspicious_detection_disabled_by_decorator(
        self, config: SecurityConfig
    ) -> None:
        """Test suspicious detection disabled by decorator sends event"""


        route_config = RouteConfig()
        route_config.enable_suspicious_detection = False

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_penetration_detection=True  # Globally enabled
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, '_get_route_decorator_config', return_value=route_config
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test?cmd=rm%20-rf")  # Suspicious pattern
            request.headers = {}
            request.method = "GET"
            request.scope = {"app": app}

            call_next = AsyncMock(return_value=MagicMock(status_code=200))
            await middleware.dispatch(request, call_next)

        # Should send decorator violation event for disabling detection
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "suspicious_detection_disabled"
