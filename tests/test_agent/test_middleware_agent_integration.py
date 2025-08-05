# tests/test_agent/test_middleware_agent_integration.py
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request, Response
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
            enable_agent=True, agent_api_key="test-api-key", agent_enable_events=False
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
            enable_agent=True, agent_api_key="test-api-key", agent_enable_metrics=False
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
            enable_agent=True, agent_api_key="test-api-key", agent_enable_metrics=False
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
            agent_api_key="test-key",  # Valid key to pass validation
        )

        # Mock to_agent_config to return None to simulate invalid config
        with patch.object(SecurityConfig, "to_agent_config", return_value=None):
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
            emergency_whitelist=["192.168.1.1"],
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

        call_next = AsyncMock(return_value=Response(status_code=200))
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
            emergency_whitelist=["192.168.1.1"],
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

        with (
            patch("guard.middleware.log_activity", new_callable=AsyncMock),
            patch(
                "guard.middleware.detect_penetration_attempt",
                new_callable=AsyncMock,
                return_value=(False, ""),
            ),
        ):
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
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, "_get_route_decorator_config", return_value=route_config
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test")
            request.headers = {}  # No authorization header
            request.method = "GET"
            request.scope = {"app": app}

            call_next = AsyncMock(return_value=Response(status_code=200))
            response = await middleware.dispatch(request, call_next)

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
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, "_get_route_decorator_config", return_value=route_config
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test")
            request.headers = {}  # No referer header
            request.method = "GET"

            call_next = AsyncMock(return_value=Response(status_code=200))
            response = await middleware.dispatch(request, call_next)

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
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, "_get_route_decorator_config", return_value=route_config
        ):
            with patch("urllib.parse.urlparse", side_effect=Exception("Parse error")):
                request = MagicMock(spec=Request)
                request.client = MagicMock(host="127.0.0.1")
                request.url = MagicMock(path="/test")
                request.headers = {"referer": "invalid://url"}
                request.method = "GET"
                request.scope = {"app": app}

                call_next = AsyncMock(return_value=Response(status_code=200))
                response = await middleware.dispatch(request, call_next)

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_invalid_referrer_domain_with_event(self) -> None:
        """Test invalid referrer domain sends decorator violation event"""

        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, "_get_route_decorator_config", return_value=route_config
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test")
            request.headers = {"referer": "https://evil.com/page"}
            request.method = "GET"
            request.scope = {"app": app}

            call_next = AsyncMock(return_value=Response(status_code=200))
            response = await middleware.dispatch(request, call_next)

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
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, "_get_route_decorator_config", return_value=route_config
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test")
            request.headers = {"User-Agent": "BadBot/1.0"}
            request.method = "GET"
            request.scope = {"app": app}

            call_next = AsyncMock(return_value=Response(status_code=200))
            response = await middleware.dispatch(request, call_next)

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
            enable_penetration_detection=True,  # Globally enabled
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        with patch.object(
            middleware, "_get_route_decorator_config", return_value=route_config
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

    @pytest.mark.asyncio
    async def test_dynamic_endpoint_rate_limiting(self) -> None:
        """Test dynamic endpoint-specific rate limiting"""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
            endpoint_rate_limits={"/api/sensitive": (10, 60)},  # 10 req/60s
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()
        middleware.redis_handler = AsyncMock()

        # Mock rate limit handler to simulate rate limit exceeded
        mock_rate_handler = AsyncMock()
        mock_rate_handler.check_rate_limit = AsyncMock(
            return_value=Response("Rate limit exceeded", status_code=429)
        )

        with (
            patch("guard.middleware.RateLimitManager", return_value=mock_rate_handler),
            patch(
                "guard.middleware.extract_client_ip",
                AsyncMock(return_value="127.0.0.1"),
            ),
            patch("guard.middleware.log_activity", new_callable=AsyncMock),
            patch(
                "guard.middleware.detect_penetration_attempt",
                new_callable=AsyncMock,
                return_value=(False, ""),
            ),
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/api/sensitive")
            request.headers = {}
            request.method = "GET"
            request.scope = {"app": app}

            call_next = AsyncMock(return_value=Response(status_code=200))
            response = await middleware.dispatch(request, call_next)

        assert response.status_code == 429
        # Verify dynamic rule violation event was sent
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "dynamic_rule_violation"
        assert event.metadata["rule_type"] == "endpoint_rate_limit"
        assert event.metadata["endpoint"] == "/api/sensitive"
        assert event.metadata["rate_limit"] == 10
        assert event.metadata["window"] == 60

    @pytest.mark.asyncio
    async def test_route_specific_rate_limit_exceeded_event(self) -> None:
        """Test route-specific rate limit exceeded sends event"""
        route_config = RouteConfig()
        route_config.rate_limit = 5
        route_config.rate_limit_window = 30

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()
        middleware.redis_handler = AsyncMock()

        # Mock rate limit handler to simulate rate limit exceeded
        mock_rate_handler = AsyncMock()
        mock_rate_handler.check_rate_limit = AsyncMock(
            return_value=Response("Rate limit exceeded", status_code=429)
        )

        with (
            patch.object(
                middleware, "_get_route_decorator_config", return_value=route_config
            ),
            patch("guard.middleware.RateLimitManager", return_value=mock_rate_handler),
            patch(
                "guard.middleware.extract_client_ip",
                AsyncMock(return_value="127.0.0.1"),
            ),
            patch("guard.middleware.log_activity", new_callable=AsyncMock),
            patch(
                "guard.middleware.detect_penetration_attempt",
                new_callable=AsyncMock,
                return_value=(False, ""),
            ),
        ):
            request = MagicMock(spec=Request)
            request.client = MagicMock(host="127.0.0.1")
            request.url = MagicMock(path="/test")
            request.headers = {}
            request.method = "GET"
            request.scope = {"app": app}

            call_next = AsyncMock(return_value=Response(status_code=200))
            response = await middleware.dispatch(request, call_next)

        assert response.status_code == 429
        # Verify decorator violation event was sent
        middleware.agent_handler.send_event.assert_called_once()
        event = middleware.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["decorator_type"] == "rate_limiting"
        assert event.metadata["violation_type"] == "rate_limit"
        assert event.metadata["rate_limit"] == 5
        assert event.metadata["window"] == 30

    @pytest.mark.asyncio
    async def test_cloud_provider_detection_with_agent_event(
        self, config: SecurityConfig
    ) -> None:
        """Test cloud provider detection sends event through cloud handler."""
        config.block_cloud_providers = {"AWS", "GCP"}

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)
        middleware.agent_handler = AsyncMock()

        request = MagicMock(spec=Request)
        request.client = MagicMock(host="3.3.3.3")  # Simulated cloud IP
        request.url = MagicMock(path="/test")
        request.headers = {"User-Agent": "Mozilla/5.0"}
        request.method = "GET"
        request.scope = {"app": app}

        # Mock cloud handler with agent support
        mock_cloud_handler = MagicMock()
        mock_cloud_handler.is_cloud_ip.return_value = True
        mock_cloud_handler.get_cloud_provider_details.return_value = (
            "aws",
            "3.0.0.0/8",
        )
        mock_cloud_handler.agent_handler = middleware.agent_handler
        mock_cloud_handler.send_cloud_detection_event = AsyncMock()
        mock_cloud_handler.refresh_async = AsyncMock()
        mock_cloud_handler.refresh = MagicMock()

        # Mock time to trigger refresh
        mock_time = MagicMock()
        mock_time.time.return_value = 9999999999  # Far in the future

        with (
            patch("guard.middleware.cloud_handler", mock_cloud_handler),
            patch("guard.middleware.time", mock_time),
            patch(
                "guard.middleware.extract_client_ip",
                AsyncMock(return_value="3.3.3.3"),
            ),
            patch("guard.middleware.log_activity", new_callable=AsyncMock),
            patch(
                "guard.middleware.detect_penetration_attempt",
                new_callable=AsyncMock,
                return_value=(False, ""),
            ),
        ):
            call_next = AsyncMock(return_value=Response(status_code=200))
            response = await middleware.dispatch(request, call_next)

        assert response.status_code == 403
        # Verify cloud detection event was sent through cloud handler
        mock_cloud_handler.send_cloud_detection_event.assert_called_once_with(
            "3.3.3.3", "aws", "3.0.0.0/8", "request_blocked"
        )

    @pytest.mark.asyncio
    async def test_initialize_with_agent_handler(self) -> None:
        """Test initialize() method with agent handler"""
        # Create a mock geo_ip_handler
        mock_geo_ip_handler = MagicMock()
        mock_geo_ip_handler.initialize_agent = AsyncMock()
        mock_geo_ip_handler.initialize_redis = AsyncMock()

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
            enable_dynamic_rules=True,
            block_cloud_providers={"AWS"},
            whitelist_countries=["US"],
            geo_ip_handler=mock_geo_ip_handler,
        )

        app = MagicMock(spec=ASGIApp)
        middleware = SecurityMiddleware(app, config=config)

        # Create mocks for all components
        middleware.agent_handler = AsyncMock()
        middleware.redis_handler = AsyncMock()
        # geo_ip_handler is already set from config
        middleware.guard_decorator = AsyncMock()
        middleware.guard_decorator.initialize_agent = AsyncMock()

        # Mock handlers
        mock_ip_ban_manager = AsyncMock()
        mock_rate_limit_handler = AsyncMock()
        mock_sus_patterns_handler = AsyncMock()
        mock_cloud_handler = AsyncMock()
        mock_dynamic_rule_manager = AsyncMock()

        with (
            patch("guard.middleware.ip_ban_manager", mock_ip_ban_manager),
            patch.object(middleware, "rate_limit_handler", mock_rate_limit_handler),
            patch("guard.middleware.sus_patterns_handler", mock_sus_patterns_handler),
            patch("guard.middleware.cloud_handler", mock_cloud_handler),
            patch(
                "guard.handlers.dynamic_rule_handler.DynamicRuleManager",
                return_value=mock_dynamic_rule_manager,
            ),
        ):
            await middleware.initialize()

        # Verify agent was started
        middleware.agent_handler.start.assert_called_once()

        # Verify agent was connected to Redis
        middleware.agent_handler.initialize_redis.assert_called_once_with(
            middleware.redis_handler
        )
        middleware.redis_handler.initialize_agent.assert_called_once_with(
            middleware.agent_handler
        )

        # Verify agent was initialized in all handlers
        mock_ip_ban_manager.initialize_agent.assert_called_once_with(
            middleware.agent_handler
        )
        mock_rate_limit_handler.initialize_agent.assert_called_once_with(
            middleware.agent_handler
        )
        mock_sus_patterns_handler.initialize_agent.assert_called_once_with(
            middleware.agent_handler
        )
        mock_cloud_handler.initialize_agent.assert_called_once_with(
            middleware.agent_handler
        )

        assert middleware.geo_ip_handler is not None

        # Verify agent was initialized in decorator handler
        middleware.guard_decorator.initialize_agent.assert_called_once_with(
            middleware.agent_handler
        )

        # Verify dynamic rule manager was initialized
        mock_dynamic_rule_manager.initialize_agent.assert_called_once_with(
            middleware.agent_handler
        )
        mock_dynamic_rule_manager.initialize_redis.assert_called_once_with(
            middleware.redis_handler
        )
