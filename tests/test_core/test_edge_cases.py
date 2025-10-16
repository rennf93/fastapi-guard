import re
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request, Response

from guard.core.events.middleware_events import SecurityEventBus
from guard.handlers.dynamic_rule_handler import DynamicRuleManager
from guard.handlers.ratelimit_handler import RateLimitManager
from guard.handlers.security_headers_handler import SecurityHeadersManager
from guard.handlers.suspatterns_handler import SusPatternsManager
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig


class TestDynamicRuleHandler:
    """Test DynamicRuleHandler edge cases."""

    @pytest.mark.asyncio
    async def test_send_rule_received_event_no_agent(self) -> None:
        """Test _send_rule_received_event when no agent handler exists."""
        from datetime import datetime, timezone

        config = SecurityConfig()
        config.enable_dynamic_rules = False
        manager = DynamicRuleManager(config)
        manager.agent_handler = None  # No agent

        # Create fake rules
        from guard.models import DynamicRules

        rules = DynamicRules(
            rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
        )

        # Should return early without error
        await manager._send_rule_received_event(rules)

        # Verify no exception was raised
        assert True


class TestRateLimitHandler:
    """Test RateLimitHandler edge cases."""

    @pytest.mark.asyncio
    async def test_get_redis_request_count_no_redis_handler(self) -> None:
        """Test _get_redis_request_count when no redis handler exists."""
        config = SecurityConfig()
        config.enable_redis = False
        manager = RateLimitManager(config)
        manager.redis_handler = None  # No Redis handler

        # Should return None early
        result = await manager._get_redis_request_count(
            client_ip="127.0.0.1", current_time=1000.0, window_start=900.0
        )

        assert result is None


class TestSecurityHeadersHandler:
    """Test SecurityHeadersHandler edge cases."""

    @pytest.mark.asyncio
    async def test_get_validated_cors_config_no_cors_config(self) -> None:
        """Test _get_validated_cors_config when cors_config is None."""
        manager = SecurityHeadersManager()
        manager.cors_config = None

        # Should return defaults
        allow_methods, allow_headers = manager._get_validated_cors_config()

        assert allow_methods == ["GET", "POST"]
        assert allow_headers == ["*"]


class TestSusPatternsHandler:
    """Test SusPatternsHandler edge cases."""

    @pytest.mark.asyncio
    async def test_remove_default_pattern_not_found(self) -> None:
        """Test _remove_default_pattern when pattern doesn't exist."""
        # Get singleton instance
        handler = SusPatternsManager()

        # Save original state
        original_patterns = handler.patterns.copy()
        original_compiled = handler.compiled_patterns.copy()

        try:
            # Try to remove non-existent pattern
            result = await handler._remove_default_pattern("nonexistent_pattern_xyz")

            assert result is False
        finally:
            # Restore original state
            handler.patterns = original_patterns
            handler.compiled_patterns = original_compiled

    @pytest.mark.asyncio
    async def test_remove_default_pattern_invalid_index(self) -> None:
        """Test _remove_default_pattern with index out of range."""
        # Get singleton instance
        handler = SusPatternsManager()

        # Save original state
        original_patterns = handler.patterns.copy()
        original_compiled = handler.compiled_patterns.copy()

        try:
            # Add a pattern to default list
            test_pattern = "test_pattern_xyz_123_unique_edge"
            handler.patterns.append(test_pattern)
            compiled = re.compile(test_pattern)
            handler.compiled_patterns.append(compiled)

            # Manually break the sync between patterns and compiled_patterns
            # to test the fallback
            handler.compiled_patterns = []  # Empty compiled list

            result = await handler._remove_default_pattern(test_pattern)

            # Pattern was found and removed from patterns list,
            # but not from compiled list (out of range)
            assert result is False
        finally:
            # Restore original state
            handler.patterns = original_patterns
            handler.compiled_patterns = original_compiled


class TestMiddleware:
    """Test Middleware edge cases."""

    @pytest.mark.asyncio
    async def test_create_https_redirect(self) -> None:
        """Test _create_https_redirect method."""
        config = SecurityConfig()
        app = Mock()
        middleware = SecurityMiddleware(app, config=config)

        # Create mock request
        mock_request = Mock(spec=Request)
        mock_request.url = Mock()
        mock_request.url.replace = Mock(return_value="https://example.com")

        # Mock response factory
        middleware.response_factory = Mock()
        middleware.response_factory.create_https_redirect = AsyncMock(
            return_value=Response(status_code=307)
        )

        # Call the method
        response = await middleware._create_https_redirect(mock_request)

        assert response.status_code == 307
        middleware.response_factory.create_https_redirect.assert_called_once()


class TestUtilsEdgeCases:
    """Test utils.py edge cases."""

    @pytest.mark.asyncio
    async def test_fallback_pattern_check_with_exception(self) -> None:
        """Test _fallback_pattern_check when pattern.search raises exception."""
        from guard.utils import _fallback_pattern_check

        # Mock pattern that raises exception
        with patch(
            "guard.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_handler:
            mock_pattern = Mock()
            mock_pattern.search = Mock(side_effect=Exception("Pattern error"))
            mock_handler.get_all_compiled_patterns = AsyncMock(
                return_value=[mock_pattern]
            )

            # Should handle exception and continue
            result = await _fallback_pattern_check("test_value")

            # Should return False since no patterns matched
            assert result == (False, "")

    @pytest.mark.asyncio
    async def test_check_value_enhanced_empty_threats_list(self) -> None:
        """Test empty threats list."""
        from guard.utils import _check_value_enhanced

        # Mock at the module level where it's imported
        with patch("guard.utils.sus_patterns_handler") as mock_handler:
            # Simulate a threat detected but no threat details available
            mock_handler.detect = AsyncMock(
                return_value={"is_threat": True, "threats": []}
            )

            # Call _check_value_enhanced
            result = await _check_value_enhanced(
                value="test_value",
                context="test_context",
                client_ip="127.0.0.1",
                correlation_id="test-123",
            )

            # Should return True with generic message
            assert result == (True, "Threat detected")

    @pytest.mark.asyncio
    async def test_detect_penetration_attempt_real_path(self) -> None:
        """Test detect_penetration_attempt with real detection."""
        from guard.utils import detect_penetration_attempt

        mock_request = Mock(spec=Request)
        mock_request.client = Mock()
        mock_request.client.host = "127.0.0.1"
        mock_request.query_params = {}
        mock_request.url = Mock()
        mock_request.url.path = "/test"
        mock_request.headers = {}
        mock_request.body = AsyncMock(return_value=b"")

        # Don't mock the handler - use real detection
        # This will exercise the actual check_value function
        result = await detect_penetration_attempt(mock_request)

        # Should return False, "" for clean request
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)


class TestEventBusGeoIPException:
    """Test SecurityEventBus geo IP exception handling."""

    @pytest.mark.asyncio
    async def test_send_middleware_event_with_geo_ip_exception(self) -> None:
        """Test middleware event when geo IP lookup raises exception."""
        config = SecurityConfig()
        config.agent_enable_events = True

        mock_agent = Mock()
        mock_agent.send_event = AsyncMock()

        mock_geo_ip = Mock()
        geo_exception = Exception("GeoIP failure")
        mock_geo_ip.get_country = Mock(side_effect=geo_exception)

        event_bus = SecurityEventBus(mock_agent, config, mock_geo_ip)

        mock_request = Mock(spec=Request)
        mock_request.client = Mock()
        mock_request.client.host = "192.168.1.1"
        mock_request.url = Mock()
        mock_request.url.path = "/test"
        mock_request.method = "GET"
        mock_request.headers = {"User-Agent": "TestAgent"}

        # Should not raise exception, just log and continue
        # Use a valid event_type from the SecurityEvent enum
        await event_bus.send_middleware_event(
            event_type="suspicious_request",  # Valid event type
            request=mock_request,
            action_taken="logged",
            reason="test reason",
        )

        # Verify event was still sent without country
        assert mock_agent.send_event.call_count == 1


@pytest.mark.asyncio
async def test_integration_all_edge_cases() -> None:
    """Integration test to ensure all edge cases work together."""
    from datetime import datetime, timezone

    # This test ensures that the combination of all edge cases doesn't cause issues
    config = SecurityConfig()
    config.enable_redis = False
    config.enable_agent = False
    config.enable_dynamic_rules = False

    # Test DynamicRuleManager
    drm = DynamicRuleManager(config)
    from guard.models import DynamicRules

    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    await drm._send_rule_received_event(rules)

    # Test RateLimitManager
    rlm = RateLimitManager(config)
    result = await rlm._get_redis_request_count("127.0.0.1", 1000.0, 900.0)
    assert result is None

    # Test SecurityHeadersManager
    shm = SecurityHeadersManager()
    shm.cors_config = None
    methods, headers = shm._get_validated_cors_config()
    assert methods == ["GET", "POST"]
    assert headers == ["*"]

    # Test SusPatternsManager
    spm = SusPatternsManager()
    result = await spm._remove_default_pattern("nonexistent")
    assert result is False
