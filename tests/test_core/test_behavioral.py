from typing import Literal
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import Request, Response

from guard.core.behavioral.context import BehavioralContext
from guard.core.behavioral.processor import BehavioralProcessor
from guard.decorators.base import RouteConfig
from guard.handlers.behavior_handler import BehaviorRule


def create_route_config_with_rules(rules: list[BehaviorRule]) -> RouteConfig:
    """Helper to create RouteConfig with behavior rules."""
    config = RouteConfig()
    config.behavior_rules = rules
    return config


@pytest.fixture
def mock_event_bus() -> Mock:
    """Create mock event bus."""
    event_bus = Mock()
    event_bus.send_middleware_event = AsyncMock()
    return event_bus


@pytest.fixture
def mock_guard_decorator() -> Mock:
    """Create mock guard decorator with behavior tracker."""
    decorator = Mock()
    decorator.behavior_tracker = Mock()
    decorator.behavior_tracker.track_endpoint_usage = AsyncMock(return_value=False)
    decorator.behavior_tracker.track_return_pattern = AsyncMock(return_value=False)
    decorator.behavior_tracker.apply_action = AsyncMock()
    return decorator


@pytest.fixture
def behavioral_context(
    mock_event_bus: Mock, mock_guard_decorator: Mock
) -> BehavioralContext:
    """Create behavioral context."""
    context = BehavioralContext(
        config=Mock(),
        logger=Mock(),
        event_bus=mock_event_bus,
        guard_decorator=mock_guard_decorator,
    )
    return context


@pytest.fixture
def processor(behavioral_context: Mock) -> BehavioralProcessor:
    """Create BehavioralProcessor instance."""
    return BehavioralProcessor(behavioral_context)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock(spec=Request)
    request.method = "GET"
    request.url = Mock()
    request.url.path = "/test"
    request.scope = {"route": Mock(endpoint=lambda: None)}
    request.scope["route"].endpoint.__module__ = "test_module"
    request.scope["route"].endpoint.__qualname__ = "test_function"
    return request


@pytest.fixture
def mock_response() -> Mock:
    """Create mock response."""
    response = Mock(spec=Response)
    response.status_code = 200
    return response


class TestBehavioralProcessor:
    """Test BehavioralProcessor class."""

    def test_init(self, behavioral_context: Mock) -> None:
        """Test processor initialization."""
        processor = BehavioralProcessor(behavioral_context)
        assert processor.context == behavioral_context

    @pytest.mark.asyncio
    async def test_process_usage_rules_no_decorator(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test process_usage_rules when guard_decorator is None."""
        processor.context.guard_decorator = None
        route_config = RouteConfig()

        # Should return early without error
        await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

    @pytest.mark.asyncio
    async def test_process_usage_rules_no_threshold_exceeded(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test process_usage_rules when threshold not exceeded."""
        rule = BehaviorRule(rule_type="usage", threshold=10, window=60, action="log")
        route_config = create_route_config_with_rules([rule])

        await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

        # Should track usage but not apply action
        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called_once()
        processor.context.guard_decorator.behavior_tracker.apply_action.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_usage_rules_threshold_exceeded(
        self, processor: Mock, mock_request: Mock, mock_event_bus: Mock
    ) -> None:
        """Test process_usage_rules when usage threshold exceeded."""
        # Mock threshold exceeded
        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage = (
            AsyncMock(return_value=True)
        )

        rule = BehaviorRule(rule_type="usage", threshold=5, window=60, action="ban")
        route_config = create_route_config_with_rules([rule])

        await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

        # Should send event and apply action
        mock_event_bus.send_middleware_event.assert_called_once()
        call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
        assert call_kwargs["event_type"] == "decorator_violation"
        assert call_kwargs["action_taken"] == "behavioral_action_triggered"
        assert "threshold exceeded" in call_kwargs["reason"]
        assert call_kwargs["threshold"] == 5
        assert call_kwargs["window"] == 60

        processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_usage_rules_frequency_type(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test process_usage_rules with frequency rule type."""
        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage = (
            AsyncMock(return_value=True)
        )

        rule = BehaviorRule(rule_type="frequency", threshold=3, window=30, action="log")
        route_config = create_route_config_with_rules([rule])

        await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

        # Should process frequency rules same as usage
        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called_once()
        processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_usage_rules_multiple_rules(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test process_usage_rules with multiple rules."""
        rule1 = BehaviorRule(rule_type="usage", threshold=5, window=60, action="log")
        rule2 = BehaviorRule(
            rule_type="frequency", threshold=10, window=30, action="ban"
        )
        route_config = create_route_config_with_rules([rule1, rule2])

        await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

        # Should process both rules
        assert (
            processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.call_count
            == 2
        )

    @pytest.mark.asyncio
    async def test_process_return_rules_no_decorator(
        self, processor: Mock, mock_request: Mock, mock_response: Mock
    ) -> None:
        """Test process_return_rules when guard_decorator is None."""
        processor.context.guard_decorator = None
        route_config = create_route_config_with_rules([])

        # Should return early without error
        await processor.process_return_rules(
            mock_request, mock_response, "1.2.3.4", route_config
        )

    @pytest.mark.asyncio
    async def test_process_return_rules_no_pattern_detected(
        self, processor: Mock, mock_request: Mock, mock_response: Mock
    ) -> None:
        """Test process_return_rules when pattern not detected."""
        rule = BehaviorRule(
            rule_type="return_pattern",
            pattern="error",
            threshold=3,
            window=60,
            action="log",
        )
        route_config = create_route_config_with_rules([rule])

        await processor.process_return_rules(
            mock_request, mock_response, "1.2.3.4", route_config
        )

        # Should track pattern but not apply action
        processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_called_once()
        processor.context.guard_decorator.behavior_tracker.apply_action.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_return_rules_pattern_detected(
        self,
        processor: Mock,
        mock_request: Mock,
        mock_response: Mock,
        mock_event_bus: Mock,
    ) -> None:
        """Test process_return_rules when return pattern threshold exceeded."""
        # Mock pattern detected
        processor.context.guard_decorator.behavior_tracker.track_return_pattern = (
            AsyncMock(return_value=True)
        )

        rule = BehaviorRule(
            rule_type="return_pattern",
            pattern="error",
            threshold=3,
            window=60,
            action="ban",
        )
        route_config = create_route_config_with_rules([rule])

        await processor.process_return_rules(
            mock_request, mock_response, "1.2.3.4", route_config
        )

        # Should send event and apply action
        mock_event_bus.send_middleware_event.assert_called_once()
        call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
        assert call_kwargs["event_type"] == "decorator_violation"
        assert call_kwargs["violation_type"] == "return_pattern"
        assert call_kwargs["pattern"] == "error"
        assert "Return pattern threshold exceeded" in call_kwargs["reason"]

        processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_return_rules_ignores_non_return_pattern(
        self, processor: Mock, mock_request: Mock, mock_response: Mock
    ) -> None:
        """Test process_return_rules ignores non-return_pattern rules."""
        rule = BehaviorRule(
            rule_type="usage",  # Not return_pattern
            threshold=5,
            window=60,
            action="log",
        )
        route_config = create_route_config_with_rules([rule])

        await processor.process_return_rules(
            mock_request, mock_response, "1.2.3.4", route_config
        )

        # Should not track return patterns for non-return_pattern rules
        processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_not_called()

    def test_get_endpoint_id_with_route(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test get_endpoint_id with route information."""
        endpoint_id = processor.get_endpoint_id(mock_request)
        assert endpoint_id == "test_module.test_function"

    def test_get_endpoint_id_no_route(self, processor: BehavioralProcessor) -> None:
        """Test get_endpoint_id fallback when no route."""
        request = Mock(spec=Request)
        request.method = "POST"
        request.url = Mock()
        request.url.path = "/api/test"
        request.scope = {}

        endpoint_id = processor.get_endpoint_id(request)
        assert endpoint_id == "POST:/api/test"

    def test_get_endpoint_id_no_endpoint_attr(self, processor: Mock) -> None:
        """Test get_endpoint_id when route has no endpoint."""
        request = Mock(spec=Request)
        request.method = "GET"
        request.url = Mock()
        request.url.path = "/test"
        request.scope = {"route": Mock(spec=[])}  # Route without endpoint

        endpoint_id = processor.get_endpoint_id(request)
        assert endpoint_id == "GET:/test"

    @pytest.mark.parametrize(
        "rule_type,pattern,threshold,window,action",
        [
            ("usage", None, 5, 60, "log"),
            ("frequency", None, 10, 30, "ban"),
            ("return_pattern", "error", 3, 120, "alert"),
        ],
    )
    @pytest.mark.asyncio
    async def test_process_rules_with_various_configs(
        self,
        processor: Mock,
        mock_request: Mock,
        mock_response: Mock,
        rule_type: Literal["usage", "return_pattern", "frequency"],
        pattern: str | None,
        threshold: int,
        window: int,
        action: Literal["ban", "log", "throttle", "alert"],
    ) -> None:
        """Test processing rules with various configurations."""
        rule = BehaviorRule(
            rule_type=rule_type,
            pattern=pattern,
            threshold=threshold,
            window=window,
            action=action,
        )
        route_config = create_route_config_with_rules([rule])

        if rule_type in ["usage", "frequency"]:
            await processor.process_usage_rules(mock_request, "1.2.3.4", route_config)
            processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called()
        else:
            await processor.process_return_rules(
                mock_request, mock_response, "1.2.3.4", route_config
            )
            processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_called()
