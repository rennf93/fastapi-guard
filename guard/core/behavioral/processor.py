# guard/core/behavioral/processor.py
from fastapi import Request, Response

from guard.core.behavioral.context import BehavioralContext
from guard.decorators.base import RouteConfig


class BehavioralProcessor:
    """Handles behavioral rule processing operations."""

    def __init__(self, context: BehavioralContext) -> None:
        """
        Initialize the BehavioralProcessor.

        Args:
            context: Behavioral context with config, logger, and dependencies
        """
        self.context = context

    async def process_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> None:
        """Process behavioral usage rules from decorators before request processing."""
        if not self.context.guard_decorator:
            return

        endpoint_id = self.get_endpoint_id(request)
        for rule in route_config.behavior_rules:
            if rule.rule_type in ["usage", "frequency"]:
                behavior_tracker = self.context.guard_decorator.behavior_tracker
                threshold_exceeded = await behavior_tracker.track_endpoint_usage(
                    endpoint_id, client_ip, rule
                )
                if threshold_exceeded:
                    details = f"{rule.threshold} calls in {rule.window}s"
                    message = f"Behavioral {rule.rule_type}"
                    reason = "threshold exceeded"

                    # Send decorator violation event for behavioral rule violation
                    await self.context.event_bus.send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="behavioral_action_triggered",
                        reason=f"{message} {reason}: {details}",
                        decorator_type="behavioral",
                        violation_type=rule.rule_type,
                        threshold=rule.threshold,
                        window=rule.window,
                        action=rule.action,
                        endpoint_id=endpoint_id,
                    )

                    await self.context.guard_decorator.behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Usage threshold exceeded: {details}",
                    )

    async def process_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        """Process behavioral return pattern rules from decorators after response."""
        if not self.context.guard_decorator:
            return

        endpoint_id = self.get_endpoint_id(request)
        for rule in route_config.behavior_rules:
            if rule.rule_type == "return_pattern":
                behavior_tracker = self.context.guard_decorator.behavior_tracker
                pattern_detected = await behavior_tracker.track_return_pattern(
                    endpoint_id, client_ip, response, rule
                )
                if pattern_detected:
                    details = f"{rule.threshold} for '{rule.pattern}' in {rule.window}s"

                    # Send decorator violation event for return pattern violation
                    await self.context.event_bus.send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="behavioral_action_triggered",
                        reason=f"Return pattern threshold exceeded: {details}",
                        decorator_type="behavioral",
                        violation_type="return_pattern",
                        threshold=rule.threshold,
                        window=rule.window,
                        pattern=rule.pattern,
                        action=rule.action,
                        endpoint_id=endpoint_id,
                    )

                    await self.context.guard_decorator.behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Return pattern threshold exceeded: {details}",
                    )

    def get_endpoint_id(self, request: Request) -> str:
        """Generate unique endpoint identifier."""
        if hasattr(request, "scope") and "route" in request.scope:
            route = request.scope["route"]
            if hasattr(route, "endpoint"):
                # This is an internal identifier for tracking, not returned to users.
                # Values come from Python introspection (module,
                # qualname), not from user input.
                # nosemgrep
                return f"{route.endpoint.__module__}.{route.endpoint.__qualname__}"
        return f"{request.method}:{request.url.path}"
