# guard/decorators/behavioral.py
from collections.abc import Callable
from typing import Any, Literal

from guard.decorators.base import BaseSecurityMixin
from guard.handlers.behavior_handler import BehaviorRule


class BehavioralMixin(BaseSecurityMixin):
    """Mixin for behavioral analysis decorators."""

    def usage_monitor(
        self,
        max_calls: int,
        window: int = 3600,  # 1 hour default
        action: Literal["ban", "log", "throttle", "alert"] = "ban",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Monitor endpoint usage per IP and take action if threshold exceeded.

        Args:
            max_calls: Maximum number of calls allowed from same IP
            window: Time window in seconds (default: 1 hour)
            action: Action to take ("ban", "log", "throttle", "alert")

        Example:
            @guard_decorator.usage_monitor(
                max_calls=8,
                window=3600,
                action="ban",
            )
            def sensitive_endpoint():
                return {"data": "sensitive"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)

            rule = BehaviorRule(
                rule_type="usage", threshold=max_calls, window=window, action=action
            )
            route_config.behavior_rules.append(rule)
            return self._apply_route_config(func)

        return decorator

    def return_monitor(
        self,
        pattern: str,
        max_occurrences: int,
        window: int = 86400,  # 24 hours default
        action: Literal["ban", "log", "throttle", "alert"] = "ban",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Monitor return values and detect if same IP gets specific results too often.

        Args:
            pattern: Pattern to match in response (supports various formats)
            max_occurrences: Maximum times pattern can occur for same IP
            window: Time window in seconds (default: 24 hours)
            action: Action to take when threshold exceeded

        Pattern formats:
            - Simple string: "win", "success", "rare_item"
            - JSON path: "json:result.status==win"
            - Regex: "regex:win|victory|success"
            - Status code: "status:200"

        Example:
            @guard_decorator.return_monitor(
                "win",
                max_occurrences=3,
                window=86400,
                action="ban",
            )
            def lootbox_endpoint():
                return {"result": {"status": "win", "item": "rare_sword"}}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)

            rule = BehaviorRule(
                rule_type="return_pattern",
                threshold=max_occurrences,
                window=window,
                pattern=pattern,
                action=action,
            )
            route_config.behavior_rules.append(rule)
            return self._apply_route_config(func)

        return decorator

    def behavior_analysis(
        self, rules: list[BehaviorRule]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Apply multiple behavioral analysis rules to an endpoint.

        Args:
            rules: List of BehaviorRule objects defining analysis rules

        Example:
            rules = [
                BehaviorRule("usage", threshold=10, window=3600),
                BehaviorRule(
                    "return_pattern",
                    threshold=3,
                    pattern="win",
                    window=86400,
                )
            ]
            @guard_decorator.behavior_analysis(rules)
            def complex_endpoint():
                return {"result": "data"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.behavior_rules.extend(rules)
            return self._apply_route_config(func)

        return decorator

    def suspicious_frequency(
        self,
        max_frequency: float,  # requests per second
        window: int = 300,  # 5 minutes
        action: Literal["ban", "log", "throttle", "alert"] = "ban",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Detect suspiciously high frequency of requests to specific endpoint.

        Args:
            max_frequency: Maximum requests per second allowed
            window: Time window to analyze
            action: Action to take when exceeded

        Example:
            @guard_decorator.suspicious_frequency(
                max_frequency=0.1,
                window=300,
            )  # Max 1 request per 10 seconds
            def expensive_operation():
                return {"result": "computed"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            max_calls = int(max_frequency * window)

            rule = BehaviorRule(
                rule_type="frequency",
                threshold=max_calls,
                window=window,
                action=action,
            )
            route_config.behavior_rules.append(rule)
            return self._apply_route_config(func)

        return decorator
