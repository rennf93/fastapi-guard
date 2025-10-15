# guard/handlers/behavior_handler.py
import json
import logging
import re
import time
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import Response

from guard.models import SecurityConfig


class BehaviorRule:
    """Defines a behavioral analysis rule."""

    def __init__(
        self,
        rule_type: Literal["usage", "return_pattern", "frequency"],
        threshold: int,
        window: int = 3600,  # 1 hour default
        pattern: str | None = None,
        action: Literal["ban", "log", "throttle", "alert"] = "log",
        custom_action: Callable | None = None,
    ):
        self.rule_type = rule_type
        self.threshold = threshold
        self.window = window
        self.pattern = pattern
        self.action = action
        self.custom_action = custom_action


class BehaviorTracker:
    """
    Advanced behavioral analysis tracker for detecting suspicious patterns.

    This class can track:
    - Per-endpoint usage patterns
    - Return value frequency analysis
    - Time-based behavioral anomalies
    """

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.logger = logging.getLogger("fastapi_guard.handlers.behavior")
        self.usage_counts: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.return_patterns: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.redis_handler: Any | None = None
        self.agent_handler: Any | None = None

    async def initialize_redis(self, redis_handler: Any) -> None:
        """Initialize Redis connection for distributed tracking."""
        self.redis_handler = redis_handler

    async def initialize_agent(self, agent_handler: Any) -> None:
        """Initialize agent integration."""
        self.agent_handler = agent_handler

    async def track_endpoint_usage(
        self, endpoint_id: str, client_ip: str, rule: BehaviorRule
    ) -> bool:
        """
        Track endpoint usage and return True if threshold exceeded.

        Args:
            endpoint_id: Unique identifier for the endpoint
            client_ip: Client IP address
            rule: Behavior rule to apply

        Returns:
            bool: True if threshold exceeded, False otherwise
        """
        current_time = time.time()
        window_start = current_time - rule.window

        # Redis implementation
        if self.redis_handler:
            key = f"behavior:usage:{endpoint_id}:{client_ip}"

            # Add current timestamp
            await self.redis_handler.set_key(
                "behavior_usage", f"{key}:{current_time}", "1", ttl=rule.window
            )

            # Count entries in window
            pattern = f"behavior_usage:{key}:*"
            keys = await self.redis_handler.keys(pattern)

            # Filter keys within time window
            valid_count = 0
            for key_name in keys:
                try:
                    timestamp = float(key_name.split(":")[-1])
                    if timestamp >= window_start:
                        valid_count += 1
                except (ValueError, IndexError):
                    continue

            return valid_count > rule.threshold

        # In-memory fallback
        timestamps = self.usage_counts[endpoint_id][client_ip]

        # Clean old timestamps
        timestamps[:] = [ts for ts in timestamps if ts >= window_start]

        # Add current timestamp
        timestamps.append(current_time)

        return len(timestamps) > rule.threshold

    async def track_return_pattern(
        self, endpoint_id: str, client_ip: str, response: Response, rule: BehaviorRule
    ) -> bool:
        """
        Track return value patterns and detect anomalies.

        Args:
            endpoint_id: Unique identifier for the endpoint
            client_ip: Client IP address
            response: FastAPI Response object
            rule: Behavior rule with pattern to match

        Returns:
            bool: True if suspicious pattern detected, False otherwise
        """
        if not rule.pattern:
            return False

        current_time = time.time()
        window_start = current_time - rule.window

        # Extract response content for analysis
        pattern_matched = await self._check_response_pattern(response, rule.pattern)

        if not pattern_matched:
            return False

        # Redis implementation
        if self.redis_handler:
            key = f"behavior:return:{endpoint_id}:{client_ip}:{rule.pattern}"

            # Add timestamp for pattern match
            await self.redis_handler.set_key(
                "behavior_returns", f"{key}:{current_time}", "1", ttl=rule.window
            )

            # Count pattern matches in window
            pattern_key = f"behavior_returns:{key}:*"
            keys = await self.redis_handler.keys(pattern_key)

            # Filter keys within time window
            valid_count = 0
            for key_name in keys:
                try:
                    timestamp = float(key_name.split(":")[-1])
                    if timestamp >= window_start:
                        valid_count += 1
                except (ValueError, IndexError):
                    continue

            return valid_count > rule.threshold

        # In-memory fallback
        pattern_key = f"{endpoint_id}:{rule.pattern}"
        timestamps = self.return_patterns[pattern_key][client_ip]

        # Clean old timestamps
        timestamps[:] = [ts for ts in timestamps if ts >= window_start]

        # Add current timestamp
        timestamps.append(current_time)

        return len(timestamps) > rule.threshold

    async def _check_response_pattern(self, response: Response, pattern: str) -> bool:
        """
        Check if response matches the specified pattern.

        Supports:
        - String matching in response body
        - JSONPath for structured data
        - Regex patterns
        - Status code matching
        """
        try:
            # Status code pattern
            if pattern.startswith("status:"):
                expected_status = int(pattern.split(":", 1)[1])
                return response.status_code == expected_status

            # Get response body
            if hasattr(response, "body") and response.body:
                body = response.body
                if isinstance(body, bytes):
                    body_str = body.decode("utf-8")
                else:
                    body_str = str(body)

                # JSON pattern matching
                if pattern.startswith("json:"):
                    json_pattern = pattern.split(":", 1)[1]
                    try:
                        response_json = json.loads(body_str)
                        return self._match_json_pattern(response_json, json_pattern)
                    except json.JSONDecodeError:
                        return False

                # Regex pattern matching
                if pattern.startswith("regex:"):
                    regex_pattern = pattern.split(":", 1)[1]
                    return bool(re.search(regex_pattern, body_str, re.IGNORECASE))

                # Simple string matching
                return pattern.lower() in body_str.lower()

            return False
        except Exception as e:
            self.logger.error(f"Error checking response pattern: {str(e)}")
            return False

    def _parse_pattern(self, pattern: str) -> tuple[str, str] | None:
        """
        Parse pattern into path and expected value.

        Returns:
            Tuple of (path, expected_value) or None if invalid pattern
        """
        if "==" not in pattern:
            return None

        path, expected = pattern.split("==", 1)
        path = path.strip()
        expected = expected.strip().strip("\"'")
        return path, expected

    def _handle_array_match(self, current: Any, part: str, expected: str) -> bool:
        """
        Handle array matching in JSONPath.

        Returns:
            True if any array item matches expected value
        """
        part = part[:-2]  # Remove [] suffix

        if not isinstance(current, dict) or part not in current:
            return False

        current = current[part]
        if not isinstance(current, list):
            return False

        return any(str(item).lower() == expected.lower() for item in current)

    def _traverse_json_path(self, data: Any, path: str) -> Any | None:
        """
        Traverse JSON using dot notation path.

        Returns:
            Value at path or None if path doesn't exist
        """
        current = data
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def _match_json_pattern(self, data: Any, pattern: str) -> bool:
        """
        Match JSONPath-like patterns in response data.

        Examples:
        - "result.status==win"
        - "data.success==true"
        - "items[].type==rare"
        """
        try:
            # Parse the pattern
            parsed = self._parse_pattern(pattern)
            if not parsed:
                return False

            path, expected = parsed

            # Handle array matching
            current = data
            for part in path.split("."):
                if part.endswith("[]"):
                    return self._handle_array_match(current, part, expected)

                # Regular traversal
                if not isinstance(current, dict) or part not in current:
                    return False
                current = current[part]

            # Compare final value
            return str(current).lower() == expected.lower()

        except Exception:
            return False

    def _log_passive_mode_action(
        self, rule: BehaviorRule, client_ip: str, details: str
    ) -> None:
        """Log action that would be taken in passive mode."""
        prefix = "[PASSIVE MODE] "

        if rule.action == "ban":
            self.logger.warning(
                f"{prefix}Would ban IP {client_ip} for behavioral violation: {details}"
            )
        elif rule.action == "log":
            self.logger.warning(f"{prefix}Behavioral anomaly detected: {details}")
        elif rule.action == "throttle":
            self.logger.warning(f"{prefix}Would throttle IP {client_ip}: {details}")
        elif rule.action == "alert":
            self.logger.critical(f"{prefix}ALERT - Behavioral anomaly: {details}")

    async def _execute_ban_action(self, client_ip: str, details: str) -> None:
        """Execute IP ban action."""
        from guard.handlers.ipban_handler import ip_ban_manager

        await ip_ban_manager.ban_ip(client_ip, 3600, "behavioral_violation")
        self.logger.warning(
            f"IP {client_ip} banned for behavioral violation: {details}"
        )

    async def _execute_active_mode_action(
        self, rule: BehaviorRule, client_ip: str, endpoint_id: str, details: str
    ) -> None:
        """Execute action in active mode."""
        # Custom action takes precedence
        if rule.custom_action:
            await rule.custom_action(client_ip, endpoint_id, details)
            return

        # Built-in actions
        if rule.action == "ban":
            await self._execute_ban_action(client_ip, details)
        elif rule.action == "log":
            self.logger.warning(f"Behavioral anomaly detected: {details}")
        elif rule.action == "throttle":
            self.logger.warning(f"Throttling IP {client_ip}: {details}")
        elif rule.action == "alert":
            self.logger.critical(f"ALERT - Behavioral anomaly: {details}")

    async def apply_action(
        self, rule: BehaviorRule, client_ip: str, endpoint_id: str, details: str
    ) -> None:
        """Apply the configured action when a rule is violated."""
        # Send behavioral violation event to agent
        if self.agent_handler:
            await self._send_behavior_event(
                event_type="behavioral_violation",
                ip_address=client_ip,
                action_taken=rule.action
                if not self.config.passive_mode
                else "logged_only",
                reason=f"Behavioral rule violated: {details}",
                endpoint=endpoint_id,
                rule_type=rule.rule_type,
                threshold=rule.threshold,
                window=rule.window,
            )

        # Handle based on mode
        if self.config.passive_mode:
            self._log_passive_mode_action(rule, client_ip, details)
        else:
            await self._execute_active_mode_action(
                rule, client_ip, endpoint_id, details
            )

    async def _send_behavior_event(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """Send behavioral analysis events to agent."""
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=ip_address,
                action_taken=action_taken,
                reason=reason,
                metadata=kwargs,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            # Don't let agent errors break behavioral analysis
            self.logger.error(f"Failed to send behavior event to agent: {e}")
