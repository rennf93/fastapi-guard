import json
import logging
import re
import time
from collections import defaultdict
from collections.abc import Callable
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
        self.logger = logging.getLogger(__name__)
        self.usage_counts: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.return_patterns: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self.redis_handler: Any | None = None

    async def initialize_redis(self, redis_handler: Any) -> None:
        """Initialize Redis connection for distributed tracking."""
        self.redis_handler = redis_handler

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

    def _match_json_pattern(self, data: Any, pattern: str) -> bool:
        """
        Match JSONPath-like patterns in response data.

        Examples:
        - "result.status==win"
        - "data.success==true"
        - "items[].type==rare"
        """
        try:
            if "==" in pattern:
                path, expected = pattern.split("==", 1)
                path = path.strip()
                expected = expected.strip().strip("\"'")

                # Simple dot notation traversal
                current = data
                for part in path.split("."):
                    if part.endswith("[]"):
                        # Array handling
                        part = part[:-2]
                        if isinstance(current, dict) and part in current:
                            current = current[part]
                            if isinstance(current, list):
                                return any(
                                    str(item).lower() == expected.lower()
                                    for item in current
                                )
                    else:
                        if isinstance(current, dict) and part in current:
                            current = current[part]
                        else:
                            return False

                return str(current).lower() == expected.lower()

            return False
        except Exception:
            return False

    async def apply_action(
        self, rule: BehaviorRule, client_ip: str, endpoint_id: str, details: str
    ) -> None:
        """Apply the configured action when a rule is violated."""

        if rule.custom_action:
            await rule.custom_action(client_ip, endpoint_id, details)
            return

        if rule.action == "ban":
            # Import here to avoid circular imports
            from guard.handlers.ipban_handler import ip_ban_manager

            await ip_ban_manager.ban_ip(client_ip, 3600)  # 1 hour ban
            self.logger.warning(
                f"IP {client_ip} banned for behavioral violation: {details}"
            )

        elif rule.action == "log":
            self.logger.warning(f"Behavioral anomaly detected: {details}")

        elif rule.action == "throttle":
            # Could implement stricter rate limiting here
            self.logger.warning(f"Throttling IP {client_ip}: {details}")

        elif rule.action == "alert":
            # Could send webhook/notification here
            self.logger.critical(f"ALERT - Behavioral anomaly: {details}")
