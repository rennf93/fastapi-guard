# guard/handlers/dynamic_rule_handler.py
import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

from guard.models import DynamicRules, SecurityConfig


class DynamicRuleManager:
    """Manages dynamic rules from SaaS platform."""

    _instance = None
    config: SecurityConfig
    agent_handler: Any = None
    redis_handler: Any = None
    logger: logging.Logger
    last_update: float = 0
    current_rules: DynamicRules | None = None
    update_task: asyncio.Task | None = None

    def __new__(
        cls: type["DynamicRuleManager"], config: SecurityConfig
    ) -> "DynamicRuleManager":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = config
            cls._instance.logger = logging.getLogger(
                "fastapi_guard.handlers.dynamic_rule"
            )
            cls._instance.last_update = 0
            cls._instance.current_rules = None
            cls._instance.update_task = None
        return cls._instance

    async def initialize_agent(self, agent_handler: Any) -> None:
        """Initialize agent integration."""
        self.agent_handler = agent_handler

        # Start background rule update task if dynamic rules are enabled
        if self.config.enable_dynamic_rules and not self.update_task:
            self.update_task = asyncio.create_task(self._rule_update_loop())
            self.logger.info("Started dynamic rule update loop")

    async def initialize_redis(self, redis_handler: Any) -> None:
        """Initialize Redis integration for rule caching."""
        self.redis_handler = redis_handler

    async def _rule_update_loop(self) -> None:
        """Background loop to periodically fetch and apply rules."""
        while True:
            try:
                await self.update_rules()
                await asyncio.sleep(self.config.dynamic_rule_interval)
            except asyncio.CancelledError:
                self.logger.info("Dynamic rule update loop cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in dynamic rule update loop: {e}")
                # Wait a bit before retrying
                await asyncio.sleep(min(60, self.config.dynamic_rule_interval))

    def _should_update_rules(self, rules: DynamicRules) -> bool:
        """Check if rules should be updated based on version."""
        if not self.current_rules:
            return True

        # Only update if rules have changed
        return not (
            rules.rule_id == self.current_rules.rule_id
            and rules.version <= self.current_rules.version
        )

    async def _send_rule_received_event(self, rules: DynamicRules) -> None:
        """Send event when new rules are received."""
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            reason = f"Received updated rules {rules.rule_id} v{rules.version}"

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="dynamic_rule_updated",
                ip_address="system",
                action_taken="rules_received",
                reason=reason,
                metadata={
                    "rule_id": rules.rule_id,
                    "version": rules.version,
                    "previous_version": self.current_rules.version
                    if self.current_rules
                    else 0,
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rule updated event: {e}")

    async def update_rules(self) -> None:
        """Fetch and apply dynamic rules from SaaS platform."""
        if not self.config.enable_dynamic_rules or not self.agent_handler:
            return

        try:
            # Fetch rules from agent
            rules = await self.agent_handler.get_dynamic_rules()
            if not rules:
                return

            # Check if rules should be updated
            if not self._should_update_rules(rules):
                return

            # Notify that rules were received
            await self._send_rule_received_event(rules)

            # Log and apply the rules
            self.logger.info(
                f"Applying dynamic rules: {rules.rule_id} v{rules.version}"
            )
            await self._apply_rules(rules)

            # Cache the rules
            self.current_rules = rules
            self.last_update = time.time()

            # Send completion event
            await self._send_rule_applied_event(rules)

        except Exception as e:
            self.logger.error(f"Failed to update dynamic rules: {e}")

    async def _apply_ip_rules(self, rules: DynamicRules) -> None:
        """Apply IP-related rules (bans and whitelist)."""
        if rules.ip_blacklist:
            await self._apply_ip_bans(rules.ip_blacklist, rules.ip_ban_duration)

        if rules.ip_whitelist:
            await self._apply_ip_whitelist(rules.ip_whitelist)

    async def _apply_blocking_rules(self, rules: DynamicRules) -> None:
        """Apply content and access blocking rules."""
        if rules.blocked_countries or rules.whitelist_countries:
            await self._apply_country_rules(
                rules.blocked_countries, rules.whitelist_countries
            )

        if rules.blocked_cloud_providers:
            await self._apply_cloud_provider_rules(rules.blocked_cloud_providers)

        if rules.blocked_user_agents:
            await self._apply_user_agent_rules(rules.blocked_user_agents)

        if rules.suspicious_patterns:
            await self._apply_pattern_rules(rules.suspicious_patterns)

    async def _apply_rules(self, rules: DynamicRules) -> None:
        """Apply dynamic rules to existing handlers."""
        try:
            # Apply IP-related rules
            await self._apply_ip_rules(rules)

            # Apply blocking rules
            await self._apply_blocking_rules(rules)

            # Apply rate limiting rules
            if rules.global_rate_limit or rules.endpoint_rate_limits:
                await self._apply_rate_limit_rules(rules)

            # Apply feature toggles
            await self._apply_feature_toggles(rules)

            # Handle emergency mode
            if rules.emergency_mode:
                await self._activate_emergency_mode(rules.emergency_whitelist)

        except Exception as e:
            self.logger.error(f"Failed to apply dynamic rules: {e}")
            raise

    async def _apply_ip_bans(self, ip_list: list[str], duration: int) -> None:
        """Apply dynamic IP bans."""
        from guard.handlers.ipban_handler import ip_ban_manager

        for ip in ip_list:
            try:
                await ip_ban_manager.ban_ip(ip, duration, "dynamic_rule")
                self.logger.info(f"Dynamic rule: Banned IP {ip} for {duration}s")
            except Exception as e:
                self.logger.error(f"Failed to ban IP {ip}: {e}")

    async def _apply_ip_whitelist(self, ip_list: list[str]) -> None:
        """Apply dynamic IP whitelist (unban if needed)."""
        from guard.handlers.ipban_handler import ip_ban_manager

        for ip in ip_list:
            try:
                await ip_ban_manager.unban_ip(ip)
                self.logger.info(f"Dynamic rule: Whitelisted IP {ip}")
            except Exception as e:
                self.logger.error(f"Failed to whitelist IP {ip}: {e}")

    async def _apply_country_rules(
        self, blocked: list[str], allowed: list[str]
    ) -> None:
        """Apply dynamic country blocking rules."""
        # Update the global config (this affects future requests)
        if blocked:
            self.config.blocked_countries = blocked
            self.logger.info(f"Dynamic rule: Blocked countries {blocked}")

        if allowed:
            self.config.whitelist_countries = allowed
            self.logger.info(f"Dynamic rule: Whitelisted countries {allowed}")

    async def _apply_rate_limit_rules(self, rules: DynamicRules) -> None:
        """Apply dynamic rate limiting rules."""
        # Update global rate limits
        if rules.global_rate_limit:
            self.config.rate_limit = rules.global_rate_limit
            if rules.global_rate_window:
                self.config.rate_limit_window = rules.global_rate_window
            message = f"Global rate limit {rules.global_rate_limit}"
            details = f"per {rules.global_rate_window}s"
            self.logger.info(f"Dynamic rule: {message} {details}")

        # Endpoint-specific rate limits (agent feature)
        if rules.endpoint_rate_limits:
            self.config.endpoint_rate_limits = rules.endpoint_rate_limits.copy()
            self.logger.info(
                f"Dynamic rule: Applied endpoint-specific rate limits for "
                f"{len(rules.endpoint_rate_limits)} endpoints: "
                f"{list(rules.endpoint_rate_limits.keys())}"
            )

    async def _apply_cloud_provider_rules(self, providers: set[str]) -> None:
        """Apply dynamic cloud provider blocking rules."""
        self.config.block_cloud_providers = providers
        self.logger.info(f"Dynamic rule: Blocked cloud providers {providers}")

    async def _apply_user_agent_rules(self, user_agents: list[str]) -> None:
        """Apply dynamic user agent blocking rules."""
        self.config.blocked_user_agents = user_agents
        self.logger.info(f"Dynamic rule: Blocked user agents {user_agents}")

    async def _apply_pattern_rules(self, patterns: list[str]) -> None:
        """Apply dynamic suspicious pattern rules."""
        from guard.handlers.suspatterns_handler import sus_patterns_handler

        # Add patterns to the existing handler
        for pattern in patterns:
            await sus_patterns_handler.add_pattern(pattern)
        self.logger.info(f"Dynamic rule: Added suspicious patterns {patterns}")

    async def _apply_feature_toggles(self, rules: DynamicRules) -> None:
        """Apply dynamic feature toggle rules."""
        if rules.enable_penetration_detection is not None:
            self.config.enable_penetration_detection = (
                rules.enable_penetration_detection
            )
            details = f"Penetration detection {rules.enable_penetration_detection}"
            self.logger.info(f"Dynamic rule: {details}")

        if rules.enable_ip_banning is not None:
            self.config.enable_ip_banning = rules.enable_ip_banning
            self.logger.info(f"Dynamic rule: IP banning {rules.enable_ip_banning}")

        if rules.enable_rate_limiting is not None:
            self.config.enable_rate_limiting = rules.enable_rate_limiting
            self.logger.info(
                f"Dynamic rule: Rate limiting {rules.enable_rate_limiting}"
            )

    async def _activate_emergency_mode(self, emergency_whitelist: list[str]) -> None:
        """Activate emergency lockdown mode."""
        self.logger.critical(
            "[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled"
        )

        self.config.emergency_mode = True
        self.config.emergency_whitelist = emergency_whitelist

        # Enhanced security: Auto-ban becomes more aggressive
        original_threshold = self.config.auto_ban_threshold
        self.config.auto_ban_threshold = max(1, original_threshold // 2)
        message = "Reduced auto-ban threshold"
        details = f"from {original_threshold} to {self.config.auto_ban_threshold}"
        self.logger.warning(f"[EMERGENCY MODE] {message} {details}")

        # Send critical alert
        if self.agent_handler:
            await self._send_emergency_event(emergency_whitelist)

    async def _send_rule_applied_event(self, rules: DynamicRules) -> None:
        """Send event when rules are applied."""
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="dynamic_rule_applied",
                ip_address="system",
                action_taken="rules_updated",
                reason=f"Applied dynamic rules {rules.rule_id} v{rules.version}",
                metadata={
                    "rule_id": rules.rule_id,
                    "version": rules.version,
                    "ip_bans": len(rules.ip_blacklist),
                    "country_blocks": len(rules.blocked_countries),
                    "emergency_mode": rules.emergency_mode,
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send rule applied event: {e}")

    async def _send_emergency_event(self, whitelist: list[str]) -> None:
        """Send emergency mode activation event."""
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="emergency_mode_activated",
                ip_address="system",
                action_taken="emergency_lockdown",
                reason="[EMERGENCY MODE] activated via dynamic rules",
                metadata={
                    "whitelist_count": len(whitelist),
                    "whitelist": whitelist[:10],  # Limit for logging
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send emergency event: {e}")

    async def get_current_rules(self) -> DynamicRules | None:
        """Get currently applied rules."""
        return self.current_rules

    async def force_update(self) -> None:
        """Force an immediate rule update."""
        await self.update_rules()

    async def stop(self) -> None:
        """Stop the dynamic rule manager."""
        if self.update_task:
            self.update_task.cancel()
            try:
                await self.update_task
            except asyncio.CancelledError:
                pass
            self.update_task = None
            self.logger.info("Stopped dynamic rule update loop")


# Instance
dynamic_rule_manager = DynamicRuleManager
