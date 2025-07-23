import asyncio
import logging
from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard.handlers.dynamic_rule_handler import DynamicRuleManager
from guard.models import DynamicRules, SecurityConfig


@pytest.fixture
def sample_rules() -> DynamicRules:
    """Create sample dynamic rules for testing."""
    return DynamicRules(
        rule_id="test-rule-123",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["172.16.0.100", "10.0.0.50"],
        ip_whitelist=["192.168.1.200"],
        blocked_countries=["XX", "YY"],
        whitelist_countries=["US", "CA"],
        global_rate_limit=50,
        global_rate_window=30,
        endpoint_rate_limits={"/api/endpoint": (10, 60)},
        blocked_cloud_providers={"aws", "azure"},
        blocked_user_agents=["badbot", "scanner"],
        suspicious_patterns=["../", "SELECT * FROM"],
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        emergency_mode=False,
        emergency_whitelist=[],
        ip_ban_duration=3600,
    )


class TestDynamicRuleManagerInitialization:
    """Test DynamicRuleManager initialization"""

    def test_singleton_pattern(
        self, config: SecurityConfig, cleanup_singleton: Generator[Any, Any, Any]
    ) -> None:
        """Test that DynamicRuleManager follows singleton pattern."""
        # Reset the singleton instance
        DynamicRuleManager._instance = None

        # Create first instance
        instance1 = DynamicRuleManager(config)

        # Create second instance
        instance2 = DynamicRuleManager(config)

        # Both should be the same instance
        assert instance1 is instance2
        assert DynamicRuleManager._instance is instance1

    def test_singleton_preserves_state(self, config: SecurityConfig) -> None:
        """Test that singleton preserves state between calls."""
        # Reset the singleton instance
        DynamicRuleManager._instance = None

        # Create instance and modify state
        instance1 = DynamicRuleManager(config)
        instance1.last_update = 12345.67
        test_rules = MagicMock()
        instance1.current_rules = test_rules

        # Create another instance reference
        instance2 = DynamicRuleManager(config)

        # State should be preserved
        assert instance2.last_update == 12345.67
        assert instance2.current_rules is test_rules


class TestDynamicRuleManagerAgentRedisInit:
    """Test agent and redis initialization"""

    @pytest.mark.asyncio
    async def test_initialize_agent_with_dynamic_rules_enabled(
        self, config: SecurityConfig, mock_agent_handler: AsyncMock
    ) -> None:
        """Test agent initialization when dynamic rules are enabled."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Initialize agent
        await manager.initialize_agent(mock_agent_handler)

        # Verify agent handler is set
        assert manager.agent_handler is mock_agent_handler

        # Verify update task was created
        assert manager.update_task is not None
        assert isinstance(manager.update_task, asyncio.Task)

        # Clean up
        manager.update_task.cancel()
        try:
            await manager.update_task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_initialize_agent_with_dynamic_rules_disabled(
        self, config: SecurityConfig, mock_agent_handler: AsyncMock
    ) -> None:
        """Test agent initialization when dynamic rules are disabled."""
        # Reset singleton
        DynamicRuleManager._instance = None

        # Disable dynamic rules
        config.enable_dynamic_rules = False

        manager = DynamicRuleManager(config)

        # Initialize agent
        await manager.initialize_agent(mock_agent_handler)

        # Verify agent handler is set
        assert manager.agent_handler is mock_agent_handler

        # Verify update task was NOT created
        assert manager.update_task is None

    @pytest.mark.asyncio
    async def test_initialize_agent_prevents_duplicate_tasks(
        self, config: SecurityConfig, mock_agent_handler: AsyncMock
    ) -> None:
        """Test initializing agent multiple times doesn't create duplicate tasks."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Initialize agent first time
        await manager.initialize_agent(mock_agent_handler)
        first_task = manager.update_task

        # Initialize agent second time
        await manager.initialize_agent(mock_agent_handler)
        second_task = manager.update_task

        # Should be the same task
        assert first_task is second_task

        # Clean up
        if manager.update_task:
            manager.update_task.cancel()
            try:
                await manager.update_task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_initialize_redis(
        self, config: SecurityConfig, mock_redis_handler: AsyncMock
    ) -> None:
        """Test redis initialization."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Initialize redis
        await manager.initialize_redis(mock_redis_handler)

        # Verify redis handler is set
        assert manager.redis_handler is mock_redis_handler


class TestDynamicRuleManagerUpdateLoop:
    """Test rule update loop functionality"""

    @pytest.mark.asyncio
    async def test_rule_update_loop_normal_operation(
        self, config: SecurityConfig
    ) -> None:
        """Test the rule update loop during normal operation."""
        # Reset singleton
        DynamicRuleManager._instance = None

        # Use a very short interval for testing
        config.dynamic_rule_interval = 1

        manager = DynamicRuleManager(config)

        # Track update calls
        update_count = 0

        async def mock_update_rules() -> None:
            nonlocal update_count
            update_count += 1
            if update_count >= 2:
                # Stop the test after 2 updates
                return

        with patch.object(manager, "update_rules", mock_update_rules):
            # Create a task to run the update loop
            loop_task = asyncio.create_task(manager._rule_update_loop())

            # Wait a bit for updates to happen
            await asyncio.sleep(2.5)

            # Cancel the task
            loop_task.cancel()

            # Wait for cancellation
            await loop_task

        # Verify updates were called
        assert update_count >= 2

    @pytest.mark.asyncio
    async def test_rule_update_loop_handles_exceptions(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that rule update loop handles exceptions gracefully."""
        # Reset singleton
        DynamicRuleManager._instance = None

        # Set a very short interval for testing
        config.dynamic_rule_interval = 1

        manager = DynamicRuleManager(config)

        # Mock update_rules to raise exception
        call_count = 0

        async def mock_update_rules() -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Test exception")

        with patch.object(manager, "update_rules", mock_update_rules):
            # Create a task to run the update loop
            with caplog.at_level(logging.ERROR):
                loop_task = asyncio.create_task(manager._rule_update_loop())

                # Wait for exception to be logged
                await asyncio.sleep(2.5)

                # Cancel the task
                loop_task.cancel()

                await loop_task

        # Verify exception was logged
        assert "Error in dynamic rule update loop: Test exception" in caplog.text
        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_rule_update_loop_cancellation_logged(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that rule update loop logs cancellation."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Use a mock that sleeps to ensure task starts
        async def mock_update_rules() -> None:
            await asyncio.sleep(
                0.1
            )  # Long enough to ensure cancellation happens during the loop

        # Use patch.object to mock the method
        with patch.object(manager, "update_rules", mock_update_rules):
            # Create task and let it start
            with caplog.at_level(logging.INFO):
                loop_task = asyncio.create_task(manager._rule_update_loop())

                # Wait a tiny bit to ensure loop starts
                await asyncio.sleep(0.01)

                # Cancel the task
                loop_task.cancel()

                await loop_task

        # Verify cancellation was logged
        assert "Dynamic rule update loop cancelled" in caplog.text


class TestDynamicRuleManagerUpdateRules:
    """Test update_rules method"""

    @pytest.mark.asyncio
    async def test_update_rules_disabled(
        self, config: SecurityConfig, mock_agent_handler: AsyncMock
    ) -> None:
        """Test update_rules when dynamic rules are disabled."""
        # Reset singleton
        DynamicRuleManager._instance = None

        config.enable_dynamic_rules = False
        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        await manager.update_rules()

        # Should not fetch rules
        mock_agent_handler.get_dynamic_rules.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_rules_no_agent(self, config: SecurityConfig) -> None:
        """Test update_rules when agent handler is not set."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = None

        await manager.update_rules()

        # Should return early without error
        assert manager.current_rules is None

    @pytest.mark.asyncio
    async def test_update_rules_no_rules_returned(
        self, config: SecurityConfig, mock_agent_handler: AsyncMock
    ) -> None:
        """Test update_rules when agent returns no rules."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Agent returns None
        mock_agent_handler.get_dynamic_rules.return_value = None

        await manager.update_rules()

        # Should not update current rules
        assert manager.current_rules is None
        assert manager.last_update == 0

    @pytest.mark.asyncio
    async def test_update_rules_same_version(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
    ) -> None:
        """Test update_rules when rules haven't changed."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler
        manager.current_rules = sample_rules

        # Agent returns same rules
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules

        await manager.update_rules()

        # Rules should not be re-applied
        assert manager.current_rules is sample_rules
        assert manager.last_update == 0

    @pytest.mark.asyncio
    async def test_update_rules_older_version(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
    ) -> None:
        """Test update_rules when agent returns older version."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Set current rules to version 2
        current_rules = sample_rules.model_copy()
        current_rules.version = 2
        manager.current_rules = current_rules

        # Agent returns version 1
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules

        await manager.update_rules()

        # Should not downgrade
        assert manager.current_rules is not None
        assert manager.current_rules.version == 2
        assert manager.last_update == 0

    @pytest.mark.asyncio
    async def test_update_rules_success(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test successful rule update with new rules."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Mock the internal methods
        with (
            patch.object(manager, "_apply_rules", AsyncMock()) as mock_apply_rules,
            patch.object(
                manager, "_send_rule_applied_event", AsyncMock()
            ) as mock_send_event,
        ):
            # Agent returns new rules
            mock_agent_handler.get_dynamic_rules.return_value = sample_rules

            with caplog.at_level(logging.INFO):
                await manager.update_rules()

            # Verify rules were applied
            mock_apply_rules.assert_called_once_with(sample_rules)

            # Verify rules were cached
            assert manager.current_rules == sample_rules
            assert manager.last_update > 0

            # Verify event was sent
            mock_send_event.assert_called_once_with(sample_rules)

        # Verify logging
        assert (
            f"Applying dynamic rules: {sample_rules.rule_id} v{sample_rules.version}"
            in caplog.text
        )

    @pytest.mark.asyncio
    async def test_update_rules_apply_failure(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test update_rules when _apply_rules fails."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Mock _apply_rules to raise exception
        with (
            patch.object(
                manager,
                "_apply_rules",
                AsyncMock(side_effect=Exception("Apply failed")),
            ),
            patch.object(
                manager, "_send_rule_applied_event", AsyncMock()
            ) as mock_send_event,
        ):
            # Agent returns new rules
            mock_agent_handler.get_dynamic_rules.return_value = sample_rules

            with caplog.at_level(logging.ERROR):
                await manager.update_rules()

            # Verify error was logged
            assert "Failed to update dynamic rules: Apply failed" in caplog.text

            # Rules should not be cached on failure
            assert manager.current_rules is None
            assert manager.last_update == 0

            # Event should not be sent
            mock_send_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_update_rules_different_rule_id(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
    ) -> None:
        """Test update_rules with different rule ID."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Set current rules with different ID
        current_rules = sample_rules.model_copy()
        current_rules.rule_id = "different-rule-456"
        manager.current_rules = current_rules

        # Mock the internal methods
        with (
            patch.object(manager, "_apply_rules", AsyncMock()) as mock_apply_rules,
            patch.object(manager, "_send_rule_applied_event", AsyncMock()),
        ):
            # Agent returns new rules with different ID
            mock_agent_handler.get_dynamic_rules.return_value = sample_rules

            await manager.update_rules()

            # Should apply new rules (different ID)
            mock_apply_rules.assert_called_once_with(sample_rules)
            assert manager.current_rules == sample_rules


class TestDynamicRuleManagerApplyRules:
    """Test _apply_rules method"""

    @pytest.mark.asyncio
    async def test_apply_rules_all_types(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
    ) -> None:
        """Test applying all types of rules."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Mock all sub-methods
        with (
            patch.object(manager, "_apply_ip_bans", AsyncMock()) as mock_ip_bans,
            patch.object(
                manager, "_apply_ip_whitelist", AsyncMock()
            ) as mock_ip_whitelist,
            patch.object(
                manager, "_apply_country_rules", AsyncMock()
            ) as mock_country_rules,
            patch.object(
                manager, "_apply_rate_limit_rules", AsyncMock()
            ) as mock_rate_limit_rules,
            patch.object(
                manager, "_apply_cloud_provider_rules", AsyncMock()
            ) as mock_cloud_provider_rules,
            patch.object(
                manager, "_apply_user_agent_rules", AsyncMock()
            ) as mock_user_agent_rules,
            patch.object(
                manager, "_apply_pattern_rules", AsyncMock()
            ) as mock_pattern_rules,
            patch.object(
                manager, "_apply_feature_toggles", AsyncMock()
            ) as mock_feature_toggles,
            patch.object(
                manager, "_activate_emergency_mode", AsyncMock()
            ) as mock_emergency_mode,
        ):
            # Apply rules
            await manager._apply_rules(sample_rules)

            # Verify all methods were called
            mock_ip_bans.assert_called_once_with(
                sample_rules.ip_blacklist, sample_rules.ip_ban_duration
            )
            mock_ip_whitelist.assert_called_once_with(sample_rules.ip_whitelist)
            mock_country_rules.assert_called_once_with(
                sample_rules.blocked_countries, sample_rules.whitelist_countries
            )
            mock_rate_limit_rules.assert_called_once_with(sample_rules)
            mock_cloud_provider_rules.assert_called_once_with(
                sample_rules.blocked_cloud_providers
            )
            mock_user_agent_rules.assert_called_once_with(
                sample_rules.blocked_user_agents
            )
            mock_pattern_rules.assert_called_once_with(sample_rules.suspicious_patterns)
            mock_feature_toggles.assert_called_once_with(sample_rules)
            mock_emergency_mode.assert_not_called()

    @pytest.mark.asyncio
    async def test_apply_rules_emergency_mode(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
    ) -> None:
        """Test applying rules with emergency mode enabled."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Enable emergency mode
        sample_rules.emergency_mode = True
        sample_rules.emergency_whitelist = ["192.168.1.1", "10.0.0.1"]

        # Mock emergency mode method
        with patch.object(
            manager, "_activate_emergency_mode", AsyncMock()
        ) as mock_emergency_mode:
            await manager._apply_rules(sample_rules)

            # Verify emergency mode was activated
            mock_emergency_mode.assert_called_once_with(
                sample_rules.emergency_whitelist
            )

    @pytest.mark.asyncio
    async def test_apply_rules_partial(
        self, config: SecurityConfig, mock_agent_handler: AsyncMock
    ) -> None:
        """Test applying rules with only some rule types."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Create rules with only some fields
        partial_rules = DynamicRules(
            rule_id="partial-123",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_blacklist=["172.16.0.100"],
            ip_whitelist=[],
            blocked_countries=[],
            whitelist_countries=[],
            global_rate_limit=None,
            global_rate_window=None,
            endpoint_rate_limits={},
            blocked_cloud_providers=set(),
            blocked_user_agents=[],
            suspicious_patterns=[],
            enable_penetration_detection=None,
            enable_ip_banning=None,
            enable_rate_limiting=None,
            emergency_mode=False,
            emergency_whitelist=[],
            ip_ban_duration=3600,
        )

        # Mock methods
        with (
            patch.object(manager, "_apply_ip_bans", AsyncMock()) as mock_ip_bans,
            patch.object(
                manager, "_apply_ip_whitelist", AsyncMock()
            ) as mock_ip_whitelist,
            patch.object(
                manager, "_apply_country_rules", AsyncMock()
            ) as mock_country_rules,
            patch.object(
                manager, "_apply_rate_limit_rules", AsyncMock()
            ) as mock_rate_limit_rules,
            patch.object(
                manager, "_apply_cloud_provider_rules", AsyncMock()
            ) as mock_cloud_provider_rules,
            patch.object(
                manager, "_apply_user_agent_rules", AsyncMock()
            ) as mock_user_agent_rules,
            patch.object(
                manager, "_apply_pattern_rules", AsyncMock()
            ) as mock_pattern_rules,
            patch.object(
                manager, "_apply_feature_toggles", AsyncMock()
            ) as mock_feature_toggles,
        ):
            await manager._apply_rules(partial_rules)

            # Only IP bans should be called
            mock_ip_bans.assert_called_once()
            mock_ip_whitelist.assert_not_called()
            mock_country_rules.assert_not_called()
            mock_rate_limit_rules.assert_not_called()
            mock_cloud_provider_rules.assert_not_called()
            mock_user_agent_rules.assert_not_called()
            mock_pattern_rules.assert_not_called()
            # Feature toggles is always called
            mock_feature_toggles.assert_called_once()

    @pytest.mark.asyncio
    async def test_apply_rules_exception_handling(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test exception handling in _apply_rules."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Mock method to raise exception
        with patch.object(
            manager, "_apply_ip_bans", AsyncMock(side_effect=Exception("IP ban failed"))
        ):
            with caplog.at_level(logging.ERROR):
                with pytest.raises(Exception, match="IP ban failed"):
                    await manager._apply_rules(sample_rules)

        # Verify error was logged
        assert "Failed to apply dynamic rules: IP ban failed" in caplog.text


class TestDynamicRuleManagerIPRules:
    """Test IP ban/whitelist methods"""

    @pytest.mark.asyncio
    async def test_apply_ip_bans_success(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test successful IP ban application."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Mock ip_ban_manager at the import location
        with patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ban_manager:
            mock_ban_manager.ban_ip = AsyncMock()

            ip_list = ["172.16.0.100", "10.0.0.50"]
            duration = 3600

            with caplog.at_level(logging.INFO):
                await manager._apply_ip_bans(ip_list, duration)

            # Verify bans were applied
            assert mock_ban_manager.ban_ip.call_count == 2
            mock_ban_manager.ban_ip.assert_any_call(
                "172.16.0.100", 3600, "dynamic_rule"
            )
            mock_ban_manager.ban_ip.assert_any_call("10.0.0.50", 3600, "dynamic_rule")

            # Verify logging
            assert "Dynamic rule: Banned IP 172.16.0.100 for 3600s" in caplog.text
            assert "Dynamic rule: Banned IP 10.0.0.50 for 3600s" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_ip_bans_with_failures(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test IP ban application with some failures."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Mock ip_ban_manager at the import location
        with patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ban_manager:
            # First call succeeds, second fails
            mock_ban_manager.ban_ip = AsyncMock(
                side_effect=[None, Exception("Ban failed")]
            )

            ip_list = ["172.16.0.100", "10.0.0.50"]
            duration = 3600

            with caplog.at_level(logging.ERROR):
                await manager._apply_ip_bans(ip_list, duration)

            # Verify both were attempted
            assert mock_ban_manager.ban_ip.call_count == 2

            # Verify error was logged
            assert "Failed to ban IP 10.0.0.50: Ban failed" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_ip_whitelist_success(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test successful IP whitelist application."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Mock ip_ban_manager at the import location
        with patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ban_manager:
            mock_ban_manager.unban_ip = AsyncMock()

            ip_list = ["192.168.1.200", "10.0.0.100"]

            with caplog.at_level(logging.INFO):
                await manager._apply_ip_whitelist(ip_list)

            # Verify unbans were applied
            assert mock_ban_manager.unban_ip.call_count == 2
            mock_ban_manager.unban_ip.assert_any_call("192.168.1.200")
            mock_ban_manager.unban_ip.assert_any_call("10.0.0.100")

            # Verify logging
            assert "Dynamic rule: Whitelisted IP 192.168.1.200" in caplog.text
            assert "Dynamic rule: Whitelisted IP 10.0.0.100" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_ip_whitelist_with_failures(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test IP whitelist application with failures."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Mock ip_ban_manager at the import location
        with patch("guard.handlers.ipban_handler.ip_ban_manager") as mock_ban_manager:
            mock_ban_manager.unban_ip = AsyncMock(side_effect=Exception("Unban failed"))

            ip_list = ["192.168.1.200"]

            with caplog.at_level(logging.ERROR):
                await manager._apply_ip_whitelist(ip_list)

            # Verify error was logged
            assert "Failed to whitelist IP 192.168.1.200: Unban failed" in caplog.text


class TestDynamicRuleManagerCountryRules:
    """Test country rules method"""

    @pytest.mark.asyncio
    async def test_apply_country_rules_blocked_only(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test applying only blocked countries."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        blocked = ["XX", "YY"]
        allowed: list[str] = []

        with caplog.at_level(logging.INFO):
            await manager._apply_country_rules(blocked, allowed)

        # Verify config was updated
        assert manager.config.blocked_countries == blocked

        # Verify logging
        assert "Dynamic rule: Blocked countries ['XX', 'YY']" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_country_rules_allowed_only(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test applying only allowed countries."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        blocked: list[str] = []
        allowed = ["US", "CA"]

        with caplog.at_level(logging.INFO):
            await manager._apply_country_rules(blocked, allowed)

        # Verify config was updated
        assert manager.config.whitelist_countries == allowed

        # Verify logging
        assert "Dynamic rule: Whitelisted countries ['US', 'CA']" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_country_rules_both(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test applying both blocked and allowed countries."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        blocked = ["XX", "YY"]
        allowed = ["US", "CA"]

        with caplog.at_level(logging.INFO):
            await manager._apply_country_rules(blocked, allowed)

        # Verify config was updated
        assert manager.config.blocked_countries == blocked
        assert manager.config.whitelist_countries == allowed

        # Verify logging
        assert "Dynamic rule: Blocked countries ['XX', 'YY']" in caplog.text
        assert "Dynamic rule: Whitelisted countries ['US', 'CA']" in caplog.text


class TestDynamicRuleManagerRateLimitRules:
    """Test rate limit rules method"""

    @pytest.mark.asyncio
    async def test_apply_rate_limit_global_only(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test applying only global rate limits."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        rules = DynamicRules(
            rule_id="rate-123",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_blacklist=[],
            ip_whitelist=[],
            blocked_countries=[],
            whitelist_countries=[],
            global_rate_limit=50,
            global_rate_window=30,
            endpoint_rate_limits={},
            blocked_cloud_providers=set(),
            blocked_user_agents=[],
            suspicious_patterns=[],
            enable_penetration_detection=None,
            enable_ip_banning=None,
            enable_rate_limiting=None,
            emergency_mode=False,
            emergency_whitelist=[],
            ip_ban_duration=3600,
        )

        with caplog.at_level(logging.INFO):
            await manager._apply_rate_limit_rules(rules)

        # Verify config was updated
        assert manager.config.rate_limit == 50
        assert manager.config.rate_limit_window == 30

        # Verify logging
        assert "Dynamic rule: Global rate limit 50 per 30s" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_rate_limit_endpoint_only(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test applying only endpoint rate limits."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        rules = DynamicRules(
            rule_id="rate-123",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_blacklist=[],
            ip_whitelist=[],
            blocked_countries=[],
            whitelist_countries=[],
            global_rate_limit=None,
            global_rate_window=None,
            endpoint_rate_limits={"/api/v1": (10, 60), "/api/v2": (20, 60)},
            blocked_cloud_providers=set(),
            blocked_user_agents=[],
            suspicious_patterns=[],
            enable_penetration_detection=None,
            enable_ip_banning=None,
            enable_rate_limiting=None,
            emergency_mode=False,
            emergency_whitelist=[],
            ip_ban_duration=3600,
        )

        with caplog.at_level(logging.INFO):
            await manager._apply_rate_limit_rules(rules)

        # Verify config was updated
        assert manager.config.endpoint_rate_limits == rules.endpoint_rate_limits

        # Verify logging
        assert (
            "Dynamic rule: Applied endpoint-specific rate limits for 2 endpoints"
            in caplog.text
        )
        assert "['/api/v1', '/api/v2']" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_rate_limit_both(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test applying both global and endpoint rate limits."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        rules = DynamicRules(
            rule_id="rate-123",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_blacklist=[],
            ip_whitelist=[],
            blocked_countries=[],
            whitelist_countries=[],
            global_rate_limit=100,
            global_rate_window=60,
            endpoint_rate_limits={"/api/endpoint": (10, 30)},
            blocked_cloud_providers=set(),
            blocked_user_agents=[],
            suspicious_patterns=[],
            enable_penetration_detection=None,
            enable_ip_banning=None,
            enable_rate_limiting=None,
            emergency_mode=False,
            emergency_whitelist=[],
            ip_ban_duration=3600,
        )

        with caplog.at_level(logging.INFO):
            await manager._apply_rate_limit_rules(rules)

        # Verify both were applied
        assert manager.config.rate_limit == 100
        assert manager.config.rate_limit_window == 60
        assert manager.config.endpoint_rate_limits == rules.endpoint_rate_limits


class TestDynamicRuleManagerOtherRules:
    """Test cloud provider, user agent, and pattern rules"""

    @pytest.mark.asyncio
    async def test_apply_cloud_provider_rules(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test applying cloud provider rules."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        providers = {"aws", "azure", "gcp"}

        with caplog.at_level(logging.INFO):
            await manager._apply_cloud_provider_rules(providers)

        # Verify config was updated
        assert manager.config.block_cloud_providers == providers

        # Verify logging
        assert (
            "Dynamic rule: Blocked cloud providers {'aws', 'azure', 'gcp'}"
            in caplog.text
            or "Dynamic rule: Blocked cloud providers {'aws', 'gcp', 'azure'}"
            in caplog.text
            or "Dynamic rule: Blocked cloud providers {'azure', 'aws', 'gcp'}"
            in caplog.text
            or "Dynamic rule: Blocked cloud providers {'azure', 'gcp', 'aws'}"
            in caplog.text
            or "Dynamic rule: Blocked cloud providers {'gcp', 'aws', 'azure'}"
            in caplog.text
            or "Dynamic rule: Blocked cloud providers {'gcp', 'azure', 'aws'}"
            in caplog.text
        )

    @pytest.mark.asyncio
    async def test_apply_user_agent_rules(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test applying user agent rules."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        user_agents = ["badbot", "scanner", "scraper"]

        with caplog.at_level(logging.INFO):
            await manager._apply_user_agent_rules(user_agents)

        # Verify config was updated
        assert manager.config.blocked_user_agents == user_agents

        # Verify logging
        assert (
            "Dynamic rule: Blocked user agents ['badbot', 'scanner', 'scraper']"
            in caplog.text
        )

    @pytest.mark.asyncio
    async def test_apply_pattern_rules(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test applying pattern rules."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        patterns = ["../", "SELECT * FROM", "<script>"]

        # Mock sus_patterns_handler at the import location
        with patch(
            "guard.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_patterns:
            mock_patterns.add_pattern = AsyncMock()

            with caplog.at_level(logging.INFO):
                await manager._apply_pattern_rules(patterns)

            # Verify patterns were added
            assert mock_patterns.add_pattern.call_count == 3
            mock_patterns.add_pattern.assert_any_call("../")
            mock_patterns.add_pattern.assert_any_call("SELECT * FROM")
            mock_patterns.add_pattern.assert_any_call("<script>")

            # Verify logging
            assert (
                "Dynamic rule: Added suspicious patterns "
                "['../', 'SELECT * FROM', '<script>']" in caplog.text
            )


class TestDynamicRuleManagerFeatureToggles:
    """Test feature toggle method"""

    @pytest.mark.asyncio
    async def test_apply_feature_toggles_all_enabled(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test enabling all features."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        rules = DynamicRules(
            rule_id="toggle-123",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_blacklist=[],
            ip_whitelist=[],
            blocked_countries=[],
            whitelist_countries=[],
            global_rate_limit=None,
            global_rate_window=None,
            endpoint_rate_limits={},
            blocked_cloud_providers=set(),
            blocked_user_agents=[],
            suspicious_patterns=[],
            enable_penetration_detection=True,
            enable_ip_banning=True,
            enable_rate_limiting=True,
            emergency_mode=False,
            emergency_whitelist=[],
            ip_ban_duration=3600,
        )

        with caplog.at_level(logging.INFO):
            await manager._apply_feature_toggles(rules)

        # Verify config was updated
        assert manager.config.enable_penetration_detection is True
        assert manager.config.enable_ip_banning is True
        assert manager.config.enable_rate_limiting is True

        # Verify logging
        assert "Dynamic rule: Penetration detection True" in caplog.text
        assert "Dynamic rule: IP banning True" in caplog.text
        assert "Dynamic rule: Rate limiting True" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_feature_toggles_all_disabled(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test disabling all features."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        rules = DynamicRules(
            rule_id="toggle-123",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_blacklist=[],
            ip_whitelist=[],
            blocked_countries=[],
            whitelist_countries=[],
            global_rate_limit=None,
            global_rate_window=None,
            endpoint_rate_limits={},
            blocked_cloud_providers=set(),
            blocked_user_agents=[],
            suspicious_patterns=[],
            enable_penetration_detection=False,
            enable_ip_banning=False,
            enable_rate_limiting=False,
            emergency_mode=False,
            emergency_whitelist=[],
            ip_ban_duration=3600,
        )

        with caplog.at_level(logging.INFO):
            await manager._apply_feature_toggles(rules)

        # Verify config was updated
        assert manager.config.enable_penetration_detection is False
        assert manager.config.enable_ip_banning is False
        assert manager.config.enable_rate_limiting is False

        # Verify logging
        assert "Dynamic rule: Penetration detection False" in caplog.text
        assert "Dynamic rule: IP banning False" in caplog.text
        assert "Dynamic rule: Rate limiting False" in caplog.text

    @pytest.mark.asyncio
    async def test_apply_feature_toggles_none_values(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test with None values (no changes)."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Store original values
        orig_pen = config.enable_penetration_detection
        orig_ban = config.enable_ip_banning
        orig_rate = config.enable_rate_limiting

        rules = DynamicRules(
            rule_id="toggle-123",
            version=1,
            timestamp=datetime.now(timezone.utc),
            ip_blacklist=[],
            ip_whitelist=[],
            blocked_countries=[],
            whitelist_countries=[],
            global_rate_limit=None,
            global_rate_window=None,
            endpoint_rate_limits={},
            blocked_cloud_providers=set(),
            blocked_user_agents=[],
            suspicious_patterns=[],
            enable_penetration_detection=None,
            enable_ip_banning=None,
            enable_rate_limiting=None,
            emergency_mode=False,
            emergency_whitelist=[],
            ip_ban_duration=3600,
        )

        with caplog.at_level(logging.INFO):
            await manager._apply_feature_toggles(rules)

        # Verify config was NOT changed
        assert manager.config.enable_penetration_detection == orig_pen
        assert manager.config.enable_ip_banning == orig_ban
        assert manager.config.enable_rate_limiting == orig_rate

        # Verify no logging
        assert "Dynamic rule: Penetration detection" not in caplog.text
        assert "Dynamic rule: IP banning" not in caplog.text
        assert "Dynamic rule: Rate limiting" not in caplog.text


class TestDynamicRuleManagerEmergencyMode:
    """Test emergency mode method"""

    @pytest.mark.asyncio
    async def test_activate_emergency_mode_with_agent(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test activating emergency mode with agent."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Mock send event
        with patch.object(
            manager, "_send_emergency_event", AsyncMock()
        ) as mock_send_event:
            # Set original threshold
            config.auto_ban_threshold = 10

            whitelist = ["192.168.1.1", "10.0.0.1"]

            with caplog.at_level(logging.WARNING):
                await manager._activate_emergency_mode(whitelist)

            # Verify emergency mode was set
            assert manager.config.emergency_mode is True
            assert manager.config.emergency_whitelist == whitelist
            assert manager.config.auto_ban_threshold == 5  # Halved from 10

            # Verify logging
            assert (
                "[EMERGENCY MODE] ACTIVATED - Enhanced security posture enabled"
                in caplog.text
            )
            assert (
                "[EMERGENCY MODE] Reduced auto-ban threshold from 10 to 5"
                in caplog.text
            )

            # Verify event was sent
            mock_send_event.assert_called_once_with(whitelist)

    @pytest.mark.asyncio
    async def test_activate_emergency_mode_without_agent(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test activating emergency mode without agent."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = None

        # Set original threshold
        config.auto_ban_threshold = 3

        whitelist = ["192.168.1.1"]

        with caplog.at_level(logging.CRITICAL):
            await manager._activate_emergency_mode(whitelist)

        # Verify emergency mode was set
        assert manager.config.emergency_mode is True
        assert manager.config.emergency_whitelist == whitelist
        assert manager.config.auto_ban_threshold == 1  # max(1, 3//2)

        # No event should be sent without agent

    @pytest.mark.asyncio
    async def test_activate_emergency_mode_minimum_threshold(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test emergency mode with very low threshold."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Set very low threshold
        config.auto_ban_threshold = 1

        whitelist: list[str] = []

        with caplog.at_level(logging.WARNING):
            await manager._activate_emergency_mode(whitelist)

        # Verify threshold is still 1 (minimum)
        assert manager.config.auto_ban_threshold == 1

        # Verify logging shows reduction
        assert "[EMERGENCY MODE] Reduced auto-ban threshold from 1 to 1" in caplog.text


class TestDynamicRuleManagerEventSending:
    """Test event sending methods"""

    @pytest.mark.asyncio
    async def test_send_rule_applied_event_success(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
    ) -> None:
        """Test successful rule applied event sending."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        await manager._send_rule_applied_event(sample_rules)

        # Verify event was sent
        mock_agent_handler.send_event.assert_called_once()

        # Check event details
        sent_event = mock_agent_handler.send_event.call_args[0][0]
        assert sent_event.event_type == "dynamic_rule_applied"
        assert sent_event.ip_address == "system"
        assert sent_event.action_taken == "rules_updated"
        assert "Applied dynamic rules" in sent_event.reason
        assert sent_event.metadata["rule_id"] == sample_rules.rule_id
        assert sent_event.metadata["version"] == sample_rules.version
        assert sent_event.metadata["ip_bans"] == len(sample_rules.ip_blacklist)
        assert sent_event.metadata["country_blocks"] == len(
            sample_rules.blocked_countries
        )
        assert sent_event.metadata["emergency_mode"] == sample_rules.emergency_mode

    @pytest.mark.asyncio
    async def test_send_rule_applied_event_no_agent(
        self, config: SecurityConfig, sample_rules: DynamicRules
    ) -> None:
        """Test rule applied event with no agent."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = None

        # Should return early without error
        await manager._send_rule_applied_event(sample_rules)

    @pytest.mark.asyncio
    async def test_send_rule_applied_event_failure(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test rule applied event sending failure."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Make send_event fail
        mock_agent_handler.send_event.side_effect = Exception("Send failed")

        with caplog.at_level(logging.ERROR):
            await manager._send_rule_applied_event(sample_rules)

        # Verify error was logged
        assert "Failed to send rule applied event: Send failed" in caplog.text

    @pytest.mark.asyncio
    async def test_send_emergency_event_success(
        self, config: SecurityConfig, mock_agent_handler: AsyncMock
    ) -> None:
        """Test successful emergency event sending."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        whitelist = ["192.168.1.1", "10.0.0.1"]

        await manager._send_emergency_event(whitelist)

        # Verify event was sent
        mock_agent_handler.send_event.assert_called_once()

        # Check event details
        sent_event = mock_agent_handler.send_event.call_args[0][0]
        assert sent_event.event_type == "emergency_mode_activated"
        assert sent_event.ip_address == "system"
        assert sent_event.action_taken == "emergency_lockdown"
        assert "[EMERGENCY MODE] activated" in sent_event.reason
        assert sent_event.metadata["whitelist_count"] == 2
        assert sent_event.metadata["whitelist"] == whitelist

    @pytest.mark.asyncio
    async def test_send_emergency_event_large_whitelist(
        self, config: SecurityConfig, mock_agent_handler: AsyncMock
    ) -> None:
        """Test emergency event with large whitelist (truncated)."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Create large whitelist
        whitelist = [f"192.168.1.{i}" for i in range(20)]

        await manager._send_emergency_event(whitelist)

        # Check that whitelist was truncated in metadata
        sent_event = mock_agent_handler.send_event.call_args[0][0]
        assert sent_event.metadata["whitelist_count"] == 20
        assert len(sent_event.metadata["whitelist"]) == 10  # Limited to 10

    @pytest.mark.asyncio
    async def test_send_emergency_event_no_agent(self, config: SecurityConfig) -> None:
        """Test emergency event with no agent."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = None

        # Should return early without error
        await manager._send_emergency_event(["192.168.1.1"])

    @pytest.mark.asyncio
    async def test_send_emergency_event_failure(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test emergency event sending failure."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Make send_event fail
        mock_agent_handler.send_event.side_effect = Exception("Send failed")

        with caplog.at_level(logging.ERROR):
            await manager._send_emergency_event(["192.168.1.1"])

        # Verify error was logged
        assert "Failed to send emergency event: Send failed" in caplog.text


class TestDynamicRuleManagerUtilityMethods:
    """Test utility methods"""

    @pytest.mark.asyncio
    async def test_get_current_rules(
        self, config: SecurityConfig, sample_rules: DynamicRules
    ) -> None:
        """Test getting current rules."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Initially None
        assert await manager.get_current_rules() is None

        # Set rules
        manager.current_rules = sample_rules

        # Should return the rules
        assert await manager.get_current_rules() == sample_rules

    @pytest.mark.asyncio
    async def test_force_update(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        sample_rules: DynamicRules,
    ) -> None:
        """Test forcing rule update."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.agent_handler = mock_agent_handler

        # Mock update_rules
        with patch.object(manager, "update_rules", AsyncMock()) as mock_update_rules:
            await manager.force_update()

            # Verify update_rules was called
            mock_update_rules.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_with_task(
        self,
        config: SecurityConfig,
        mock_agent_handler: AsyncMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test stopping manager with active task."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)

        # Create asyncio task that can be cancelled
        async def dummy_task() -> None:
            pass  # pragma: no cover

        # Create and start the task
        manager.update_task = asyncio.create_task(dummy_task())

        with caplog.at_level(logging.INFO):
            await manager.stop()

        # Task should have been cancelled

        # Verify cleanup
        assert manager.update_task is None

    @pytest.mark.asyncio
    async def test_stop_without_task(
        self, config: SecurityConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test stopping manager without active task."""
        # Reset singleton
        DynamicRuleManager._instance = None

        manager = DynamicRuleManager(config)
        manager.update_task = None

        with caplog.at_level(logging.INFO):
            await manager.stop()

        # Should complete without error
        assert manager.update_task is None
        # No log message when there's no task to stop
        assert "Stopped dynamic rule update loop" not in caplog.text


# Cleanup fixture
@pytest.fixture
def cleanup_singleton() -> Generator[Any, Any, Any]:
    """Reset singleton before and after each test."""
    # Reset before test
    DynamicRuleManager._instance = None
    yield
    # Reset after test
    DynamicRuleManager._instance = None
