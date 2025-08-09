# tests/test_agent/test_models_agent_integration.py
from unittest.mock import MagicMock

import pytest

from guard.models import SecurityConfig


class TestSecurityConfigAgentIntegration:
    """Test SecurityConfig agent-related functionality."""

    def test_agent_config_validation_missing_api_key(self) -> None:
        """Test validation error when enable_agent is True but api_key is missing."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            SecurityConfig(
                enable_agent=True,
                agent_api_key=None,  # Missing API key
            )

        assert "agent_api_key is required when enable_agent is True" in str(
            exc_info.value
        )

    def test_agent_config_validation_dynamic_rules_without_agent(self) -> None:
        """
        Test validation error when enable_dynamic_rules is True but agent is disabled.
        """
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            SecurityConfig(
                enable_agent=False,  # Agent not enabled
                enable_dynamic_rules=True,  # But dynamic rules enabled
                agent_api_key="test-key",
            )

        assert "enable_agent must be True when enable_dynamic_rules is True" in str(
            exc_info.value
        )

    def test_to_agent_config_returns_none_when_disabled(self) -> None:
        """Test to_agent_config returns None when agent is disabled."""
        config = SecurityConfig(
            enable_agent=False,
            agent_api_key="test-key",
        )

        result = config.to_agent_config()
        assert result is None

    def test_to_agent_config_returns_none_when_no_api_key(self) -> None:
        """Test to_agent_config returns None when api_key is missing."""
        # Create a config with agent disabled first to bypass validation
        config = SecurityConfig(
            enable_agent=False,
        )
        # Then enable agent but keep api_key as None
        config.enable_agent = True
        config.agent_api_key = None

        result = config.to_agent_config()
        assert result is None

    def test_to_agent_config_success(self) -> None:
        """Test to_agent_config returns AgentConfig when properly configured."""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-api-key",
            agent_endpoint="https://test.example.com",
            agent_project_id="test-project",
            agent_buffer_size=200,
            agent_flush_interval=60,
            agent_enable_events=True,
            agent_enable_metrics=False,
            agent_timeout=45,
            agent_retry_attempts=5,
        )

        # The to_agent_config method returns an AgentConfig object
        # In test environment with mocks, we just verify it returns something
        result = config.to_agent_config()

        # Due to the mocking in conftest.py, we can't assert on the actual values
        # but we can verify that the method returns a non-None value when
        # agent is enabled with an API key
        assert result is not None

    def test_to_agent_config_import_error(self) -> None:
        """Test to_agent_config returns None when guard_agent is not installed."""
        import sys

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-api-key",
        )

        # Temporarily remove guard_agent from sys.modules to simulate import error
        original_module = sys.modules.get("guard_agent")
        if "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]

        # Mock the import to raise ImportError
        mock_module = MagicMock()
        mock_module.AgentConfig.side_effect = ImportError(
            "No module named 'guard_agent'"
        )
        sys.modules["guard_agent"] = mock_module

        try:
            result = config.to_agent_config()
            assert result is None
        finally:
            # Restore original module
            if original_module:
                sys.modules["guard_agent"] = original_module
            elif "guard_agent" in sys.modules:  # pragma: no cover
                del sys.modules["guard_agent"]

    def test_agent_config_with_all_defaults(self) -> None:
        """Test agent configuration with all default values."""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
        )

        # Check defaults
        assert config.agent_endpoint == "https://api.fastapi-guard.com"
        assert config.agent_project_id is None
        assert config.agent_buffer_size == 100
        assert config.agent_flush_interval == 30
        assert config.agent_enable_events is True
        assert config.agent_enable_metrics is True
        assert config.agent_timeout == 30
        assert config.agent_retry_attempts == 3
        assert config.enable_dynamic_rules is False
        assert config.dynamic_rule_interval == 300

    def test_emergency_mode_defaults(self) -> None:
        """Test emergency mode and related fields have correct defaults."""
        config = SecurityConfig()

        assert config.emergency_mode is False
        assert config.emergency_whitelist == []
        assert config.endpoint_rate_limits == {}

    def test_valid_agent_and_dynamic_rules_config(self) -> None:
        """Test valid configuration with both agent and dynamic rules enabled."""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_dynamic_rules=True,
            dynamic_rule_interval=600,
        )

        assert config.enable_agent is True
        assert config.enable_dynamic_rules is True
        assert config.dynamic_rule_interval == 600
