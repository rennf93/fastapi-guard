"""
Fixtures for sus_patterns tests.
"""

import os
from collections.abc import AsyncGenerator

import pytest

from guard.handlers.ipinfo_handler import IPInfoManager
from guard.handlers.suspatterns_handler import SusPatternsManager
from guard.models import SecurityConfig

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN", "test_token"))


@pytest.fixture
def security_config_with_detection() -> SecurityConfig:
    """
    SecurityConfig with detection engine settings enabled.

    This fixture provides a config that will initialize all detection
    engine components in SusPatternsManager.
    """
    return SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN, None),
        detection_compiler_timeout=2.0,
        detection_max_content_length=10000,
        detection_preserve_attack_patterns=True,
        detection_semantic_threshold=0.7,
        detection_anomaly_threshold=3.0,
        detection_slow_pattern_threshold=0.1,
        detection_monitor_history_size=1000,
        detection_max_tracked_patterns=1000,
    )


@pytest.fixture
async def sus_patterns_manager_with_detection(
    security_config_with_detection: SecurityConfig,
) -> AsyncGenerator[SusPatternsManager, None]:
    """
    SusPatternsManager instance with detection engine components initialized.

    This fixture ensures that all detection engine components are properly
    initialized for tests that require them.
    """
    # Save original singleton state
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    # Reset singleton to ensure clean state
    SusPatternsManager._instance = None
    SusPatternsManager._config = None

    # Create new instance with detection config
    manager = SusPatternsManager(security_config_with_detection)

    yield manager

    # Clean up after test
    await manager.reset()

    # Restore original singleton state
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config


@pytest.fixture(autouse=True)
async def reset_sus_patterns() -> AsyncGenerator[None, None]:
    """
    Automatically reset SusPatternsManager between tests to prevent contamination.
    """
    # Save original state
    original_instance = SusPatternsManager._instance
    original_config = SusPatternsManager._config

    # If instance exists, save patterns
    original_patterns = None
    original_custom_patterns: set[str] = set()
    if original_instance:
        original_patterns = original_instance.patterns.copy()
        original_custom_patterns = original_instance.custom_patterns.copy()

    yield

    # Reset singleton
    if SusPatternsManager._instance:
        await SusPatternsManager._instance.reset()

    # Restore original state
    SusPatternsManager._instance = original_instance
    SusPatternsManager._config = original_config

    # Restore patterns if instance existed
    if original_instance and original_patterns:
        original_instance.patterns = original_patterns
        original_instance.custom_patterns = original_custom_patterns
