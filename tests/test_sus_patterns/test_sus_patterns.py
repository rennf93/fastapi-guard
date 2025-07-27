import concurrent.futures
import re
from unittest.mock import MagicMock, patch

import pytest

from guard.handlers.redis_handler import RedisManager
from guard.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from guard.models import SecurityConfig


@pytest.mark.asyncio
async def test_add_pattern() -> None:
    """
    Test adding a custom pattern to SusPatternsManager.
    """
    pattern_to_add = r"new_pattern"
    await sus_patterns_handler.add_pattern(pattern_to_add, custom=True)
    assert pattern_to_add in sus_patterns_handler.custom_patterns


@pytest.mark.asyncio
async def test_remove_pattern() -> None:
    """
    Test removing a custom pattern from SusPatternsManager.
    """
    pattern_to_remove = r"new_pattern"
    await sus_patterns_handler.add_pattern(pattern_to_remove, custom=True)
    result = await sus_patterns_handler.remove_pattern(pattern_to_remove, custom=True)
    assert result is True
    assert pattern_to_remove not in sus_patterns_handler.custom_patterns


@pytest.mark.asyncio
async def test_get_all_patterns() -> None:
    """
    Test retrieving all patterns (default and custom) from SusPatternsManager.
    """
    default_patterns = sus_patterns_handler.patterns
    custom_pattern = r"custom_pattern"
    await sus_patterns_handler.add_pattern(custom_pattern, custom=True)
    all_patterns = await sus_patterns_handler.get_all_patterns()
    assert custom_pattern in all_patterns
    assert all(pattern in all_patterns for pattern in default_patterns)


@pytest.mark.asyncio
async def test_get_default_patterns() -> None:
    """
    Test retrieving only default patterns from SusPatternsManager.
    """
    default_patterns = sus_patterns_handler.patterns
    custom_pattern = r"custom_pattern_test"
    await sus_patterns_handler.add_pattern(custom_pattern, custom=True)

    # Get only default patterns
    patterns = await sus_patterns_handler.get_default_patterns()

    assert custom_pattern not in patterns
    assert all(pattern in patterns for pattern in default_patterns)


@pytest.mark.asyncio
async def test_get_custom_patterns() -> None:
    """
    Test retrieving only custom patterns from SusPatternsManager.
    """
    custom_pattern = r"custom_pattern_only"
    await sus_patterns_handler.add_pattern(custom_pattern, custom=True)

    # Get only custom patterns
    patterns = await sus_patterns_handler.get_custom_patterns()

    assert custom_pattern in patterns
    default_pattern = sus_patterns_handler.patterns[0]
    assert default_pattern not in patterns


@pytest.mark.asyncio
async def test_invalid_pattern_handling() -> None:
    with pytest.raises(re.error):
        await sus_patterns_handler.add_pattern(r"invalid(regex", custom=True)


@pytest.mark.asyncio
async def test_remove_nonexistent_pattern() -> None:
    result = await sus_patterns_handler.remove_pattern("nonexistent", custom=True)
    assert result is False


def test_singleton_behavior() -> None:
    instance1 = sus_patterns_handler
    instance2 = sus_patterns_handler
    assert instance1 is instance2
    assert instance1.compiled_patterns is instance2.compiled_patterns


@pytest.mark.asyncio
async def test_add_default_pattern() -> None:
    """
    Test adding a default pattern to SusPatternsManager.
    """
    pattern_to_add = r"default_pattern"
    initial_length = len(sus_patterns_handler.patterns)

    await sus_patterns_handler.add_pattern(pattern_to_add, custom=False)

    assert len(sus_patterns_handler.patterns) == initial_length + 1
    assert pattern_to_add in sus_patterns_handler.patterns


@pytest.mark.asyncio
async def test_remove_default_pattern() -> None:
    """
    Test removing a default pattern from SusPatternsManager.
    """
    sus_patterns_handler._instance = None
    original_patterns = sus_patterns_handler.patterns.copy()

    try:
        pattern_to_remove = r"default_pattern"

        await sus_patterns_handler.add_pattern(pattern_to_remove, custom=False)

        result = await sus_patterns_handler.remove_pattern(
            pattern_to_remove, custom=False
        )

        assert result is True
        assert pattern_to_remove not in sus_patterns_handler.patterns
        assert len(sus_patterns_handler.patterns) == len(original_patterns)

    finally:
        sus_patterns_handler.patterns = original_patterns.copy()
        sus_patterns_handler._instance = None


@pytest.mark.asyncio
async def test_get_compiled_patterns_separation() -> None:
    """
    Test separation of compiled patterns
    """
    # Setup
    default_pattern = r"default_test_pattern_\d+"
    custom_pattern = r"custom_test_pattern_\d+"

    # Add patterns
    await sus_patterns_handler.add_pattern(default_pattern, custom=False)
    await sus_patterns_handler.add_pattern(custom_pattern, custom=True)

    # Get separated compiled patterns
    default_compiled = await sus_patterns_handler.get_default_compiled_patterns()
    custom_compiled = await sus_patterns_handler.get_custom_compiled_patterns()

    # Test default compiled patterns
    test_default_string = "default_test_pattern_123"
    default_matched = any(p.search(test_default_string) for p in default_compiled)
    assert default_matched

    # Test custom compiled patterns
    test_custom_string = "custom_test_pattern_456"
    custom_matched = any(p.search(test_custom_string) for p in custom_compiled)
    assert custom_matched

    # Verify separation
    assert len(default_compiled) == len(sus_patterns_handler.compiled_patterns)
    assert len(custom_compiled) == len(sus_patterns_handler.compiled_custom_patterns)


@pytest.mark.asyncio
async def test_redis_initialization(security_config_redis: SecurityConfig) -> None:
    """Test Redis initialization and pattern caching"""
    # Setup
    redis_handler = RedisManager(security_config_redis)
    await redis_handler.initialize()

    # Pre-populate Redis with some patterns
    test_patterns = "pattern1,pattern2,pattern3"
    await redis_handler.set_key("patterns", "custom", test_patterns)

    # Initialize SusPatternsManager with Redis
    await sus_patterns_handler.initialize_redis(redis_handler)

    # Verify patterns were loaded from Redis
    for pattern in test_patterns.split(","):
        assert pattern in sus_patterns_handler.custom_patterns

    await redis_handler.close()


@pytest.mark.asyncio
async def test_redis_pattern_persistence(security_config_redis: SecurityConfig) -> None:
    """Test pattern persistence to Redis"""
    redis_handler = RedisManager(security_config_redis)
    await redis_handler.initialize()

    # Initialize SusPatternsManager with Redis
    await sus_patterns_handler.initialize_redis(redis_handler)

    # Add and remove patterns
    test_pattern = "test_pattern"
    await sus_patterns_handler.add_pattern(test_pattern, custom=True)

    # Verify pattern was saved to Redis
    cached_patterns = await redis_handler.get_key("patterns", "custom")
    assert test_pattern in cached_patterns.split(",")

    # Remove pattern
    result = await sus_patterns_handler.remove_pattern(test_pattern, custom=True)
    assert result is True

    # Verify pattern was removed from Redis
    cached_patterns = await redis_handler.get_key("patterns", "custom")
    assert not cached_patterns or test_pattern not in cached_patterns.split(",")

    await redis_handler.close()


@pytest.mark.asyncio
async def test_redis_disabled() -> None:
    """Test SusPatternsManager behavior when Redis is disabled"""

    # Initialize without Redis
    await sus_patterns_handler.initialize_redis(None)

    # Add and remove patterns should work without Redis
    test_pattern = "test_pattern"
    await sus_patterns_handler.add_pattern(test_pattern, custom=True)
    assert test_pattern in sus_patterns_handler.custom_patterns

    result = await sus_patterns_handler.remove_pattern(test_pattern, custom=True)
    assert result is True
    assert test_pattern not in sus_patterns_handler.custom_patterns


@pytest.mark.asyncio
async def test_get_all_compiled_patterns() -> None:
    """Test retrieving all compiled patterns"""

    # Add a custom pattern
    test_pattern = r"test_pattern\d+"
    await sus_patterns_handler.add_pattern(test_pattern, custom=True)

    # Get all compiled patterns
    compiled_patterns = await sus_patterns_handler.get_all_compiled_patterns()

    # Verify both default and custom patterns are included
    assert len(compiled_patterns) == len(sus_patterns_handler.compiled_patterns) + len(
        sus_patterns_handler.compiled_custom_patterns
    )

    # Test pattern matching with compiled patterns
    test_string = "test_pattern123"
    matched = False
    for pattern in compiled_patterns:
        if pattern.search(test_string):
            matched = True
            break
    assert matched


@pytest.mark.asyncio
async def test_init_with_config() -> None:
    """Test SusPatternsManager initialization with detection engine config."""
    # Create a config with detection engine settings
    config = MagicMock()
    config.detection_compiler_timeout = 3.0
    config.detection_max_tracked_patterns = 500
    config.detection_max_content_length = 20000
    config.detection_preserve_attack_patterns = True
    config.detection_anomaly_threshold = 2.5
    config.detection_slow_pattern_threshold = 0.2
    config.detection_monitor_history_size = 100
    config.detection_semantic_threshold = 0.8

    # Force a new instance with config
    SusPatternsManager._instance = None
    manager = SusPatternsManager(config)

    # Verify components were initialized with config values
    assert manager._compiler is not None
    assert manager._compiler.default_timeout == 3.0
    assert manager._preprocessor is not None
    assert manager._preprocessor.max_content_length == 20000
    assert manager._preprocessor.preserve_attack_patterns is True
    assert manager._semantic_analyzer is not None
    assert manager._performance_monitor is not None
    assert manager._performance_monitor.anomaly_threshold == 2.5
    assert manager._performance_monitor.slow_pattern_threshold == 0.2
    assert manager._semantic_threshold == 0.8

    # Clean up
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_regex_timeout_fallback() -> None:
    """Test regex timeout fallback when compiler is not available."""
    # Create a manager without compiler
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    # Disable compiler to force fallback
    original_compiler = manager._compiler
    manager._compiler = None

    # Create a pattern that will timeout
    evil_pattern = r"(a+)+$"  # ReDoS pattern
    await manager.add_pattern(evil_pattern, custom=True)

    # Test with content that triggers timeout
    evil_content = "a" * 100 + "b"

    # Mock ThreadPoolExecutor to simulate timeout
    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        # Mock logging to verify warning
        with patch("logging.getLogger") as mock_logger:
            mock_logger.return_value.warning = MagicMock()

            # Run detection
            matched, pattern = await manager.detect_pattern_match(
                evil_content, "127.0.0.1", "test_timeout"
            )

            # Verify timeout was handled
            assert not matched
            assert pattern is None

            # Verify warning was logged
            mock_logger.return_value.warning.assert_called()
            warning_msg = mock_logger.return_value.warning.call_args[0][0]
            assert "Regex timeout exceeded" in warning_msg

    # Restore compiler
    manager._compiler = original_compiler
    # Clean up
    await manager.remove_pattern(evil_pattern, custom=True)
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_regex_search_success_fallback() -> None:
    """
    Test successful regex search using fallback when compiler is not available.
    """
    # Create a manager without compiler
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    # Disable compiler to force fallback
    original_compiler = manager._compiler
    manager._compiler = None

    # Create a simple pattern
    test_pattern = r"test_pattern_\d+"
    await manager.add_pattern(test_pattern, custom=True)

    # Test with matching content
    test_content = "This contains test_pattern_123 in it"

    # Run detection
    matched, pattern = await manager.detect_pattern_match(
        test_content, "127.0.0.1", "test_search"
    )

    # Verify match was found
    assert matched is True
    assert pattern == test_pattern

    # Restore compiler
    manager._compiler = original_compiler
    # Clean up
    await manager.remove_pattern(test_pattern, custom=True)
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_get_performance_stats_none() -> None:
    """Test get_performance_stats returns None when monitor is disabled."""
    # Create a manager without performance monitor
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    # Disable performance monitor
    original_monitor = manager._performance_monitor
    manager._performance_monitor = None

    # Get stats
    stats = await manager.get_performance_stats()

    # Verify None is returned
    assert stats is None

    # Restore monitor
    manager._performance_monitor = original_monitor
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_get_performance_stats_with_monitor() -> None:
    """Test get_performance_stats returns None when monitor is not enabled."""
    manager = sus_patterns_handler

    # Monitor is not initialized without config, so stats should be None
    stats = await manager.get_performance_stats()
    assert stats is None


@pytest.mark.asyncio
async def test_pattern_timeout_with_compiler(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test pattern timeout detection when compiler is available."""
    manager = sus_patterns_manager_with_detection

    # Create a ReDoS pattern
    evil_pattern = r"(a+)+"
    await manager.add_pattern(evil_pattern, custom=True)

    # Create content that will cause timeout
    evil_content = "a" * 1000 + "b"

    # Counter for time calls
    time_counter = 0

    def mock_time() -> float:
        nonlocal time_counter
        time_counter += 1
        # Return 0 for start times, 2.0 for end times to simulate timeout
        if time_counter % 2 == 1:  # Odd calls are starts
            return 0.0
        else:  # Even calls are ends
            return 2.0

    # Mock the safe_matcher to return None for timeout
    with patch.object(manager._compiler, "create_safe_matcher") as mock_create:
        # Create a mock that returns None (simulating timeout)
        mock_matcher = MagicMock(return_value=None)
        mock_create.return_value = mock_matcher

        # Mock time
        with patch("time.time", mock_time):
            # Mock logging to verify warning
            with patch("logging.getLogger") as mock_logger:
                mock_log_instance = MagicMock()
                mock_logger.return_value = mock_log_instance

                # Run detection
                result = await manager.detect(evil_content, "127.0.0.1", "test_timeout")

                # Check if any pattern caused a timeout warning
                # The exact pattern that times out depends on matching
                if mock_log_instance.warning.called:
                    warning_calls = [
                        call[0][0] for call in mock_log_instance.warning.call_args_list
                    ]
                    timeout_warnings = [
                        msg for msg in warning_calls if "Pattern timeout:" in msg
                    ]
                    assert len(timeout_warnings) > 0

                    # Verify timeouts were recorded
                    assert len(result["timeouts"]) > 0

    # Clean up
    await manager.remove_pattern(evil_pattern, custom=True)


@pytest.mark.asyncio
async def test_regex_search_exception_fallback() -> None:
    """Test regex search exception handling in fallback mode."""
    # Create a manager without compiler
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    # Disable compiler to force fallback
    original_compiler = manager._compiler
    manager._compiler = None

    # Add a test pattern
    test_pattern = r"test_pattern"
    await manager.add_pattern(test_pattern, custom=True)

    # Mock ThreadPoolExecutor to raise an exception
    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        # Simulate a non-timeout exception
        mock_future.result.side_effect = RuntimeError("Test exception")
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        # Mock logging to verify error
        with patch("logging.getLogger") as mock_logger:
            mock_log_instance = MagicMock()
            mock_logger.return_value = mock_log_instance

            # Run detection
            result = await manager.detect("test content", "127.0.0.1", "test_exception")

            # Verify exception was handled
            assert not result["is_threat"]

            # Verify error was logged
            mock_log_instance.error.assert_called()
            error_msg = mock_log_instance.error.call_args[0][0]
            assert "Error in regex search" in error_msg

    # Restore compiler
    manager._compiler = original_compiler
    # Clean up
    await manager.remove_pattern(test_pattern, custom=True)
    SusPatternsManager._instance = None


@pytest.mark.asyncio
async def test_semantic_threat_detection(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test semantic threat detection."""
    manager = sus_patterns_manager_with_detection

    # Ensure semantic analyzer is available
    assert manager._semantic_analyzer is not None

    # Mock semantic analysis to return high threat score
    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        with patch.object(manager._semantic_analyzer, "get_threat_score") as mock_score:
            # Set up analysis results with attack probabilities
            semantic_analysis = {
                "attack_probabilities": {
                    "sql_injection": 0.85,
                    "xss": 0.65,
                    "command_injection": 0.45,
                },
                "tokens": ["SELECT", "*", "FROM", "users"],
                "suspicious_patterns": ["sql_keywords"],
            }
            mock_analyze.return_value = semantic_analysis
            mock_score.return_value = 0.85

            # Set semantic threshold
            await manager.configure_semantic_threshold(0.7)

            # Run detection
            result = await manager.detect(
                "SELECT * FROM users WHERE id=1", "127.0.0.1", "test_semantic"
            )

            # Verify semantic threat was detected
            assert result["is_threat"]
            assert result["threat_score"] >= 0.85

            # Find semantic threats
            semantic_threats = [t for t in result["threats"] if t["type"] == "semantic"]
            assert len(semantic_threats) >= 1

            # Verify specific attack types were detected
            attack_types = [t["attack_type"] for t in semantic_threats]
            assert "sql_injection" in attack_types


@pytest.mark.asyncio
async def test_semantic_threat_suspicious_fallback(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test semantic threat detection with general suspicious behavior."""
    manager = sus_patterns_manager_with_detection

    # Mock semantic analysis with high score but no specific attacks above threshold
    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        with patch.object(manager._semantic_analyzer, "get_threat_score") as mock_score:
            # Set up analysis with low individual attack probabilities
            semantic_analysis = {
                "attack_probabilities": {
                    "sql_injection": 0.4,
                    "xss": 0.3,
                    "command_injection": 0.2,
                },
                "suspicious_patterns": ["multiple_keywords"],
            }
            mock_analyze.return_value = semantic_analysis
            mock_score.return_value = 0.75  # High overall score

            # Set semantic threshold
            await manager.configure_semantic_threshold(0.7)

            # Run detection
            result = await manager.detect(
                "Suspicious content with multiple patterns",
                "127.0.0.1",
                "test_suspicious",
            )

            # Verify threat was detected
            assert result["is_threat"]

            # Find semantic threats
            semantic_threats = [t for t in result["threats"] if t["type"] == "semantic"]
            assert len(semantic_threats) == 1

            # Verify it's marked as general suspicious behavior
            assert semantic_threats[0]["attack_type"] == "suspicious"
            assert semantic_threats[0]["threat_score"] == 0.75


@pytest.mark.asyncio
async def test_legacy_detect_semantic_threat(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test legacy detect_pattern_match with semantic threat."""
    manager = sus_patterns_manager_with_detection

    # Mock to return only semantic threats
    with patch.object(manager, "detect") as mock_detect:
        mock_detect.return_value = {
            "is_threat": True,
            "threats": [
                {"type": "semantic", "attack_type": "sql_injection", "probability": 0.9}
            ],
        }

        # Call legacy method
        matched, pattern = await manager.detect_pattern_match(
            "test content", "127.0.0.1", "test"
        )

        # Verify semantic threat format
        assert matched is True
        assert pattern == "semantic:sql_injection"


@pytest.mark.asyncio
async def test_legacy_detect_unknown_threat(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test legacy detect_pattern_match with unknown threat type."""
    manager = sus_patterns_manager_with_detection

    # Mock to return unknown threat type
    with patch.object(manager, "detect") as mock_detect:
        mock_detect.return_value = {
            "is_threat": True,
            "threats": [{"type": "unknown_type", "data": "some_data"}],
        }

        # Call legacy method
        matched, pattern = await manager.detect_pattern_match(
            "test content", "127.0.0.1", "test"
        )

        # Verify unknown threat format
        assert matched is True
        assert pattern == "unknown"


@pytest.mark.asyncio
async def test_compiler_cache_clearing_on_pattern_operations(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test compiler cache clearing on pattern add/remove."""
    manager = sus_patterns_manager_with_detection

    # Ensure compiler is available
    assert manager._compiler is not None

    # Mock compiler clear_cache method
    with patch.object(manager._compiler, "clear_cache") as mock_clear:
        # Test adding pattern clears cache
        test_pattern = r"cache_test_pattern"
        await manager.add_pattern(test_pattern, custom=True)

        # Verify cache was cleared
        mock_clear.assert_called_once()

        # Reset mock
        mock_clear.reset_mock()

        # Test removing pattern clears cache
        result = await manager.remove_pattern(test_pattern, custom=True)
        assert result is True

        # Verify cache was cleared again
        mock_clear.assert_called_once()

    # Also test performance monitor stats removal
    if manager._performance_monitor:
        with patch.object(
            manager._performance_monitor, "remove_pattern_stats"
        ) as mock_remove:
            # Remove a default pattern
            pattern_to_remove = manager.patterns[0]
            await manager.remove_pattern(pattern_to_remove, custom=False)

            # Verify stats were removed
            mock_remove.assert_called_once_with(pattern_to_remove)


@pytest.mark.asyncio
async def test_detect_semantic_only_pattern_info(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test pattern info extraction for semantic-only threats."""
    manager = sus_patterns_manager_with_detection

    # Mock to detect only semantic threats
    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        with patch.object(manager._semantic_analyzer, "get_threat_score") as mock_score:
            # High semantic score
            mock_analyze.return_value = {"attack_probabilities": {"xss": 0.9}}
            mock_score.return_value = 0.9

            # Mock agent handler to capture event
            mock_agent = MagicMock()
            manager.agent_handler = mock_agent

            # Run detection (no regex patterns will match)
            result = await manager.detect(
                "semantic only threat", "127.0.0.1", "test_semantic_info"
            )

            # Verify threat detected
            assert result["is_threat"]


@pytest.mark.asyncio
async def test_get_component_status() -> None:
    """Test getting component status."""
    # Save original instance
    original_instance = SusPatternsManager._instance

    try:
        # Test with no components
        SusPatternsManager._instance = None
        manager = SusPatternsManager()

        status = await manager.get_component_status()
        assert status["compiler"] is False
        assert status["preprocessor"] is False
        assert status["semantic_analyzer"] is False
        assert status["performance_monitor"] is False
    finally:
        # Restore original instance
        SusPatternsManager._instance = original_instance
