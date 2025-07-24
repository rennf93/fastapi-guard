"""
Test the extended SusPatterns handler with individual components.
"""

import pytest

from guard.handlers.suspatterns_handler import SusPatternsManager


@pytest.mark.asyncio
async def test_component_initialization() -> None:
    """Test that all components are properly initialized."""
    manager = SusPatternsManager()

    # Check all components are initialized
    assert manager._compiler is not None
    assert manager._preprocessor is not None
    assert manager._semantic_analyzer is not None
    assert manager._performance_monitor is not None

    # Check component status
    status = await manager.get_component_status()
    assert status["compiler"] is True
    assert status["preprocessor"] is True
    assert status["semantic_analyzer"] is True
    assert status["performance_monitor"] is True


@pytest.mark.asyncio
async def test_extended_detection() -> None:
    """Test detection with extended components."""
    manager = SusPatternsManager()

    # Test XSS detection
    xss_content = "<script>alert('xss')</script>"
    is_threat, pattern = await manager.detect_pattern_match(
        xss_content, "127.0.0.1", "test"
    )
    assert is_threat is True
    assert pattern is not None

    # Test SQL injection with preprocessing
    sql_content = "SELECT%20*%20FROM%20users"  # URL encoded
    is_threat, pattern = await manager.detect_pattern_match(
        sql_content, "127.0.0.1", "test"
    )
    assert is_threat is True



@pytest.mark.asyncio
async def test_performance_monitoring() -> None:
    """Test that performance monitoring is working."""
    manager = SusPatternsManager()

    # Run some detections
    test_contents = [
        "normal content",
        "<script>alert(1)</script>",
        "SELECT * FROM users",
    ]

    for content in test_contents:
        await manager.detect_pattern_match(content, "127.0.0.1", "test")

    # Get performance stats
    stats = await manager.get_performance_stats()
    assert stats is not None
    assert "summary" in stats
    assert stats["summary"]["total_executions"] >= 3

    # Check for overall_detection pattern
    assert stats["summary"]["total_patterns"] >= 1


@pytest.mark.asyncio
async def test_semantic_threshold_configuration() -> None:
    """Test semantic threshold configuration."""
    manager = SusPatternsManager()

    # Configure threshold
    await manager.configure_semantic_threshold(0.5)
    assert manager._semantic_threshold == 0.5

    # Test edge cases
    await manager.configure_semantic_threshold(2.0)  # Above max
    assert manager._semantic_threshold == 1.0

    await manager.configure_semantic_threshold(-1.0)  # Below min
    assert manager._semantic_threshold == 0.0


@pytest.mark.asyncio
async def test_compiler_timeout_protection() -> None:
    """Test that compiler provides timeout protection."""
    manager = SusPatternsManager()

    # Test with a potentially slow pattern
    # The compiler should protect against ReDoS
    slow_pattern_content = "a" * 1000 + "b"

    # This should complete without hanging
    is_threat, pattern = await manager.detect_pattern_match(
        slow_pattern_content, "127.0.0.1", "test"
    )
    # Result doesn't matter, just that it completes


@pytest.mark.asyncio
async def test_preprocessor_normalization() -> None:
    """Test content preprocessing normalization."""
    manager = SusPatternsManager()

    # Test various encoding bypasses
    encoded_attacks = [
        "%3Cscript%3E",  # URL encoded
        "&#60;script&#62;",  # HTML entities
        "\\u003cscript\\u003e",  # Unicode escape
    ]

    for encoded in encoded_attacks:
        is_threat, pattern = await manager.detect_pattern_match(
            encoded, "127.0.0.1", "test"
        )
        # Preprocessor should normalize these to detect the attack
        assert is_threat is True