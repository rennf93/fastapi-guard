import re

import pytest

from guard.handlers.redis_handler import RedisManager
from guard.handlers.suspatterns_handler import sus_patterns_handler
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
