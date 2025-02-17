from guard.sus_patterns import SusPatterns
import pytest
import re
from guard.handlers.redis_handler import RedisManager


@pytest.mark.asyncio
async def test_add_pattern():
    """
    Test adding a custom pattern to SusPatterns.
    """
    sus_patterns = SusPatterns()
    pattern_to_add = r"new_pattern"
    await sus_patterns.add_pattern(pattern_to_add, custom=True)
    assert pattern_to_add in sus_patterns.custom_patterns


@pytest.mark.asyncio
async def test_remove_pattern():
    """
    Test removing a custom pattern from SusPatterns.
    """
    sus_patterns = SusPatterns()
    pattern_to_remove = r"new_pattern"
    await sus_patterns.add_pattern(pattern_to_remove, custom=True)
    await sus_patterns.remove_pattern(pattern_to_remove, custom=True)
    assert pattern_to_remove not in sus_patterns.custom_patterns


@pytest.mark.asyncio
async def test_get_all_patterns():
    """
    Test retrieving all patterns (default and custom) from SusPatterns.
    """
    sus_patterns = SusPatterns()
    default_patterns = sus_patterns.patterns
    custom_pattern = r"custom_pattern"
    await sus_patterns.add_pattern(custom_pattern, custom=True)
    all_patterns = await sus_patterns.get_all_patterns()
    assert custom_pattern in all_patterns
    assert all(pattern in all_patterns for pattern in default_patterns)


@pytest.mark.asyncio
async def test_invalid_pattern_handling():
    with pytest.raises(re.error):
        await SusPatterns.add_pattern(r"invalid(regex", custom=True)


@pytest.mark.asyncio
async def test_remove_nonexistent_pattern():
    sus_patterns = SusPatterns()
    await sus_patterns.remove_pattern(
        "nonexistent",
        custom=True
    )


def test_singleton_behavior():
    instance1 = SusPatterns()
    instance2 = SusPatterns()
    assert instance1 is instance2
    assert instance1.compiled_patterns is instance2.compiled_patterns


@pytest.mark.asyncio
async def test_add_default_pattern():
    """
    Test adding a default pattern to SusPatterns.
    """
    sus_patterns = SusPatterns()
    pattern_to_add = r"default_pattern"
    initial_length = len(sus_patterns.patterns)

    await sus_patterns.add_pattern(pattern_to_add, custom=False)

    assert len(sus_patterns.patterns) == initial_length + 1
    assert pattern_to_add in sus_patterns.patterns


@pytest.mark.asyncio
async def test_remove_default_pattern():
    """
    Test removing a default pattern from SusPatterns.
    """
    SusPatterns._instance = None
    original_patterns = SusPatterns.patterns.copy()

    try:
        sus_patterns = SusPatterns()
        pattern_to_remove = r"default_pattern"

        await sus_patterns.add_pattern(pattern_to_remove, custom=False)

        await sus_patterns.remove_pattern(pattern_to_remove, custom=False)

        assert pattern_to_remove not in sus_patterns.patterns
        assert len(sus_patterns.patterns) == len(original_patterns)

    finally:
        SusPatterns.patterns = original_patterns.copy()
        SusPatterns._instance = None


@pytest.mark.asyncio
async def test_redis_initialization(security_config_redis):
    """Test Redis initialization and pattern caching"""
    # Setup
    redis_handler = RedisManager(security_config_redis)
    await redis_handler.initialize()

    # Pre-populate Redis with some patterns
    test_patterns = "pattern1,pattern2,pattern3"
    await redis_handler.set_key("patterns", "custom", test_patterns)

    # Initialize SusPatterns with Redis
    sus_patterns = SusPatterns()
    await sus_patterns.initialize_redis(redis_handler)

    # Verify patterns were loaded from Redis
    for pattern in test_patterns.split(','):
        assert pattern in sus_patterns.custom_patterns

    await redis_handler.close()


@pytest.mark.asyncio
async def test_redis_pattern_persistence(security_config_redis):
    """Test pattern persistence to Redis"""
    redis_handler = RedisManager(security_config_redis)
    await redis_handler.initialize()

    # Initialize SusPatterns with Redis
    sus_patterns = SusPatterns()
    await sus_patterns.initialize_redis(redis_handler)

    # Add and remove patterns
    test_pattern = "test_pattern"
    await sus_patterns.add_pattern(test_pattern, custom=True)

    # Verify pattern was saved to Redis
    cached_patterns = await redis_handler.get_key("patterns", "custom")
    assert test_pattern in cached_patterns.split(',')

    # Remove pattern
    await sus_patterns.remove_pattern(test_pattern, custom=True)

    # Verify pattern was removed from Redis
    cached_patterns = await redis_handler.get_key("patterns", "custom")
    assert not cached_patterns or test_pattern not in cached_patterns.split(',')

    await redis_handler.close()


@pytest.mark.asyncio
async def test_redis_disabled():
    """Test SusPatterns behavior when Redis is disabled"""
    sus_patterns = SusPatterns()

    # Initialize without Redis
    await sus_patterns.initialize_redis(None)

    # Add and remove patterns should work without Redis
    test_pattern = "test_pattern"
    await sus_patterns.add_pattern(test_pattern, custom=True)
    assert test_pattern in sus_patterns.custom_patterns

    await sus_patterns.remove_pattern(test_pattern, custom=True)
    assert test_pattern not in sus_patterns.custom_patterns


@pytest.mark.asyncio
async def test_get_all_compiled_patterns():
    """Test retrieving all compiled patterns"""
    sus_patterns = SusPatterns()

    # Add a custom pattern
    test_pattern = r"test_pattern\d+"
    await sus_patterns.add_pattern(test_pattern, custom=True)

    # Get all compiled patterns
    compiled_patterns = await sus_patterns.get_all_compiled_patterns()

    # Verify both default and custom patterns are included
    assert len(compiled_patterns) == len(sus_patterns.compiled_patterns) + len(sus_patterns.compiled_custom_patterns)

    # Test pattern matching with compiled patterns
    test_string = "test_pattern123"
    matched = False
    for pattern in compiled_patterns:
        if pattern.search(test_string):
            matched = True
            break
    assert matched
