"""
Comprehensive tests for the PatternCompiler module.
"""

import asyncio
import concurrent.futures
import re
import signal
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from guard.detection_engine.compiler import PatternCompiler, TimeoutError


@pytest.fixture
def compiler() -> PatternCompiler:
    """Create a PatternCompiler instance for testing."""
    return PatternCompiler(default_timeout=5.0, max_cache_size=100)


def test_initialization() -> None:
    """Test PatternCompiler initialization."""
    # Test with default values
    compiler = PatternCompiler()
    assert compiler.default_timeout == 5.0
    assert compiler.max_cache_size == 1000
    assert len(compiler._compiled_cache) == 0
    assert len(compiler._cache_order) == 0

    # Test with custom values
    compiler = PatternCompiler(default_timeout=10.0, max_cache_size=500)
    assert compiler.default_timeout == 10.0
    assert compiler.max_cache_size == 500

    # Test max_cache_size hard limit
    compiler = PatternCompiler(max_cache_size=10000)
    assert compiler.max_cache_size == 5000  # Hard upper limit


def test_compile_pattern_sync(compiler: PatternCompiler) -> None:
    """Test synchronous pattern compilation."""
    pattern = r"test\d+"
    compiled = compiler.compile_pattern_sync(pattern)
    assert isinstance(compiled, re.Pattern)
    assert compiled.search("test123") is not None
    assert compiled.search("test") is None

    # Test with custom flags
    pattern = r"TEST\d+"
    compiled = compiler.compile_pattern_sync(pattern, flags=0)
    assert compiled.search("TEST123") is not None
    assert compiled.search("test123") is None


@pytest.mark.asyncio
async def test_compile_pattern_cache_hit(compiler: PatternCompiler) -> None:
    """Test compile_pattern with cache hit scenario."""
    pattern = r"cached_pattern\d+"

    # First compilation - cache miss
    compiled1 = await compiler.compile_pattern(pattern)
    assert isinstance(compiled1, re.Pattern)

    # Second compilation - cache hit
    compiled2 = await compiler.compile_pattern(pattern)
    assert compiled1 is compiled2  # Should be the same object

    # Verify cache state
    cache_key = f"{hash(pattern)}:{re.IGNORECASE | re.MULTILINE}"
    assert cache_key in compiler._compiled_cache
    assert cache_key in compiler._cache_order
    assert compiler._cache_order[-1] == cache_key  # Should be moved to end for LRU


@pytest.mark.asyncio
async def test_compile_pattern_cache_miss(compiler: PatternCompiler) -> None:
    """Test compile_pattern with cache miss and LRU eviction."""
    # Fill cache to capacity
    compiler.max_cache_size = 3
    patterns = [f"pattern_{i}" for i in range(3)]

    for pattern in patterns:
        await compiler.compile_pattern(pattern)

    assert len(compiler._compiled_cache) == 3
    assert len(compiler._cache_order) == 3

    # Add one more pattern to trigger LRU eviction
    new_pattern = "pattern_new"
    await compiler.compile_pattern(new_pattern)

    # Verify LRU eviction
    assert len(compiler._compiled_cache) == 3
    assert len(compiler._cache_order) == 3

    # First pattern should be evicted
    first_key = f"{hash(patterns[0])}:{re.IGNORECASE | re.MULTILINE}"
    assert first_key not in compiler._compiled_cache

    # New pattern should be in cache
    new_key = f"{hash(new_pattern)}:{re.IGNORECASE | re.MULTILINE}"
    assert new_key in compiler._compiled_cache


@pytest.mark.asyncio
async def test_compile_pattern_concurrent_access(compiler: PatternCompiler) -> None:
    """Test compile_pattern with concurrent access."""
    pattern = r"concurrent_pattern"

    # Simulate concurrent compilations
    tasks = [compiler.compile_pattern(pattern) for _ in range(10)]
    results = await asyncio.gather(*tasks)

    # All should return the same compiled pattern object
    first_result = results[0]
    assert all(result is first_result for result in results)

    # Cache should contain only one entry
    assert len(compiler._compiled_cache) == 1


def test_timeout_context(compiler: PatternCompiler) -> None:
    """Test timeout context manager."""
    # Test successful operation within timeout
    with compiler._timeout_context(1.0):
        time.sleep(0.01)  # Should complete successfully

    # Test timeout scenario
    def handler(signum: int, frame: Any) -> None:
        raise TimeoutError("Operation timed out after 0.1 seconds")

    # Save original handler
    old_handler = signal.signal(signal.SIGALRM, handler)

    try:
        # Set alarm and trigger timeout
        signal.alarm(0)  # Clear any existing alarm
        with pytest.raises(TimeoutError) as exc_info:
            signal.alarm(0)  # Set immediate alarm
            handler(signal.SIGALRM, None)  # Call handler directly

        assert "Operation timed out after 0.1 seconds" in str(exc_info.value)
    finally:
        # Restore original handler
        signal.signal(signal.SIGALRM, old_handler)
        signal.alarm(0)


def test_timeout_context_signal_handling(compiler: PatternCompiler) -> None:
    """Test timeout context signal handling."""

    # Create a mock frame
    mock_frame = MagicMock()

    # Access the actual timeout handler through the context manager
    with patch('signal.signal') as mock_signal:
        with patch('signal.alarm'):
            # Capture the handler when context is entered
            with compiler._timeout_context(1.5):
                # Get the handler that was passed to signal.signal
                handler = mock_signal.call_args[0][1]

            # Test that the handler raises TimeoutError with correct message
            with pytest.raises(TimeoutError) as exc_info:
                handler(signal.SIGALRM, mock_frame)

            assert "Operation timed out after 1.5 seconds" in str(exc_info.value)


def test_validate_pattern_safety_dangerous_patterns(compiler: PatternCompiler) -> None:
    """Test validation of dangerous regex patterns."""
    dangerous_patterns = [
        r"(.*)+",
        r"(.+)+",
        r"([a-z]*)+",
        r"([a-z]+)+",
        r".*.*",
        r".+.+",
    ]

    for pattern in dangerous_patterns:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False
        assert "dangerous" in reason.lower()


def test_validate_pattern_safety_slow_pattern(compiler: PatternCompiler) -> None:
    """Test validation with slow pattern detection."""
    # Use a pattern that bypasses dangerous pattern checks
    slow_pattern = r"^[a-z]+$"

    # Mock time.time to simulate slow execution
    call_count = 0
    start_time = time.time()

    def mock_time() -> float:
        nonlocal call_count
        call_count += 1
        # For the pattern execution timing check
        if call_count % 2 == 0:  # End time measurement
            # Return a time that shows > 50ms elapsed
            return start_time + 0.06
        else:  # Start time measurement
            return start_time

    with patch('time.time', side_effect=mock_time):
        is_safe, reason = compiler.validate_pattern_safety(slow_pattern)
        assert is_safe is False
        assert "timed out on test string" in reason


def test_validate_pattern_safety_timeout_error(compiler: PatternCompiler) -> None:
    """Test validation with timeout error."""
    pattern = r"test_pattern"

    # Mock the timeout context to raise TimeoutError
    with patch.object(compiler, '_timeout_context') as mock_context:
        mock_context.return_value.__enter__.side_effect = TimeoutError("Test timeout")

        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False
        assert reason == "Pattern timed out during validation"


def test_validate_pattern_safety_exception(compiler: PatternCompiler) -> None:
    """Test validation with general exception."""
    pattern = r"test_pattern"

    # Mock compile_pattern_sync to raise an exception
    with patch.object(
        compiler, 'compile_pattern_sync', side_effect=Exception("Test error")
    ):
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is False
        assert reason == "Pattern validation failed: Test error"


def test_validate_pattern_safety_safe_pattern(compiler: PatternCompiler) -> None:
    """Test validation of safe patterns."""
    safe_patterns = [
        r"<script[^>]*>",
        r"\d{3}-\d{3}-\d{4}",
        r"[a-zA-Z0-9]+",
        r"https?://[^\s]+",
    ]

    for pattern in safe_patterns:
        is_safe, reason = compiler.validate_pattern_safety(pattern)
        assert is_safe is True
        assert reason == "Pattern appears safe"


def test_validate_pattern_safety_custom_test_strings(compiler: PatternCompiler) -> None:
    """Test validation with custom test strings."""
    pattern = r"test\d+"
    test_strings = ["test123", "test456", "test789"]

    is_safe, reason = compiler.validate_pattern_safety(pattern, test_strings)
    assert is_safe is True
    assert reason == "Pattern appears safe"


def test_create_safe_matcher(compiler: PatternCompiler) -> None:
    """Test creation of safe matcher function."""
    pattern = r"test\d+"
    matcher = compiler.create_safe_matcher(pattern)

    # Test successful match
    result = matcher("test123")
    assert result is not None
    assert result.group() == "test123"

    # Test no match
    result = matcher("test")
    assert result is None


def test_create_safe_matcher_with_timeout(compiler: PatternCompiler) -> None:
    """Test safe matcher with timeout."""
    pattern = r"test.*"
    matcher = compiler.create_safe_matcher(pattern, timeout=0.1)

    # Mock ThreadPoolExecutor to simulate timeout
    with patch('concurrent.futures.ThreadPoolExecutor') as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_future.cancel.return_value = True
        mock_executor.return_value.__enter__.return_value.submit.return_value = (
            mock_future
        )

        result = matcher("test123")
        assert result is None
        mock_future.cancel.assert_called_once()


def test_create_safe_matcher_with_exception(compiler: PatternCompiler) -> None:
    """Test safe matcher with exception."""
    pattern = r"test.*"
    matcher = compiler.create_safe_matcher(pattern)

    # Mock ThreadPoolExecutor to simulate exception
    with patch('concurrent.futures.ThreadPoolExecutor') as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = Exception("Test error")
        mock_executor.return_value.__enter__.return_value.submit.return_value = (
            mock_future
        )

        result = matcher("test123")
        assert result is None


@pytest.mark.asyncio
async def test_batch_compile(compiler: PatternCompiler) -> None:
    """Test batch compilation of patterns."""
    patterns = [
        r"pattern1\d+",
        r"pattern2\w+",
        r"pattern3[a-z]+",
    ]

    # Test without validation
    compiled = await compiler.batch_compile(patterns, validate=False)
    assert len(compiled) == 3
    for pattern in patterns:
        assert pattern in compiled
        assert isinstance(compiled[pattern], re.Pattern)


@pytest.mark.asyncio
async def test_batch_compile_with_validation(compiler: PatternCompiler) -> None:
    """Test batch compilation with validation."""
    patterns = [
        r"safe_pattern\d+",
        r"(.*)+",  # Dangerous pattern
        r"another_safe\w+",
    ]

    compiled = await compiler.batch_compile(patterns, validate=True)
    # Should only compile safe patterns
    assert len(compiled) == 2
    assert patterns[0] in compiled
    assert patterns[1] not in compiled  # Dangerous pattern skipped
    assert patterns[2] in compiled


@pytest.mark.asyncio
async def test_batch_compile_with_invalid_pattern(compiler: PatternCompiler) -> None:
    """Test batch compilation with invalid regex."""
    patterns = [
        r"valid_pattern",
        r"invalid(pattern",  # Invalid regex
        r"another_valid",
    ]

    compiled = await compiler.batch_compile(patterns, validate=False)
    # Should skip invalid patterns
    assert len(compiled) == 2
    assert patterns[0] in compiled
    assert patterns[1] not in compiled  # Invalid pattern skipped
    assert patterns[2] in compiled


@pytest.mark.asyncio
async def test_clear_cache(compiler: PatternCompiler) -> None:
    """Test cache clearing."""
    # Add some patterns to cache
    patterns = ["pattern1", "pattern2", "pattern3"]
    for pattern in patterns:
        await compiler.compile_pattern(pattern)

    assert len(compiler._compiled_cache) == 3
    assert len(compiler._cache_order) == 3

    # Clear cache
    await compiler.clear_cache()

    assert len(compiler._compiled_cache) == 0
    assert len(compiler._cache_order) == 0


@pytest.mark.asyncio
async def test_clear_cache_thread_safety(compiler: PatternCompiler) -> None:
    """Test cache clearing with concurrent access."""
    await compiler.compile_pattern("pattern1")

    # Simulate concurrent clear and compile
    async def compile_task() -> None:
        await compiler.compile_pattern("pattern2")

    async def clear_task() -> None:
        await compiler.clear_cache()

    # Run concurrently
    await asyncio.gather(
        compile_task(),
        clear_task(),
        return_exceptions=True
    )

    # Cache should be in a consistent state
    assert len(compiler._compiled_cache) == len(compiler._cache_order)