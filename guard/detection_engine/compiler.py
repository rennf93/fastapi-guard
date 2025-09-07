# guard/detection_engine/compiler.py
import asyncio
import re
import time
from collections.abc import Callable


class TimeoutError(Exception):
    """Raised when a pattern matching operation times out."""

    pass


class PatternCompiler:
    """
    Compiles and validates regex patterns for ReDoS safety.

    This class provides utilities for creating timeout-protected pattern
    matchers and validating patterns for potential ReDoS vulnerabilities.
    """

    MAX_CACHE_SIZE = 1000

    def __init__(self, default_timeout: float = 5.0, max_cache_size: int = 1000):
        """
        Initialize the PatternCompiler.

        Args:
            default_timeout: Default timeout in seconds for pattern matching
            max_cache_size: Maximum number of compiled patterns to cache
        """
        self.default_timeout = default_timeout
        self.max_cache_size = min(max_cache_size, 5000)  # Hard upper limit
        self._compiled_cache: dict[str, re.Pattern] = {}
        self._cache_order: list[str] = []  # Track insertion order for LRU
        self._lock = asyncio.Lock()  # Thread safety for cache operations

    async def compile_pattern(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        """
        Compile a regex pattern with caching (thread-safe).

        Args:
            pattern: The regex pattern to compile
            flags: Regex compilation flags

        Returns:
            Compiled regex pattern

        Raises:
            re.error: If the pattern is invalid
        """
        # Sanitize cache key to prevent injection
        cache_key = f"{hash(pattern)}:{flags}"

        # Fast path: check cache without lock
        if cache_key in self._compiled_cache:
            async with self._lock:
                # Double-check inside lock
                if cache_key in self._compiled_cache:
                    # Move to end for LRU
                    self._cache_order.remove(cache_key)
                    self._cache_order.append(cache_key)
                    return self._compiled_cache[cache_key]

        # Compile and cache with lock
        async with self._lock:
            # Check again in case another coroutine added it
            if cache_key not in self._compiled_cache:
                # Enforce cache size limit (LRU eviction)
                if len(self._compiled_cache) >= self.max_cache_size:
                    oldest_key = self._cache_order.pop(0)
                    del self._compiled_cache[oldest_key]

                self._compiled_cache[cache_key] = re.compile(pattern, flags)
                self._cache_order.append(cache_key)

            return self._compiled_cache[cache_key]

    def compile_pattern_sync(
        self, pattern: str, flags: int = re.IGNORECASE | re.MULTILINE
    ) -> re.Pattern:
        """
        Synchronous version of compile_pattern for backward compatibility.

        Args:
            pattern: The regex pattern to compile
            flags: Regex compilation flags

        Returns:
            Compiled regex pattern

        Raises:
            re.error: If the pattern is invalid
        """
        # For sync usage, just compile without caching to avoid async complexity
        return re.compile(pattern, flags)

    def validate_pattern_safety(
        self, pattern: str, test_strings: list[str] | None = None
    ) -> tuple[bool, str]:
        """
        Validate if a pattern is safe from ReDoS attacks.

        Args:
            pattern: The regex pattern to validate
            test_strings: Optional test strings to check against

        Returns:
            Tuple of (is_safe, reason)
        """
        # Check for dangerous patterns
        dangerous_patterns = [
            r"\(\.\*\)\+",  # (.*)+
            r"\(\.\+\)\+",  # (.+)+
            r"\([^)]*\*\)\+",  # Nested quantifiers
            r"\([^)]*\+\)\+",  # Nested quantifiers
            r"(?:\.\*){2,}",  # Multiple greedy quantifiers
            r"(?:\.\+){2,}",  # Multiple greedy quantifiers
        ]

        for dangerous in dangerous_patterns:
            if re.search(dangerous, pattern):
                return False, f"Pattern contains dangerous construct: {dangerous}"

        # If no test strings provided, generate some
        if test_strings is None:
            test_strings = [
                "a" * 10,
                "a" * 100,
                "a" * 1000,
                "x" * 50 + "y" * 50,
                "<" * 100 + ">" * 100,
            ]

        # Test pattern performance using thread-based timeout
        try:
            compiled = self.compile_pattern_sync(pattern)
            import concurrent.futures

            for test_str in test_strings:
                start_time = time.time()

                def _search(text: str = test_str) -> re.Match | None:
                    return compiled.search(text)

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(_search)
                    try:
                        future.result(timeout=0.1)  # 100ms timeout for testing
                    except concurrent.futures.TimeoutError:
                        return (
                            False,
                            f"Pattern timed out on test string of length "
                            f"{len(test_str)}",
                        )

                elapsed = time.time() - start_time
                if elapsed > 0.05:  # 50ms threshold
                    return (
                        False,
                        f"Pattern timed out on test string of length {len(test_str)}",
                    )
        except Exception as e:
            return False, f"Pattern validation failed: {str(e)}"

        return True, "Pattern appears safe"

    def create_safe_matcher(
        self, pattern: str, timeout: float | None = None
    ) -> Callable[[str], re.Match | None]:
        """
        Create a timeout-protected pattern matcher.

        Args:
            pattern: The regex pattern to match
            timeout: Optional timeout override (uses default if None)

        Returns:
            A function that safely matches the pattern with timeout protection
        """
        compiled = self.compile_pattern_sync(pattern)
        match_timeout = timeout or self.default_timeout

        def safe_match(text: str) -> re.Match | None:
            """
            Safely match text against the pattern with timeout protection.

            Args:
                text: The text to match against

            Returns:
                Match object if found, None otherwise
            """
            # Use thread-based timeout instead of signal-based
            import concurrent.futures

            def _search() -> re.Match | None:
                return compiled.search(text)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_search)
                try:
                    return future.result(timeout=match_timeout)
                except concurrent.futures.TimeoutError:
                    # Attempt to cancel the thread
                    future.cancel()
                    return None
                except Exception:
                    # Don't leak exceptions
                    return None

        return safe_match

    async def batch_compile(
        self, patterns: list[str], validate: bool = True
    ) -> dict[str, re.Pattern]:
        """
        Compile multiple patterns with optional validation.

        Args:
            patterns: List of regex patterns
            validate: Whether to validate patterns for ReDoS safety

        Returns:
            Dictionary mapping patterns to compiled regex objects
        """
        compiled_patterns = {}
        for pattern in patterns:
            if validate:
                is_safe, reason = self.validate_pattern_safety(pattern)
                if not is_safe:
                    # Skip unsafe patterns or handle as needed
                    continue
            try:
                compiled_patterns[pattern] = await self.compile_pattern(pattern)
            except re.error:
                # Skip invalid patterns
                continue
        return compiled_patterns

    async def clear_cache(self) -> None:
        """Clear the compiled pattern cache (thread-safe)."""
        async with self._lock:
            self._compiled_cache.clear()
            self._cache_order.clear()
