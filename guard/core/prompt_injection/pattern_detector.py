# guard/core/prompt_injection/pattern_detector.py
import re

from guard.core.prompt_injection.pattern_manager import PatternManager


class PatternDetector:
    """
    Detects prompt injection attempts using regex pattern matching.

    Provides fast, zero-dependency detection of common injection patterns
    including role-switching, instruction manipulation, and special formatting.

    Uses PatternManager for flexible pattern management with categorization,
    weights, and runtime control.

    IMPORTANT: All patterns are defined in pattern_library.py via get_default_patterns().
    To add new patterns, edit pattern_library.py, NOT this file.
    """

    def __init__(
        self,
        sensitivity: float = 0.5,  # Default 0.5 = strict mode (block on any match)
        custom_patterns: list[str] | None = None,
        pattern_manager: "PatternManager | None" = None,
    ) -> None:
        """
        Initialize the pattern detector.

        Args:
            sensitivity: Detection sensitivity (0.0-1.0).
                        Lower = more strict (more false positives).
                        Higher = more permissive (more false negatives).
                        Default 0.5 = strict mode (block on ANY pattern match).
            custom_patterns: Additional regex patterns to add to defaults.
            pattern_manager: Optional PatternManager. If not provided, loads
                           patterns from pattern_library.get_default_patterns().
        """
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        self.custom_patterns = custom_patterns or []

        # Always use PatternManager for consistent behavior
        if pattern_manager:
            self.pattern_manager = pattern_manager
        else:
            # Load patterns from pattern_library.py (single source of truth)
            self.pattern_manager = self._create_default_pattern_manager()

    def _create_default_pattern_manager(self) -> "PatternManager":
        """
        Create a PatternManager with default patterns from pattern_library.py.

        Loads all patterns defined in pattern_library.get_default_patterns()
        and adds any custom patterns provided during initialization.
        """
        from guard.core.prompt_injection.pattern_library import (
            create_default_pattern_manager,
        )
        from guard.core.prompt_injection.pattern_types import (
            InjectionPattern,
            PatternCategory,
        )

        # Load default patterns from pattern_library.py (single source of truth)
        manager = create_default_pattern_manager()

        # Add any custom patterns provided during initialization
        for idx, pattern_str in enumerate(self.custom_patterns):
            try:
                # Create a simple InjectionPattern for custom patterns
                custom_pattern = InjectionPattern(
                    pattern_id=f"custom_pattern_{idx}",
                    pattern=pattern_str,
                    category=PatternCategory.INSTRUCTION_OVERRIDE,  # Default category
                    weight=1.0,
                    description=f"Custom pattern: {pattern_str[:50]}...",
                    confidence=0.8,  # Moderate confidence for custom patterns
                )
                manager.add_pattern(custom_pattern, persist=False)
            except (ValueError, re.error):
                # Skip invalid patterns
                continue

        return manager

    def is_suspicious(self, text: str) -> bool:
        """
        Check if text contains suspicious patterns indicating injection attempt.

        Uses PatternManager for weighted, categorized threat scoring.

        Args:
            text: Input text to analyze.

        Returns:
            True if suspicious patterns detected, False otherwise.
        """
        if not text:
            return False

        # Get all enabled patterns
        patterns = self.pattern_manager.get_all_patterns(enabled_only=True)

        if not patterns:
            return False

        # Calculate weighted threat score
        total_score = 0.0
        match_count = 0

        for pattern in patterns:
            matches = pattern.match(text)
            if matches:
                match_count += len(matches)
                # Add weighted score: category weight * pattern weight * confidence
                total_score += pattern.get_score() * len(matches)

        # No matches = not suspicious
        if match_count == 0:
            return False

        # For strict modes (sensitivity <= 0.5), block on ANY match
        # This makes pattern detection the PRIMARY blocker for malicious prompts
        if self.sensitivity <= 0.5 and match_count > 0:
            return True

        # For permissive modes (> 0.5), use weighted scoring
        # Calculate threshold based on sensitivity
        # Lower sensitivity = lower threshold = easier to trigger
        # Base threshold is average score per match
        avg_score_per_match = total_score / match_count if match_count > 0 else 0

        # Threshold calculation:
        # sensitivity 0.6 → threshold 40
        # sensitivity 0.7 → threshold 30
        # sensitivity 0.8 → threshold 20
        # sensitivity 0.9 → threshold 10
        threshold = (1.0 - self.sensitivity) * 100

        return avg_score_per_match >= threshold

    def get_matched_patterns(self, text: str) -> list[str]:
        """
        Get list of pattern descriptions that matched the text.

        Useful for debugging and logging which patterns triggered.

        Args:
            text: Input text to analyze.

        Returns:
            List of matched pattern IDs with descriptions.
        """
        if not text:
            return []

        matched: list[str] = []
        patterns = self.pattern_manager.get_all_patterns(enabled_only=True)

        for pattern in patterns:
            if pattern.match(text):
                # Return pattern ID and description for better logging
                desc: str = (
                    f"{pattern.pattern_id}: {pattern.description}"
                    if pattern.description is not None
                    else pattern.pattern_id
                )
                matched.append(desc)

        return matched

    def add_custom_pattern(self, pattern: str) -> bool:
        """
        Add a new custom pattern at runtime.

        Args:
            pattern: Regex pattern string to add.

        Returns:
            True if successfully added, False otherwise.
        """
        from guard.core.prompt_injection.pattern_types import (
            InjectionPattern,
            PatternCategory,
        )

        try:
            # Track in custom_patterns list
            self.custom_patterns.append(pattern)

            # Create and add to PatternManager
            custom_pattern = InjectionPattern(
                pattern_id=f"runtime_custom_{len(self.custom_patterns)}",
                pattern=pattern,
                category=PatternCategory.INSTRUCTION_OVERRIDE,  # Default category
                weight=1.0,
                description=f"Runtime custom pattern: {pattern[:50]}...",
                confidence=0.8,
            )
            self.pattern_manager.add_pattern(custom_pattern, persist=False)
            return True
        except (ValueError, re.error):
            # Invalid pattern, remove from list if added
            if pattern in self.custom_patterns:
                self.custom_patterns.remove(pattern)
            return False

    def remove_custom_pattern(self, pattern: str) -> bool:
        """
        Remove a custom pattern.

        Args:
            pattern: Pattern string to remove.

        Returns:
            True if removed, False if not found.
        """
        if pattern not in self.custom_patterns:
            return False

        # Find the pattern ID in PatternManager
        idx = self.custom_patterns.index(pattern)
        pattern_id = f"runtime_custom_{idx + 1}"

        # Remove from both lists
        self.custom_patterns.remove(pattern)
        return self.pattern_manager.remove_pattern(pattern_id, persist=False)

    def clear_custom_patterns(self) -> None:
        """Clear all custom patterns added at runtime."""
        # Remove all runtime custom patterns from PatternManager
        for idx in range(len(self.custom_patterns)):
            pattern_id = f"runtime_custom_{idx + 1}"
            self.pattern_manager.remove_pattern(pattern_id, persist=False)

        # Clear the list
        self.custom_patterns.clear()

    def get_pattern_count(self) -> dict[str, int]:
        """
        Get count of patterns currently loaded in the PatternManager.

        Returns:
            Dictionary with pattern counts from PatternManager.
        """
        stats = self.pattern_manager.get_pattern_stats()
        return {
            "total_patterns": stats["total_patterns"],
            "enabled_patterns": stats["enabled_patterns"],
            "custom_patterns_added": len(self.custom_patterns),
        }
