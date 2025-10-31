# guard/core/prompt_injection/pattern_manager.py
import json
from pathlib import Path
from typing import Any

from guard.core.prompt_injection.pattern_types import InjectionPattern, PatternCategory


class PatternManager:
    """
    Manages a collection of injection detection patterns.

    Provides:
    - Runtime pattern add/remove/enable/disable
    - Pattern persistence to JSON/YAML
    - Pattern querying by category
    - Pattern testing interface
    - Effectiveness metrics
    """

    def __init__(self, pattern_file: str | Path | None = None) -> None:
        """
        Initialize pattern manager.

        Args:
            pattern_file: Optional path to pattern file for persistence.
        """
        self.patterns: dict[str, InjectionPattern] = {}
        self.pattern_file = Path(pattern_file) if pattern_file else None

        # Load patterns from file if provided
        if self.pattern_file and self.pattern_file.exists():
            self.load_patterns()

    def add_pattern(
        self,
        pattern: InjectionPattern,
        persist: bool = True,
    ) -> None:
        """
        Add a new pattern with unique ID.

        Args:
            pattern: InjectionPattern to add.
            persist: Whether to persist changes to file.

        Raises:
            ValueError: If pattern_id already exists.
        """
        if pattern.pattern_id in self.patterns:
            raise ValueError(f"Pattern ID already exists: {pattern.pattern_id}")

        self.patterns[pattern.pattern_id] = pattern

        if persist and self.pattern_file:
            self.save_patterns()

    def remove_pattern(self, pattern_id: str, persist: bool = True) -> bool:
        """
        Remove a pattern by ID.

        Args:
            pattern_id: ID of pattern to remove.
            persist: Whether to persist changes to file.

        Returns:
            True if removed, False if not found.
        """
        if pattern_id not in self.patterns:
            return False

        del self.patterns[pattern_id]

        if persist and self.pattern_file:
            self.save_patterns()

        return True

    def get_pattern(self, pattern_id: str) -> InjectionPattern | None:
        """
        Get a pattern by ID.

        Args:
            pattern_id: Pattern ID to retrieve.

        Returns:
            InjectionPattern or None if not found.
        """
        return self.patterns.get(pattern_id)

    def enable_pattern(self, pattern_id: str, persist: bool = True) -> bool:
        """
        Enable a specific pattern.

        Args:
            pattern_id: ID of pattern to enable.
            persist: Whether to persist changes to file.

        Returns:
            True if enabled, False if not found.
        """
        pattern = self.patterns.get(pattern_id)
        if not pattern:
            return False

        pattern.enabled = True

        if persist and self.pattern_file:
            self.save_patterns()

        return True

    def disable_pattern(self, pattern_id: str, persist: bool = True) -> bool:
        """
        Disable a specific pattern.

        Args:
            pattern_id: ID of pattern to disable.
            persist: Whether to persist changes to file.

        Returns:
            True if disabled, False if not found.
        """
        pattern = self.patterns.get(pattern_id)
        if not pattern:
            return False

        pattern.enabled = False

        if persist and self.pattern_file:
            self.save_patterns()

        return True

    def update_pattern_weight(
        self,
        pattern_id: str,
        weight: float,
        persist: bool = True,
    ) -> bool:
        """
        Adjust pattern weight for scoring.

        Args:
            pattern_id: ID of pattern to update.
            weight: New weight value (must be >= 0).
            persist: Whether to persist changes to file.

        Returns:
            True if updated, False if not found.

        Raises:
            ValueError: If weight is negative.
        """
        if weight < 0:
            raise ValueError("Weight must be non-negative")

        pattern = self.patterns.get(pattern_id)
        if not pattern:
            return False

        pattern.weight = weight

        if persist and self.pattern_file:
            self.save_patterns()

        return True

    def update_pattern_confidence(
        self,
        pattern_id: str,
        confidence: float,
        persist: bool = True,
    ) -> bool:
        """
        Adjust pattern confidence level.

        Args:
            pattern_id: ID of pattern to update.
            confidence: New confidence value (0.0-1.0).
            persist: Whether to persist changes to file.

        Returns:
            True if updated, False if not found.

        Raises:
            ValueError: If confidence not in range [0, 1].
        """
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")

        pattern = self.patterns.get(pattern_id)
        if not pattern:
            return False

        pattern.confidence = confidence

        if persist and self.pattern_file:
            self.save_patterns()

        return True

    def get_patterns_by_category(
        self,
        category: PatternCategory,
        enabled_only: bool = True,
    ) -> list[InjectionPattern]:
        """
        Get all patterns in a category.

        Args:
            category: Category to filter by.
            enabled_only: Only return enabled patterns.

        Returns:
            List of matching patterns.
        """
        patterns = [p for p in self.patterns.values() if p.category == category]

        if enabled_only:
            patterns = [p for p in patterns if p.enabled]

        return patterns

    def get_all_patterns(self, enabled_only: bool = True) -> list[InjectionPattern]:
        """
        Get all patterns.

        Args:
            enabled_only: Only return enabled patterns.

        Returns:
            List of patterns.
        """
        patterns = list(self.patterns.values())

        if enabled_only:
            patterns = [p for p in patterns if p.enabled]

        return patterns

    def test_pattern(self, pattern_id: str, test_text: str) -> dict[str, Any]:
        """
        Test a specific pattern against text.

        Args:
            pattern_id: ID of pattern to test.
            test_text: Text to test against.

        Returns:
            Dictionary with test results.
        """
        pattern = self.patterns.get(pattern_id)
        if not pattern:
            return {"error": "Pattern not found"}

        matches = pattern.match(test_text)

        return {
            "pattern_id": pattern_id,
            "matched": bool(matches),
            "match_count": len(matches),
            "matches": [
                {
                    "text": m.group(),
                    "start": m.start(),
                    "end": m.end(),
                }
                for m in matches
            ],
            "category": pattern.category.key,
            "weight": pattern.weight,
            "confidence": pattern.confidence,
            "score": pattern.get_score(),
        }

    def get_pattern_stats(self) -> dict[str, Any]:
        """
        Get statistics about all patterns.

        Returns:
            Dictionary with pattern statistics.
        """
        total = len(self.patterns)
        enabled = sum(1 for p in self.patterns.values() if p.enabled)
        disabled = total - enabled

        category_counts = {}
        for category in PatternCategory:
            count = sum(
                1 for p in self.patterns.values() if p.category == category
            )
            category_counts[category.key] = count

        return {
            "total_patterns": total,
            "enabled_patterns": enabled,
            "disabled_patterns": disabled,
            "patterns_by_category": category_counts,
        }

    def get_effectiveness_report(self) -> dict[str, Any]:
        """
        Generate effectiveness report for all patterns.

        Returns:
            Dictionary with effectiveness metrics per pattern.
        """
        report = []

        for pattern in self.patterns.values():
            stats = pattern.get_stats()

            # Calculate effectiveness metrics
            total_matches = stats["match_count"]
            false_positives = stats["false_positive_count"]
            true_positives = total_matches - false_positives

            precision = (
                true_positives / total_matches if total_matches > 0 else 0.0
            )

            report.append(
                {
                    **stats,
                    "true_positives": true_positives,
                    "precision": precision,
                }
            )

        # Sort by match count (most used patterns first)
        report.sort(key=lambda x: x["match_count"], reverse=True)

        return {
            "patterns": report,
            "summary": {
                "total_patterns": len(self.patterns),
                "total_matches": sum(p["match_count"] for p in report),
                "total_false_positives": sum(
                    p["false_positive_count"] for p in report
                ),
            },
        }

    def save_patterns(self) -> None:
        """
        Save patterns to file.

        Raises:
            ValueError: If no pattern_file configured.
            OSError: If file cannot be written.
        """
        if not self.pattern_file:
            raise ValueError("No pattern file configured")

        # Serialize all patterns
        data = {
            "version": "1.0",
            "patterns": [p.to_dict() for p in self.patterns.values()],
        }

        # Write to file
        self.pattern_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.pattern_file, "w") as f:
            json.dump(data, f, indent=2)

    def load_patterns(self) -> None:
        """
        Load patterns from file.

        Raises:
            ValueError: If no pattern_file configured or file doesn't exist.
            OSError: If file cannot be read.
            json.JSONDecodeError: If file is not valid JSON.
        """
        if not self.pattern_file:
            raise ValueError("No pattern file configured")

        if not self.pattern_file.exists():
            raise ValueError(f"Pattern file not found: {self.pattern_file}")

        # Read from file
        with open(self.pattern_file) as f:
            data = json.load(f)

        # Deserialize patterns
        self.patterns.clear()
        for pattern_data in data.get("patterns", []):
            pattern = InjectionPattern.from_dict(pattern_data)
            self.patterns[pattern.pattern_id] = pattern

    def clear_all_patterns(self, persist: bool = True) -> None:
        """
        Remove all patterns.

        Args:
            persist: Whether to persist changes to file.
        """
        self.patterns.clear()

        if persist and self.pattern_file:
            self.save_patterns()

    def bulk_update_category_weights(
        self,
        category: PatternCategory,
        weight_multiplier: float,
        persist: bool = True,
    ) -> int:
        """
        Update weights for all patterns in a category.

        Args:
            category: Category to update.
            weight_multiplier: Multiplier to apply to all weights.
            persist: Whether to persist changes.

        Returns:
            Number of patterns updated.
        """
        count = 0
        for pattern in self.patterns.values():
            if pattern.category == category:
                pattern.weight *= weight_multiplier
                count += 1

        if persist and self.pattern_file and count > 0:
            self.save_patterns()

        return count
