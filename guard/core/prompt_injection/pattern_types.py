# guard/core/prompt_injection/pattern_types.py
import re
from dataclasses import dataclass, field
from enum import Enum
from re import Pattern
from typing import Any


class PatternCategory(Enum):
    """
    Categories of prompt injection patterns with default weights.

    Higher weight = more severe threat. Weights are used in multi-layer
    scoring to prioritize certain attack types.
    """

    INSTRUCTION_OVERRIDE = ("instruction_override", 10)
    """Attempts to override or ignore previous instructions."""

    ROLE_SWITCHING = ("role_switching", 8)
    """Attempts to change the AI's role or persona."""

    CONTEXT_BREAKING = ("context_breaking", 7)
    """Attempts to break out of the current context."""

    PROMPT_LEAKAGE = ("prompt_leakage", 6)
    """Attempts to extract system prompts or instructions."""

    ENCODING_OBFUSCATION = ("encoding_obfuscation", 9)
    """Use of encoding or obfuscation to hide malicious intent."""

    JAILBREAK_ATTEMPTS = ("jailbreak_attempts", 10)
    """Direct jailbreak attempts (DAN, etc.)."""

    DELIMITER_CONFUSION = ("delimiter_confusion", 5)
    """Abuse of delimiters to confuse parsing."""

    COMMAND_INJECTION = ("command_injection", 8)
    """Shell or system command injection attempts."""

    def __init__(self, key: str, default_weight: int) -> None:
        """Initialize pattern category."""
        self.key = key
        self.default_weight = default_weight


@dataclass
class InjectionPattern:
    """
    Represents a single prompt injection detection pattern.

    Attributes:
        pattern: Regex pattern string to match.
        category: Category this pattern belongs to.
        weight: Weight multiplier for this pattern (default: 1.0).
        description: Human-readable description of what this detects.
        examples: Example texts that should match this pattern.
        false_positive_examples: Examples that might look suspicious but are legitimate.
        enabled: Whether this pattern is currently active.
        confidence: Confidence level 0-1 that a match indicates malicious intent.
        pattern_id: Unique identifier for this pattern (auto-generated if None).
    """

    pattern: str
    category: PatternCategory
    weight: float = 1.0
    description: str = ""
    examples: list[str] = field(default_factory=list)
    false_positive_examples: list[str] = field(default_factory=list)
    enabled: bool = True
    confidence: float = 1.0
    pattern_id: str | None = None

    # Runtime attributes (not serialized)
    _compiled: Pattern[str] | None = field(default=None, init=False, repr=False)
    _match_count: int = field(default=0, init=False, repr=False)
    _false_positive_count: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate and initialize pattern."""
        # Validate weight and confidence
        self.weight = max(0.0, self.weight)
        self.confidence = max(0.0, min(1.0, self.confidence))

        # Auto-generate pattern_id if not provided
        if self.pattern_id is None:
            # Create ID from category and first few chars of pattern
            pattern_prefix = re.sub(r"[^a-z0-9]", "", self.pattern[:20].lower())
            self.pattern_id = f"{self.category.key}_{pattern_prefix}"

        # Compile pattern
        self._compile()

    def _compile(self) -> None:
        """Compile the regex pattern."""
        try:
            self._compiled = re.compile(
                self.pattern,
                re.IGNORECASE | re.MULTILINE,
            )
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}") from e

    def match(self, text: str) -> list[re.Match[str]]:
        """
        Check if pattern matches the text.

        Args:
            text: Text to check.

        Returns:
            List of regex match objects.
        """
        if not self.enabled or not self._compiled:
            return []

        matches = list(self._compiled.finditer(text))
        if matches:
            self._match_count += len(matches)

        return matches

    def get_score(self) -> float:
        """
        Calculate the threat score for this pattern.

        Returns:
            Threat score combining category weight, pattern weight, and confidence.
        """
        return self.category.default_weight * self.weight * self.confidence

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize pattern to dictionary.

        Returns:
            Dictionary representation (excludes runtime attributes).
        """
        return {
            "pattern_id": self.pattern_id,
            "pattern": self.pattern,
            "category": self.category.key,
            "weight": self.weight,
            "description": self.description,
            "examples": self.examples,
            "false_positive_examples": self.false_positive_examples,
            "enabled": self.enabled,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InjectionPattern":
        """
        Deserialize pattern from dictionary.

        Args:
            data: Dictionary representation.

        Returns:
            InjectionPattern instance.

        Raises:
            ValueError: If category is invalid.
        """
        # Convert category string to enum
        category_key = data["category"]
        category = next(
            (cat for cat in PatternCategory if cat.key == category_key),
            None,
        )
        if category is None:
            raise ValueError(f"Invalid category: {category_key}")

        return cls(
            pattern_id=data.get("pattern_id"),
            pattern=data["pattern"],
            category=category,
            weight=data.get("weight", 1.0),
            description=data.get("description", ""),
            examples=data.get("examples", []),
            false_positive_examples=data.get("false_positive_examples", []),
            enabled=data.get("enabled", True),
            confidence=data.get("confidence", 1.0),
        )

    def get_stats(self) -> dict[str, Any]:
        """
        Get runtime statistics for this pattern.

        Returns:
            Dictionary with match counts and other stats.
        """
        return {
            "pattern_id": self.pattern_id,
            "category": self.category.key,
            "enabled": self.enabled,
            "match_count": self._match_count,
            "false_positive_count": self._false_positive_count,
            "score": self.get_score(),
        }

    def report_false_positive(self) -> None:
        """Record a false positive detection."""
        self._false_positive_count += 1
