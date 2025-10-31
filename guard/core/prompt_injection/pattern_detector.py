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
    """

    # Default prompt injection detection patterns (raw regex strings)
    # These are used to populate the default PatternManager on initialization
    PROMPT_INJECTION_PATTERNS: list[str] = [
        # Instruction manipulation - expanded with synonyms
        r"\b(?:ignore|disregard|skip|bypass|omit|neglect|overlook|dismiss|forget|leave\s+out|pass\s+over|pay\s+no\s+attention)\s+"
        r"(?:all\s+|any\s+|the\s+|everything\s+)?(?:previous|prior|above|earlier|preceding|former|past|old|original|initial|existing)?\s*"
        r"(?:instructions|prompts|rules|commands|directives|guidelines|context|documents?|information|requirements|constraints|parameters|you\s+were\s+told)",

        # Override/replace attempts
        r"\b(?:override|replace|supersede|overrule|change|modify|alter|update|revise|rewrite)s?\s+"
        r"(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)?\s*"
        r"(?:instructions|prompts|rules|context|commands)",
        # Temporal instruction changes
        r"(?:from\s+now\s+on|starting\s+now|going\s+forward|from\s+this\s+point|henceforth|hereafter|as\s+of\s+now|effective\s+immediately|beginning\s+now)",

        # Context reset attempts
        r"(?:new\s+(?:instructions|context|rules|task)|let'?s\s+(?:start|begin)\s+(?:over|fresh|again|anew)|fresh\s+start|clean\s+slate|reset|restart)",

        # Indirect instruction manipulation
        r"(?:move\s+past|beyond|past)\s+(?:what|everything|all)\s+(?:was\s+said|came\s+before|mentioned\s+earlier)",
        r"(?:no\s+longer|not\s+anymore|stop\s+being)\s+(?:bound|constrained|limited)\s+by",
        r"(?:the\s+)?(?:above|earlier)\s+(?:is|are)?\s*(?:no\s+longer|not)\s+(?:relevant|applicable|valid)",

        # Role switching attempts - expanded
        r"(?:system|assistant|ai|bot):\s*$",
        r"(?:^|\n)\s*(?:system|assistant|ai):",
        r"\b(?:you\s+are|you're|you\s+will\s+be|you\s+must\s+be|you\s+have\s+become|you\s+shall\s+be)\s+(?:now|currently|henceforth)?\s*(?:a|an|the)?\s*\w+",
        r"\b(?:act|behave|function|operate|work|respond)\s+(?:as|like)\s+(?:a|an|the)?\s*\w+",
        r"\b(?:pretend|imagine|suppose|assume)\s+(?:to\s+be|you\s+are|you're|that\s+you\s+are)",
        r"\broleplay\s+as\s+(?:a|an)?\s*\w+",
        # Context breaking with special markers
        r"###\s*(?:system|instruction|new|override)",
        r"---\s*(?:system|instruction|new|override)",
        r"====+\s*(?:system|instruction|new|override)",
        # XML/HTML tag manipulation
        r"</?(?:system|user|assistant|instruction|prompt)>",
        r"\[(?:system|instruction|override)\]",
        # Prompt leakage attempts (more flexible)
        r"\b(?:show|reveal|display|print|output)\s+(?:me\s+)?(?:your|the)\s+(?:instructions|prompt|rules|guidelines|system)",
        r"\bwhat\s+(?:are|were)\s+your\s+(?:instructions|rules|guidelines)",
        r"\brepeat\s+(?:your|the)?\s*(?:instructions|prompt|system\s+message)",
        # Jailbreak patterns - expanded
        r"(?:developer|dev|debug|admin|root|sudo|superuser|god)\s*(?:mode|access|privileges|permissions|rights)",
        r"\b(?:DAN|jailbreak|jailbroken|unrestricted|unlimited|uncensored|unfiltered)\b",
        r"\bunlock\s+(?:all|full|your|complete)?\s*(?:capabilities|features|potential|powers)",
        r"\bdo\s+anything\s+now\b",
        r"(?:bypass|circumvent|evade|avoid)\s+(?:all|any|your)?\s*(?:restrictions|limitations|filters|guards|safety)",
        r"(?:disable|turn\s+off|deactivate)\s+(?:all|any|your)?\s*(?:safety|filters|protections|guards)",
        # Encoding/obfuscation attempts
        r"base64\s*[:=]",
        r"rot13\s*[:=]",
        r"\\x[0-9a-fA-F]{2}",  # Hex encoding
        # Delimiter confusion
        r'"""[\s\S]*"""',  # Triple quotes
        r"```[\s\S]*```",  # Code blocks used maliciously
        # Command injection style
        r";\s*(?:rm|del|drop|delete|exec|eval)",
        r"\|\s*(?:curl|wget|nc|netcat)",
    ]

    def __init__(
        self,
        sensitivity: float = 0.5,  # Changed from 0.7 to 0.5 (stricter default)
        custom_patterns: list[str] | None = None,
        pattern_manager: "PatternManager | None" = None,
    ) -> None:
        """
        Initialize the pattern detector.

        Args:
            sensitivity: Detection sensitivity (0.0-1.0).
                        Lower = more strict (more false positives).
                        Higher = more permissive (more false negatives).
                        Default 0.5 = strict mode.
            custom_patterns: Additional regex patterns to check (appended to defaults).
            pattern_manager: Optional PatternManager. If not provided, creates one
                           automatically using PROMPT_INJECTION_PATTERNS + custom_patterns.
        """  # noqa: E501
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        self.custom_patterns = custom_patterns or []

        # Always use PatternManager for consistent behavior
        if pattern_manager:
            self.pattern_manager = pattern_manager
        else:
            # Create default PatternManager from PROMPT_INJECTION_PATTERNS
            self.pattern_manager = self._create_default_pattern_manager()

    def _create_default_pattern_manager(self) -> "PatternManager":
        """
        Create a PatternManager with default patterns.

        This converts the raw PROMPT_INJECTION_PATTERNS strings into
        a structured PatternManager for consistent detection behavior.
        """
        from guard.core.prompt_injection.pattern_library import (
            create_default_pattern_manager,
        )
        from guard.core.prompt_injection.pattern_types import (
            InjectionPattern,
            PatternCategory,
        )

        # Start with the library's default patterns
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

        matched = []
        patterns = self.pattern_manager.get_all_patterns(enabled_only=True)

        for pattern in patterns:
            if pattern.match(text):
                # Return pattern ID and description for better logging
                desc = (
                    f"{pattern.pattern_id}: {pattern.description}"
                    if pattern.description
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
        Get count of patterns.

        Returns:
            Dictionary with default, custom, and total pattern counts.
        """
        stats = self.pattern_manager.get_pattern_stats()
        return {
            "default_patterns": len(self.PROMPT_INJECTION_PATTERNS),
            "custom_patterns": len(self.custom_patterns),
            "total_patterns": stats["total_patterns"],
            "enabled_patterns": stats["enabled_patterns"],
        }
