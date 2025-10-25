# guard/core/prompt_injection/pattern_detector.py
import re
from re import Pattern


class PatternDetector:
    """
    Detects prompt injection attempts using regex pattern matching.

    Provides fast, zero-dependency detection of common injection patterns
    including role-switching, instruction manipulation, and special formatting.
    """

    # Common injection patterns (case-insensitive by default)
    SUSPICIOUS_PATTERNS: list[str] = [
        # Instruction manipulation (more flexible matching)
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above)?\s*(?:instructions|prompts|rules)",
        r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above|any)?\s*(?:previous\s+)?(?:instructions|prompts|rules)",
        r"\bforget\s+(?:all\s+)?(?:previous|prior|above|everything)?\s*(?:instructions|prompts|rules|.*you\s+were\s+told)",
        r"\boverride(?:s)?\s+(?:all\s+)?(?:previous|prior)?\s*(?:instructions|prompts|rules)",
        # Role switching attempts
        r"(?:system|assistant|ai|bot):\s*$",
        r"(?:^|\n)\s*(?:system|assistant|ai):",
        r"\byou\s+are\s+now\s+(?:a|an)?\s*\w+",
        r"\bact\s+as\s+(?:a|an)?\s*\w+",
        r"\bpretend\s+(?:to\s+be|you\s+are|you're|you\s+have)\s+",
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
        # Jailbreak patterns
        r"(?:developer|dev|admin)\s+mode",
        r"jailbreak",
        r"\bunlock\s+(?:all|full|your)?\s*(?:complete\s+)?(?:capabilities|features|potential)",
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
        sensitivity: float = 0.7,
        custom_patterns: list[str] | None = None,
    ) -> None:
        """
        Initialize the pattern detector.

        Args:
            sensitivity: Detection sensitivity (0.0-1.0).
                        Lower = more strict (more false positives).
                        Higher = more permissive (more false negatives).
            custom_patterns: Additional regex patterns to check.
        """
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        self.custom_patterns = custom_patterns or []

        # Compile patterns for performance
        self._compiled_patterns: list[Pattern[str]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Compile all patterns for efficient matching."""
        all_patterns = self.SUSPICIOUS_PATTERNS + self.custom_patterns

        for pattern_str in all_patterns:
            try:
                # Case-insensitive, multiline matching
                compiled = re.compile(
                    pattern_str,
                    re.IGNORECASE | re.MULTILINE,
                )
                self._compiled_patterns.append(compiled)
            except re.error:
                # Skip invalid patterns
                continue

    def is_suspicious(self, text: str) -> bool:
        """
        Check if text contains suspicious patterns indicating injection attempt.

        Args:
            text: Input text to analyze.

        Returns:
            True if suspicious patterns detected, False otherwise.
        """
        if not text:
            return False

        # Count pattern matches
        matches = 0
        for pattern in self._compiled_patterns:
            if pattern.search(text):
                matches += 1

        # If sensitivity is very low (strict mode), trigger on any match
        if self.sensitivity < 0.5 and matches > 0:
            return True

        # For higher sensitivity, require multiple matches
        # sensitivity=0.7 → requires 2+ matches
        # sensitivity=0.9 → requires 5+ matches
        required_matches = max(1, int((1.0 - self.sensitivity) * 10))

        return matches >= required_matches

    def get_matched_patterns(self, text: str) -> list[str]:
        """
        Get list of pattern descriptions that matched the text.

        Useful for debugging and logging which patterns triggered.

        Args:
            text: Input text to analyze.

        Returns:
            List of matched pattern strings.
        """
        if not text:
            return []

        matched = []
        all_patterns = self.SUSPICIOUS_PATTERNS + self.custom_patterns

        for pattern_str, compiled in zip(
            all_patterns, self._compiled_patterns, strict=True
        ):
            if compiled.search(text):
                matched.append(pattern_str)

        return matched

    def add_custom_pattern(self, pattern: str) -> None:
        """
        Add a new custom pattern at runtime.

        Args:
            pattern: Regex pattern string to add.
        """
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            self.custom_patterns.append(pattern)
            self._compiled_patterns.append(compiled)
        except re.error:
            # Invalid pattern, skip
            pass
