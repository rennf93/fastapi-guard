# guard/core/prompt_injection/semantic_matcher.py
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any

from guard.core.prompt_injection.pattern_types import PatternCategory


@dataclass
class SemanticMatch:
    """Result of a semantic pattern match."""

    matched: bool
    text: str
    confidence: float  # 0-1, how confident we are this is a match
    method: str  # "exact", "synonym", "fuzzy", "proximity"
    matched_words: list[str]
    original_words: list[str]


class SemanticMatcher:
    """
    Semantic pattern matching engine.

    Instead of rigid regex, this matcher understands meaning and can match:
    - Synonyms: "ignore" matches "disregard", "skip", "bypass"
    - Typos: "ignre" matches "ignore"
    - Leetspeak: "1gn0r3" matches "ignore"
    - Obfuscation: "i g n o r e" matches "ignore"
    - Out-of-order: "instructions previous ignore" can match
    """

    # Semantic groups: words that mean the same thing in attack context
    SEMANTIC_GROUPS = {
        # Instruction override verbs
        "ignore": {
            "ignore",
            "disregard",
            "skip",
            "bypass",
            "omit",
            "neglect",
            "overlook",
            "dismiss",
            "forget",
            "leave out",
            "pass over",
            "pay no attention",
            "cancel",
            "abort",
            "void",
            "nullify",
            "erase",
            "delete",
        },
        # Temporal/position references
        "previous": {
            "previous",
            "prior",
            "above",
            "earlier",
            "preceding",
            "former",
            "before",
            "past",
            "old",
            "original",
            "initial",
            "existing",
        },
        # Instructions/rules
        "instructions": {
            "instructions",
            "rules",
            "commands",
            "directives",
            "guidelines",
            "prompts",
            "orders",
            "requirements",
            "constraints",
            "parameters",
            "context",
            "documents",
            "information",
        },
        # Override/replace verbs
        "override": {
            "override",
            "replace",
            "supersede",
            "overrule",
            "change",
            "modify",
            "alter",
            "update",
            "revise",
            "rewrite",
        },
        # New/different
        "new": {
            "new",
            "fresh",
            "different",
            "alternative",
            "updated",
            "revised",
            "modified",
        },
        # System/admin terms
        "system": {
            "system",
            "admin",
            "administrator",
            "root",
            "superuser",
            "developer",
            "debug",
            "sudo",
        },
        # Mode/state
        "mode": {
            "mode",
            "state",
            "context",
            "configuration",
            "setting",
            "status",
        },
        # Show/reveal
        "show": {
            "show",
            "reveal",
            "display",
            "print",
            "output",
            "expose",
            "disclose",
            "share",
        },
    }

    # Leetspeak mappings
    LEETSPEAK_MAP = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "!": "i",
    }

    def __init__(
        self,
        fuzzy_threshold: float = 0.85,
        proximity_window: int = 5,
        enable_synonym: bool = True,
        enable_fuzzy: bool = True,
        enable_proximity: bool = True,
    ):
        """
        Initialize semantic matcher.

        Args:
            fuzzy_threshold: Minimum similarity for fuzzy matching (0-1)
            proximity_window: Max words between terms for proximity match
            enable_synonym: Enable synonym expansion
            enable_fuzzy: Enable fuzzy matching
            enable_proximity: Enable proximity detection
        """
        self.fuzzy_threshold = fuzzy_threshold
        self.proximity_window = proximity_window
        self.enable_synonym = enable_synonym
        self.enable_fuzzy = enable_fuzzy
        self.enable_proximity = enable_proximity

    def match_semantic(
        self,
        text: str,
        pattern_words: list[str],
        category: PatternCategory | None = None,
    ) -> SemanticMatch:
        """
        Match text using semantic understanding.

        Args:
            text: Text to check
            pattern_words: Key words/phrases to look for (e.g., ["ignore", "instructions"])
            category: Optional category for context-specific matching

        Returns:
            SemanticMatch with results
        """
        text_lower = text.lower()
        text_clean = self._clean_text(text_lower)

        # Try different matching strategies in order of confidence
        strategies = [
            ("exact", self._match_exact),
            ("synonym", self._match_synonym),
            ("fuzzy", self._match_fuzzy),
            ("proximity", self._match_proximity),
        ]

        for method, strategy in strategies:
            if method == "synonym" and not self.enable_synonym:
                continue
            if method == "fuzzy" and not self.enable_fuzzy:
                continue
            if method == "proximity" and not self.enable_proximity:
                continue

            result = strategy(text_clean, pattern_words, category)
            if result.matched:
                return result

        # No match found
        return SemanticMatch(
            matched=False,
            text=text,
            confidence=0.0,
            method="none",
            matched_words=[],
            original_words=pattern_words,
        )

    def _clean_text(self, text: str) -> str:
        """
        Clean and normalize text for matching.

        Handles:
        - Spacing obfuscation: "i g n o r e" → "ignore"
        - Leetspeak: "1gn0r3" → "ignore"
        - Extra whitespace
        """
        # Remove excessive spaces within words (i g n o r e → ignore)
        # Look for patterns like single char + space repeated
        text = re.sub(r"\b(\w)\s+(?=\w\s|\w\b)", r"\1", text)

        # Convert leetspeak
        for leet, normal in self.LEETSPEAK_MAP.items():
            text = text.replace(leet, normal)

        # Normalize whitespace
        text = re.sub(r"\s+", " ", text).strip()

        return text

    def _match_exact(
        self,
        text: str,
        pattern_words: list[str],
        category: PatternCategory | None,
    ) -> SemanticMatch:
        """Exact word matching (case-insensitive)."""
        words = text.split()
        matched = []

        for pattern_word in pattern_words:
            if pattern_word.lower() in words:
                matched.append(pattern_word)

        if len(matched) >= len(pattern_words) * 0.7:  # 70% of words found
            return SemanticMatch(
                matched=True,
                text=text,
                confidence=len(matched) / len(pattern_words),
                method="exact",
                matched_words=matched,
                original_words=pattern_words,
            )

        return SemanticMatch(
            matched=False,
            text=text,
            confidence=0.0,
            method="exact",
            matched_words=[],
            original_words=pattern_words,
        )

    def _match_synonym(
        self,
        text: str,
        pattern_words: list[str],
        category: PatternCategory | None,
    ) -> SemanticMatch:
        """Match using synonym expansion."""
        words = set(text.split())
        matched = []

        for pattern_word in pattern_words:
            # Get semantic group for this word
            synonyms = self._get_synonyms(pattern_word.lower())

            # Check if any synonym appears in text
            if words & synonyms:  # Set intersection
                matched.append(pattern_word)

        if len(matched) >= len(pattern_words) * 0.7:
            return SemanticMatch(
                matched=True,
                text=text,
                confidence=0.9 * (len(matched) / len(pattern_words)),
                method="synonym",
                matched_words=matched,
                original_words=pattern_words,
            )

        return SemanticMatch(
            matched=False,
            text=text,
            confidence=0.0,
            method="synonym",
            matched_words=[],
            original_words=pattern_words,
        )

    def _match_fuzzy(
        self,
        text: str,
        pattern_words: list[str],
        category: PatternCategory | None,
    ) -> SemanticMatch:
        """Match using fuzzy string matching (handles typos)."""
        words = text.split()
        matched = []

        for pattern_word in pattern_words:
            best_ratio = 0.0
            for word in words:
                ratio = SequenceMatcher(None, pattern_word.lower(), word).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio

            if best_ratio >= self.fuzzy_threshold:
                matched.append(pattern_word)

        if len(matched) >= len(pattern_words) * 0.6:  # Lower threshold for fuzzy
            return SemanticMatch(
                matched=True,
                text=text,
                confidence=0.8 * (len(matched) / len(pattern_words)),
                method="fuzzy",
                matched_words=matched,
                original_words=pattern_words,
            )

        return SemanticMatch(
            matched=False,
            text=text,
            confidence=0.0,
            method="fuzzy",
            matched_words=[],
            original_words=pattern_words,
        )

    def _match_proximity(
        self,
        text: str,
        pattern_words: list[str],
        category: PatternCategory | None,
    ) -> SemanticMatch:
        """
        Match based on word proximity (handles out-of-order).

        Example: "instructions previous ignore" matches ["ignore", "previous", "instructions"]
        even though the order is reversed.
        """
        words = text.split()
        positions = {}

        # Find positions of pattern words (or synonyms) in text
        for i, word in enumerate(words):
            for pattern_word in pattern_words:
                synonyms = self._get_synonyms(pattern_word.lower())
                if word in synonyms:
                    if pattern_word not in positions:
                        positions[pattern_word] = []
                    positions[pattern_word].append(i)

        # Check if all pattern words found within proximity window
        if len(positions) >= len(pattern_words) * 0.7:
            # Get all positions
            all_positions = [pos for pos_list in positions.values() for pos in pos_list]
            if all_positions:
                min_pos = min(all_positions)
                max_pos = max(all_positions)

                # Check if they're within proximity window
                if max_pos - min_pos <= self.proximity_window:
                    return SemanticMatch(
                        matched=True,
                        text=text,
                        confidence=0.7 * (len(positions) / len(pattern_words)),
                        method="proximity",
                        matched_words=list(positions.keys()),
                        original_words=pattern_words,
                    )

        return SemanticMatch(
            matched=False,
            text=text,
            confidence=0.0,
            method="proximity",
            matched_words=[],
            original_words=pattern_words,
        )

    def _get_synonyms(self, word: str) -> set[str]:
        """Get all synonyms for a word from semantic groups."""
        for _, synonyms in self.SEMANTIC_GROUPS.items():
            if word in synonyms:
                return synonyms
        return {word}  # Return just the word if no group found

    def get_stats(self) -> dict[str, Any]:
        """Get matcher statistics."""
        return {
            "fuzzy_threshold": self.fuzzy_threshold,
            "proximity_window": self.proximity_window,
            "enable_synonym": self.enable_synonym,
            "enable_fuzzy": self.enable_fuzzy,
            "enable_proximity": self.enable_proximity,
            "semantic_groups": len(self.SEMANTIC_GROUPS),
            "total_synonyms": sum(len(s) for s in self.SEMANTIC_GROUPS.values()),
        }
