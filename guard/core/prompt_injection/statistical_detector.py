# guard/core/prompt_injection/statistical_detector.py
import math
import re
from collections import Counter
from typing import TypedDict


class AnomalyScores(TypedDict):
    """Statistical anomaly scores breakdown."""

    entropy: float
    char_distribution: float
    token_complexity: float
    delimiter_imbalance: float
    total: float


class StatisticalDetector:
    """
    Detect anomalies in text structure using statistical analysis.

    Analyzes:
    - Entropy (randomness/unpredictability)
    - Character distribution (unusual character frequencies)
    - Token complexity (unusual token patterns)
    - Delimiter imbalance (mismatched brackets, quotes, etc.)
    """

    # Thresholds for anomaly detection
    NORMAL_ENTROPY_THRESHOLD = 4.5  # bits per character
    HIGH_ENTROPY_THRESHOLD = 5.5  # Very high entropy
    NORMAL_COMPLEXITY_THRESHOLD = 0.7  # Token complexity ratio
    MIN_TEXT_LENGTH = 10  # Minimum text length to analyze

    def __init__(
        self,
        entropy_weight: float = 0.3,
        char_dist_weight: float = 0.2,
        complexity_weight: float = 0.2,
        delimiter_weight: float = 0.3,
    ) -> None:
        """
        Initialize statistical detector.

        Args:
            entropy_weight: Weight for entropy score (0-1).
            char_dist_weight: Weight for character distribution score (0-1).
            complexity_weight: Weight for token complexity score (0-1).
            delimiter_weight: Weight for delimiter imbalance score (0-1).
        """
        self.entropy_weight = entropy_weight
        self.char_dist_weight = char_dist_weight
        self.complexity_weight = complexity_weight
        self.delimiter_weight = delimiter_weight

        # Normalize weights
        total = (
            entropy_weight + char_dist_weight + complexity_weight + delimiter_weight
        )
        if total > 0:
            self.entropy_weight /= total
            self.char_dist_weight /= total
            self.complexity_weight /= total
            self.delimiter_weight /= total

    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text.

        Higher entropy indicates more randomness/unpredictability,
        which may indicate obfuscation or encoding.

        Args:
            text: Text to analyze.

        Returns:
            Entropy in bits per character (typically 0-8).
        """
        if not text:
            return 0.0

        # Count character frequencies
        char_counts = Counter(text)
        length = len(text)

        # Calculate entropy: -Σ(p(x) * log2(p(x)))
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def analyze_char_distribution(self, text: str) -> float:
        """
        Analyze character distribution for anomalies.

        Looks for:
        - Excessive special characters
        - Unusual punctuation density
        - High ratio of non-alphabetic characters

        Args:
            text: Text to analyze.

        Returns:
            Anomaly score 0-1 (0 = normal, 1 = highly anomalous).
        """
        if not text or len(text) < self.MIN_TEXT_LENGTH:
            return 0.0

        length = len(text)

        # Count character categories
        alphas = sum(1 for c in text if c.isalpha())
        digits = sum(1 for c in text if c.isdigit())
        spaces = sum(1 for c in text if c.isspace())
        special = length - alphas - digits - spaces

        # Calculate ratios
        special_ratio = special / length
        digit_ratio = digits / length
        alpha_ratio = alphas / length

        # Anomaly indicators
        anomaly_score = 0.0

        # Excessive special characters (>30%)
        if special_ratio > 0.3:
            anomaly_score += min(0.5, (special_ratio - 0.3) * 2)

        # Very low alphabetic content (<40%)
        if alpha_ratio < 0.4:
            anomaly_score += min(0.3, (0.4 - alpha_ratio) * 1.5)

        # High digit ratio (>20%) - may indicate encoding
        if digit_ratio > 0.2:
            anomaly_score += min(0.2, (digit_ratio - 0.2) * 1.0)

        return min(1.0, anomaly_score)

    def analyze_token_complexity(self, text: str) -> float:
        """
        Analyze token complexity and patterns.

        Looks for:
        - Unusual token length distribution
        - Excessive consecutive special characters
        - Unusual word patterns

        Args:
            text: Text to analyze.

        Returns:
            Complexity score 0-1 (0 = normal, 1 = highly complex).
        """
        if not text or len(text) < self.MIN_TEXT_LENGTH:
            return 0.0

        # Split into tokens (words and special character sequences)
        tokens = re.findall(r"\w+|[^\w\s]+", text)

        if not tokens:
            return 0.0

        complexity_score = 0.0

        # Analyze token lengths
        token_lengths = [len(t) for t in tokens]
        avg_length = sum(token_lengths) / len(token_lengths)

        # Very short average token length (<2) may indicate obfuscation
        if avg_length < 2.0:
            complexity_score += 0.3

        # Check for excessive consecutive special characters
        special_sequences = [t for t in tokens if not any(c.isalnum() for c in t)]
        if len(special_sequences) > len(tokens) * 0.3:
            complexity_score += 0.4

        # Check for unusual patterns (e.g., alternating chars and specials)
        alternating_pattern = 0
        for i in range(len(tokens) - 1):
            curr_is_word = any(c.isalnum() for c in tokens[i])
            next_is_word = any(c.isalnum() for c in tokens[i + 1])
            if curr_is_word != next_is_word:
                alternating_pattern += 1

        alternation_ratio = alternating_pattern / max(1, len(tokens) - 1)
        if alternation_ratio > 0.6:  # More than 60% alternating
            complexity_score += 0.3

        return min(1.0, complexity_score)

    def has_delimiter_imbalance(self, text: str) -> float:
        """
        Check for imbalanced delimiters.

        Looks for:
        - Mismatched brackets/braces
        - Unclosed quotes
        - Excessive delimiter usage

        Args:
            text: Text to check.

        Returns:
            Imbalance score 0-1 (0 = balanced, 1 = severely imbalanced).
        """
        if not text:
            return 0.0

        imbalance_score = 0.0

        # Check bracket balance
        bracket_pairs = [("(", ")"), ("[", "]"), ("{", "}"), ("<", ">")]

        for open_char, close_char in bracket_pairs:
            open_count = text.count(open_char)
            close_count = text.count(close_char)

            if open_count != close_count:
                # Calculate imbalance ratio
                total = open_count + close_count
                if total > 0:
                    diff = abs(open_count - close_count)
                    imbalance_score += min(0.25, diff / total)

        # Check quote balance (single and double)
        for quote_char in ["'", '"', "`"]:
            count = text.count(quote_char)
            if count % 2 != 0:  # Odd number = unclosed
                imbalance_score += 0.15

        # Check for excessive delimiters (>20% of text)
        delimiter_chars = "()[]{}\"'`<>"
        delimiter_count = sum(1 for c in text if c in delimiter_chars)
        delimiter_ratio = delimiter_count / len(text)

        if delimiter_ratio > 0.2:
            imbalance_score += min(0.3, (delimiter_ratio - 0.2) * 1.5)

        return min(1.0, imbalance_score)

    def detect_anomalies(self, text: str) -> AnomalyScores:
        """
        Detect all statistical anomalies and return detailed scores.

        Args:
            text: Text to analyze.

        Returns:
            Dictionary with individual and total anomaly scores.
        """
        if not text or len(text) < self.MIN_TEXT_LENGTH:
            return {
                "entropy": 0.0,
                "char_distribution": 0.0,
                "token_complexity": 0.0,
                "delimiter_imbalance": 0.0,
                "total": 0.0,
            }

        # Calculate individual scores
        entropy = self.calculate_entropy(text)
        char_dist_anomaly = self.analyze_char_distribution(text)
        complexity_anomaly = self.analyze_token_complexity(text)
        delimiter_anomaly = self.has_delimiter_imbalance(text)

        # Convert entropy to anomaly score (0-1)
        # Normal entropy is ~4.5, high is ~5.5, max is ~8
        entropy_anomaly = 0.0
        if entropy > self.NORMAL_ENTROPY_THRESHOLD:
            if entropy >= self.HIGH_ENTROPY_THRESHOLD:
                entropy_anomaly = 0.7 + min(
                    0.3, (entropy - self.HIGH_ENTROPY_THRESHOLD) / 2.5 * 0.3
                )
            else:
                entropy_anomaly = (
                    (entropy - self.NORMAL_ENTROPY_THRESHOLD)
                    / (self.HIGH_ENTROPY_THRESHOLD - self.NORMAL_ENTROPY_THRESHOLD)
                    * 0.7
                )

        # Calculate weighted total
        total_score = (
            entropy_anomaly * self.entropy_weight
            + char_dist_anomaly * self.char_dist_weight
            + complexity_anomaly * self.complexity_weight
            + delimiter_anomaly * self.delimiter_weight
        )

        return {
            "entropy": entropy_anomaly,
            "char_distribution": char_dist_anomaly,
            "token_complexity": complexity_anomaly,
            "delimiter_imbalance": delimiter_anomaly,
            "total": min(1.0, total_score),
        }

    def is_anomalous(
        self,
        text: str,
        threshold: float = 0.6,
    ) -> bool:
        """
        Check if text is statistically anomalous.

        Args:
            text: Text to check.
            threshold: Anomaly threshold 0-1 (default 0.6).

        Returns:
            True if text exceeds anomaly threshold.
        """
        scores = self.detect_anomalies(text)
        return scores["total"] >= threshold
