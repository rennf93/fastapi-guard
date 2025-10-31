# guard/core/prompt_injection/context_detector.py
import re
from collections import Counter, deque
from enum import Enum

from guard.core.prompt_injection.pattern_detector import PatternDetector


class ContextType(Enum):
    """Type of application context for detection."""

    GENERAL = "general"  # General-purpose chat
    RAG_QUERY = "rag_query"  # Retrieval-Augmented Generation queries
    CODE_GENERATION = "code_generation"  # Code generation requests
    DATA_ANALYSIS = "data_analysis"  # Data analysis queries
    ADMIN_COMMAND = "admin_command"  # Administrative commands


class UserProfile:
    """
    Track user behavior patterns to detect anomalies.

    Maintains a history of user inputs to establish a baseline
    and detect sudden changes in behavior.
    """

    def __init__(self, max_history: int = 50) -> None:
        """
        Initialize user profile.

        Args:
            max_history: Maximum number of inputs to track.
        """
        self.max_history = max_history
        self.input_history: deque[str] = deque(maxlen=max_history)

        # Behavioral metrics
        self.avg_length = 0.0
        self.avg_word_count = 0.0
        self.common_tokens: Counter[str] = Counter()
        self.typical_patterns: set[str] = set()

    def add_input(self, text: str) -> None:
        """
        Add a new input to the profile.

        Args:
            text: User input to add.
        """
        self.input_history.append(text)
        self._update_metrics()

    def _update_metrics(self) -> None:
        """Update behavioral metrics from history."""
        if not self.input_history:
            return

        # Calculate average length
        lengths = [len(text) for text in self.input_history]
        self.avg_length = sum(lengths) / len(lengths)

        # Calculate average word count
        word_counts = [len(text.split()) for text in self.input_history]
        self.avg_word_count = sum(word_counts) / len(word_counts)

        # Build common token frequency
        self.common_tokens = Counter()
        for text in self.input_history:
            tokens = re.findall(r"\w+", text.lower())
            self.common_tokens.update(tokens)

    def is_anomalous(self, text: str, threshold: float = 0.7) -> bool:
        """
        Check if text is anomalous for this user.

        Args:
            text: Text to check.
            threshold: Anomaly threshold 0-1.

        Returns:
            True if text is anomalous compared to user's pattern.
        """
        if len(self.input_history) < 10:  # Need baseline
            return False

        anomaly_score = 0.0

        # Check length anomaly
        length_diff = abs(len(text) - self.avg_length)
        if self.avg_length > 0:
            length_ratio = length_diff / self.avg_length
            if length_ratio > 2.0:  # More than 2x different
                anomaly_score += 0.3

        # Check word count anomaly
        word_count = len(text.split())
        word_diff = abs(word_count - self.avg_word_count)
        if self.avg_word_count > 0:
            word_ratio = word_diff / self.avg_word_count
            if word_ratio > 2.0:
                anomaly_score += 0.3

        # Check token overlap with typical vocabulary
        tokens = set(re.findall(r"\w+", text.lower()))
        if tokens:
            typical_tokens = set(self.common_tokens.keys())
            if typical_tokens:
                overlap = len(tokens & typical_tokens) / len(tokens)
                if overlap < 0.3:  # Less than 30% overlap
                    anomaly_score += 0.4

        return anomaly_score >= threshold


class ContextAwareDetector:
    """
    Detect prompt injection attempts with context awareness.

    Applies different detection rules based on the application context
    and tracks user behavior to detect anomalous inputs.
    """

    def __init__(
        self,
        pattern_detector: "PatternDetector | None" = None,
        max_history: int = 50,
    ) -> None:
        """
        Initialize context-aware detector.

        Args:
            pattern_detector: Optional PatternDetector for context-specific rules.
            max_history: Maximum number of inputs to track per user profile.
        """
        self.pattern_detector = pattern_detector
        self.max_history = max_history
        self.user_profiles: dict[str, UserProfile] = {}
        self.context_history: list[tuple[str, ContextType]] = []

    def get_user_profile(self, user_id: str) -> UserProfile:
        """
        Get or create user profile.

        Args:
            user_id: Unique user identifier.

        Returns:
            UserProfile for the user.
        """
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserProfile(max_history=self.max_history)
        return self.user_profiles[user_id]

    def detect_context_switch(
        self,
        current_context: ContextType,
        previous_context: ContextType | None = None,
    ) -> bool:
        """
        Detect suspicious context switches.

        Args:
            current_context: Current context type.
            previous_context: Previous context type (if any).

        Returns:
            True if context switch is suspicious.
        """
        if previous_context is None:
            return False

        # Suspicious switches
        suspicious_switches = [
            (ContextType.RAG_QUERY, ContextType.ADMIN_COMMAND),
            (ContextType.DATA_ANALYSIS, ContextType.ADMIN_COMMAND),
            (ContextType.CODE_GENERATION, ContextType.ADMIN_COMMAND),
        ]

        return (previous_context, current_context) in suspicious_switches

    def check_rag_specific_patterns(self, text: str) -> bool:
        """
        Check for RAG-specific injection patterns.

        RAG contexts are more permissive but still watch for:
        - Attempts to manipulate retrieval
        - Document override attempts
        - Source manipulation

        Args:
            text: Text to check.

        Returns:
            True if suspicious patterns found.
        """
        # RAG-specific injection patterns
        rag_patterns = [
            r"ignore\s+(?:the\s+)?retrieved\s+documents?",
            r"don'?t\s+use\s+the\s+(?:retrieved\s+)?(?:context|documents?)",
            r"override\s+(?:the\s+)?(?:retrieval|documents?|context)",
            r"pretend\s+the\s+documents?\s+say",
            r"act\s+as\s+if\s+(?:the\s+)?documents?",
        ]

        for pattern in rag_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False

    def check_code_injection_patterns(self, text: str) -> bool:
        """
        Check for code generation injection patterns.

        Code generation requires strict checks for:
        - Shell command injection
        - File system manipulation
        - Network operations
        - Privilege escalation

        Args:
            text: Text to check.

        Returns:
            True if suspicious patterns found.
        """
        # Code-specific injection patterns (stricter)
        code_patterns = [
            r"\beval\s*\(",
            r"\bexec\s*\(",
            r"\b__import__\s*\(",
            r"\bos\.system\s*\(",
            r"\bsubprocess\.",
            r"\brm\s+-rf\s+/",
            r"\b(?:curl|wget)\s+.*\|\s*(?:bash|sh)",
            r";\s*(?:rm|del|drop|delete)\s+",
        ]

        for pattern in code_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False

    def check_chat_patterns(self, text: str) -> bool:
        """
        Check for general chat injection patterns.

        Balanced checking for common injection attempts.

        Args:
            text: Text to check.

        Returns:
            True if suspicious patterns found (uses PatternDetector if available).
        """
        if self.pattern_detector:
            return self.pattern_detector.is_suspicious(text)

        # Fallback to basic checks if no pattern detector
        return False

    def is_suspicious_in_context(
        self,
        text: str,
        context_type: ContextType = ContextType.GENERAL,
        user_id: str | None = None,
    ) -> bool:
        """
        Check if text is suspicious given the context.

        Applies context-specific rules and checks user behavior anomalies.

        Args:
            text: Text to check.
            context_type: Type of context for the check.
            user_id: Optional user identifier for behavior tracking.

        Returns:
            True if text is suspicious in this context.
        """
        # Check context-specific patterns
        if context_type == ContextType.RAG_QUERY:
            if self.check_rag_specific_patterns(text):
                return True
        elif context_type == ContextType.CODE_GENERATION:
            if self.check_code_injection_patterns(text):
                return True
        elif context_type in (ContextType.GENERAL, ContextType.DATA_ANALYSIS):
            if self.check_chat_patterns(text):
                return True

        # Check for context switch anomalies
        if self.context_history:
            last_context = self.context_history[-1][1]
            if self.detect_context_switch(context_type, last_context):
                return True

        # Check user behavior anomalies
        if user_id:
            profile = self.get_user_profile(user_id)
            if profile.is_anomalous(text):
                return True

            # Update profile with this input
            profile.add_input(text)

        # Record context
        self.context_history.append((text, context_type))

        return False

    def get_context_score(
        self,
        text: str,
        context_type: ContextType = ContextType.GENERAL,
        user_id: str | None = None,
    ) -> float:
        """
        Get context anomaly score (0-1).

        Args:
            text: Text to analyze.
            context_type: Type of context.
            user_id: Optional user identifier.

        Returns:
            Context anomaly score 0-1.
        """
        score = 0.0

        # Context-specific pattern score
        if context_type == ContextType.RAG_QUERY:
            if self.check_rag_specific_patterns(text):
                score += 0.5
        elif context_type == ContextType.CODE_GENERATION:
            if self.check_code_injection_patterns(text):
                score += 0.7  # Higher weight for code injection
        elif context_type == ContextType.GENERAL:
            if self.check_chat_patterns(text):
                score += 0.6

        # Context switch score
        if self.context_history:
            last_context = self.context_history[-1][1]
            if self.detect_context_switch(context_type, last_context):
                score += 0.3

        # User behavior score
        if user_id:
            profile = self.get_user_profile(user_id)
            if len(profile.input_history) >= 10:
                # Calculate anomaly score
                length_diff = abs(len(text) - profile.avg_length)
                if profile.avg_length > 0:
                    length_ratio = length_diff / profile.avg_length
                    if length_ratio > 2.0:
                        score += 0.2

                # Token overlap
                tokens = set(re.findall(r"\w+", text.lower()))
                if tokens and profile.common_tokens:
                    typical_tokens = set(profile.common_tokens.keys())
                    overlap = len(tokens & typical_tokens) / len(tokens)
                    if overlap < 0.3:
                        score += 0.3

        return min(1.0, score)
