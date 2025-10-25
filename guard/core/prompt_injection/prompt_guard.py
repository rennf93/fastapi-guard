# guard/core/prompt_injection/prompt_guard.py
from typing import Any, Literal

from guard.core.prompt_injection.canary_manager import CanaryManager
from guard.core.prompt_injection.format_strategies import FormatStrategyFactory
from guard.core.prompt_injection.pattern_detector import PatternDetector


class PromptInjectionAttempt(Exception):
    """Exception raised when a prompt injection attempt is detected."""

    def __init__(
        self,
        message: str = "Prompt injection attempt detected",
        matched_patterns: list[str] | None = None,
    ) -> None:
        """
        Initialize the exception.

        Args:
            message: Error message.
            matched_patterns: List of patterns that matched.
        """
        super().__init__(message)
        self.matched_patterns = matched_patterns or []


class PromptGuard:
    """
    Multi-layered defense system against prompt injection attacks.

    Provides configurable protection levels from basic pattern detection
    to paranoid mode with statistical analysis.
    """

    def __init__(
        self,
        protection_level: Literal[
            "basic", "standard", "strict", "paranoid"
        ] = "standard",
        format_strategy: Literal[
            "repr", "code_block", "byte_string", "xml_tags", "json_escape"
        ] = "repr",
        pattern_sensitivity: float = 0.7,
        custom_patterns: list[str] | None = None,
        enable_canary: bool = True,
        redis_manager: Any | None = None,
        use_redis_for_canaries: bool = True,
    ) -> None:
        """
        Initialize PromptGuard with specified protection configuration.

        Args:
            protection_level: Protection level to use.
                - basic: Pattern detection only
                - standard: Pattern + format manipulation
                - strict: Standard + canary tokens
                - paranoid: Strict + statistical anomaly detection
            format_strategy: Format manipulation strategy to use.
            pattern_sensitivity: Pattern detection sensitivity (0.0-1.0).
            custom_patterns: Additional regex patterns for detection.
            enable_canary: Whether to use canary tokens (strict+).
            redis_manager: Redis manager for distributed canary storage.
            use_redis_for_canaries: Whether to store canaries in Redis.
        """
        self.protection_level = protection_level

        # Bound and adjust sensitivity
        bounded_sensitivity = max(0.0, min(1.0, pattern_sensitivity))

        # Auto-adjust based on protection level if using default
        if pattern_sensitivity == 0.7:  # Using default
            if protection_level == "paranoid":
                self.pattern_sensitivity = 0.3  # Very strict
            elif protection_level == "strict":
                self.pattern_sensitivity = 0.5  # Strict
            else:
                self.pattern_sensitivity = bounded_sensitivity
        else:
            self.pattern_sensitivity = bounded_sensitivity

        self.enable_canary = enable_canary and protection_level in (
            "strict",
            "paranoid",
        )

        # Initialize pattern detector
        self.pattern_detector = PatternDetector(
            sensitivity=self.pattern_sensitivity,
            custom_patterns=custom_patterns,
        )

        # Initialize format strategy
        self.format_strategy = FormatStrategyFactory.get_strategy(format_strategy)

        # Initialize canary manager if needed
        self.canary_manager: CanaryManager | None = None
        if self.enable_canary:
            self.canary_manager = CanaryManager(
                redis_manager=redis_manager,
                use_redis=use_redis_for_canaries,
            )

        # Current session canary (for request-response pairing)
        self._current_canary: str | None = None

    def protect_input(self, user_input: str, session_id: str | None = None) -> str:
        """
        Protect user input through layered defense mechanisms.

        Args:
            user_input: Raw user input to protect.
            session_id: Optional session identifier.

        Returns:
            Sanitized input ready for LLM consumption.

        Raises:
            PromptInjectionAttempt: If injection attempt detected.
        """
        # Layer 1: Pattern detection (all levels)
        if self.pattern_detector.is_suspicious(user_input):
            matched = self.pattern_detector.get_matched_patterns(user_input)
            raise PromptInjectionAttempt(
                "Suspicious patterns detected in input",
                matched_patterns=matched,
            )

        # Layer 2: Format manipulation (standard+)
        sanitized = user_input
        if self.protection_level in ("standard", "strict", "paranoid"):
            sanitized = self.format_strategy.apply(user_input)

        # Layer 3: Canary injection (strict+)
        if self.enable_canary and self.canary_manager:
            self._current_canary = self.canary_manager.generate_canary(session_id)
            # Note: Canary is injected into system prompt, not user input
            # This is handled separately via inject_system_canary()

        return sanitized

    def inject_system_canary(self, system_prompt: str) -> str:
        """
        Inject canary token into system prompt.

        Should be called on system prompts when strict+ protection is enabled.

        Args:
            system_prompt: System prompt to inject canary into.

        Returns:
            System prompt with canary injection.
        """
        if (
            not self.enable_canary
            or not self.canary_manager
            or not self._current_canary
        ):
            return system_prompt

        return self.canary_manager.inject_canary(system_prompt, self._current_canary)

    def verify_output(self, llm_output: str) -> bool:
        """
        Verify LLM output for canary leakage.

        Args:
            llm_output: Output from LLM to verify.

        Returns:
            True if output is safe, False if canary leaked.
        """
        if (
            not self.enable_canary
            or not self.canary_manager
            or not self._current_canary
        ):
            return True

        is_safe = self.canary_manager.verify_output(llm_output, self._current_canary)

        # Clear current canary after verification
        self._current_canary = None

        return is_safe

    def get_protection_info(self) -> dict[str, bool | str | float]:
        """
        Get information about active protection mechanisms.

        Returns:
            Dictionary containing protection configuration.
        """
        return {
            "protection_level": self.protection_level,
            "pattern_detection": True,
            "format_manipulation": self.protection_level
            in (
                "standard",
                "strict",
                "paranoid",
            ),
            "format_strategy": self.format_strategy.strategy_name,
            "canary_tokens": self.enable_canary,
            "statistical_analysis": self.protection_level == "paranoid",
            "pattern_sensitivity": self.pattern_sensitivity,
        }
