import logging
import re
import time
from typing import Any

from .compiler import PatternCompiler
from .monitor import PerformanceMonitor
from .preprocessor import ContentPreprocessor
from .semantic import SemanticAnalyzer


class ThreatDetector:
    """
    Enhanced security detection engine that addresses bypass vulnerabilities
    while maintaining ReDoS protection.

    This class provides multi-layered threat detection combining:
    - Existing regex patterns with timeout protection
    - Content preprocessing for bypass prevention
    - Semantic analysis for bypass-resistant detection
    - Hybrid detection approaches
    """

    def __init__(
        self,
        patterns: list[str],
        enable_preprocessing: bool = True,
        enable_semantic: bool = True,
        enable_monitoring: bool = True,
        pattern_timeout: float = 5.0,
        semantic_threshold: float = 0.7,
        agent_handler: Any = None,
    ):
        """
        Initialize the ThreatDetector.

        Args:
            patterns: List of regex patterns to use for detection
            enable_preprocessing: Whether to preprocess content
            enable_semantic: Whether to use semantic analysis
            enable_monitoring: Whether to monitor performance
            pattern_timeout: Timeout for pattern matching (seconds)
            semantic_threshold: Threshold for semantic threat detection (0-1)
        """
        self.enable_preprocessing = enable_preprocessing
        self.enable_semantic = enable_semantic
        self.enable_monitoring = enable_monitoring
        self.semantic_threshold = semantic_threshold
        self.agent_handler = agent_handler
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.compiler = PatternCompiler(default_timeout=pattern_timeout)
        self.preprocessor = ContentPreprocessor()
        self.semantic_analyzer = SemanticAnalyzer()
        self.monitor = PerformanceMonitor() if enable_monitoring else None

        # Compile patterns
        self.patterns = patterns
        self.compiled_patterns: dict[str, re.Pattern] = {}
        # NOTE: _compile_patterns is async but called from __init__
        # This is a design issue - should be called separately
        # For now, compile patterns synchronously
        self._compile_patterns_sync()

    def _compile_patterns_sync(self) -> None:
        """Synchronous version of pattern compilation for __init__."""
        for pattern in self.patterns:
            is_safe, reason = self.compiler.validate_pattern_safety(pattern)
            if is_safe:
                try:
                    compiled = self.compiler.compile_pattern_sync(pattern)
                    self.compiled_patterns[pattern] = compiled
                except re.error as e:
                    # Log to standard logger since we can't use async here
                    self.logger.error(
                        f"Failed to compile pattern: {pattern[:50]}...",
                        extra={"error": str(e), "pattern": pattern[:100]}
                    )
            else:
                # Log to standard logger since we can't use async here
                self.logger.warning(
                    f"Pattern rejected as unsafe: {reason}",
                    extra={"pattern": pattern[:100], "safety_reason": reason}
                )

    async def _compile_patterns(self) -> None:
        """Compile and validate all patterns."""
        for pattern in self.patterns:
            is_safe, reason = self.compiler.validate_pattern_safety(pattern)
            if is_safe:
                try:
                    compiled = await self.compiler.compile_pattern(pattern)
                    self.compiled_patterns[pattern] = compiled
                except re.error as e:
                    # Log pattern compilation error
                    await self._send_detector_event(
                        event_type="pattern_compilation_error",
                        action_taken="compilation_failed",
                        reason=f"Failed to compile pattern: {pattern[:50]}...",
                        error=str(e),
                        pattern=pattern[:100],
                    )
            else:
                # Log unsafe pattern
                await self._send_detector_event(
                    event_type="unsafe_pattern_detected",
                    action_taken="pattern_rejected",
                    reason=f"Pattern rejected as unsafe: {reason}",
                    pattern=pattern[:100],
                    safety_reason=reason,
                )

    async def add_pattern(self, pattern: str) -> bool:
        """
        Add a new pattern to the detector.

        Args:
            pattern: The regex pattern to add

        Returns:
            True if pattern was added successfully
        """
        is_safe, reason = self.compiler.validate_pattern_safety(pattern)
        if not is_safe:
            return False

        try:
            compiled = await self.compiler.compile_pattern(pattern)
            self.patterns.append(pattern)
            self.compiled_patterns[pattern] = compiled
            return True
        except re.error:
            return False

    async def remove_pattern(self, pattern: str) -> bool:
        """
        Remove a pattern from the detector.

        Args:
            pattern: The pattern to remove

        Returns:
            True if pattern was removed successfully
        """
        if pattern in self.patterns:
            self.patterns.remove(pattern)
            if pattern in self.compiled_patterns:
                del self.compiled_patterns[pattern]
            if self.monitor:
                await self.monitor.remove_pattern_stats(pattern)
            return True
        return False

    async def detect_regex_threats(self, content: str) -> list[dict[str, Any]]:
        """
        Detect threats using regex patterns.

        Args:
            content: The content to check

        Returns:
            List of detected threats with metadata
        """
        threats = []

        for pattern_str, _ in self.compiled_patterns.items():
            start_time = time.time()
            timeout = False
            matched = False

            try:
                # Use the safe matcher from compiler
                safe_matcher = self.compiler.create_safe_matcher(pattern_str)
                match = safe_matcher(content)
                matched = match is not None

                if matched:
                    threats.append(
                        {
                            "type": "regex",
                            "pattern": pattern_str,
                            "match": match.group() if match else None,
                            "position": match.start() if match else None,
                        }
                    )
            except Exception as e:
                if "timeout" in str(e).lower():
                    timeout = True

            # Record performance metric
            if self.monitor:
                execution_time = time.time() - start_time
                await self.monitor.record_metric(
                    pattern=pattern_str,
                    execution_time=execution_time,
                    content_length=len(content),
                    matched=matched,
                    timeout=timeout,
                )

        return threats

    def detect_semantic_threats(self, content: str) -> list[dict[str, Any]]:
        """
        Detect threats using semantic analysis.

        Args:
            content: The content to check

        Returns:
            List of detected threats with metadata
        """
        if not self.enable_semantic:
            return []

        threats = []
        analysis = self.semantic_analyzer.analyze(content)
        threat_score = self.semantic_analyzer.get_threat_score(analysis)

        if threat_score >= self.semantic_threshold:
            # Identify specific threat types
            attack_probs = analysis.get("attack_probabilities", {})
            for attack_type, probability in attack_probs.items():
                if probability >= self.semantic_threshold:
                    threats.append(
                        {
                            "type": "semantic",
                            "attack_type": attack_type,
                            "probability": probability,
                            "analysis": analysis,
                        }
                    )

            # Check for general suspicious behavior
            if not threats and threat_score >= self.semantic_threshold:
                threats.append(
                    {
                        "type": "semantic",
                        "attack_type": "suspicious",
                        "threat_score": threat_score,
                        "analysis": analysis,
                    }
                )

        return threats

    async def detect(self, content: str, context: str | None = None) -> dict[str, Any]:
        """
        Perform comprehensive threat detection.

        Args:
            content: The content to check
            context: Optional context information (e.g., "header", "body", "query")

        Returns:
            Detection results dictionary
        """
        start_time = time.time()
        original_content = content

        # Preprocess content if enabled
        if self.enable_preprocessing:
            content = await self.preprocessor.preprocess(content)

        # Detect using regex patterns
        regex_threats = await self.detect_regex_threats(content)

        # Detect using semantic analysis
        semantic_threats = self.detect_semantic_threats(content)

        # Combine results
        all_threats = regex_threats + semantic_threats
        is_threat = len(all_threats) > 0

        # Calculate overall threat score
        threat_score = 0.0
        if all_threats:
            # Take the maximum threat score from all detections
            regex_score = 1.0 if regex_threats else 0.0
            semantic_scores = [
                t.get("probability", t.get("threat_score", 0.0))
                for t in semantic_threats
            ]
            semantic_score = max(semantic_scores) if semantic_scores else 0.0
            threat_score = max(regex_score, semantic_score)

        result = {
            "is_threat": is_threat,
            "threat_score": threat_score,
            "threats": all_threats,
            "context": context,
            "original_length": len(original_content),
            "processed_length": len(content),
            "execution_time": time.time() - start_time,
        }

        return result

    def get_performance_stats(self) -> dict[str, Any] | None:
        """
        Get performance statistics.

        Returns:
            Performance statistics or None if monitoring disabled
        """
        if not self.monitor:
            return None

        return {
            "summary": self.monitor.get_summary_stats(),
            "slow_patterns": self.monitor.get_slow_patterns(),
            "problematic_patterns": self.monitor.get_problematic_patterns(),
        }

    def register_anomaly_callback(self, callback: Any) -> None:
        """
        Register a callback for performance anomalies.

        Args:
            callback: Function to call when anomaly detected
        """
        if self.monitor:
            self.monitor.register_anomaly_callback(callback)

    async def _send_detector_event(
        self,
        event_type: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """Send detector-related events to agent."""
        if not self.agent_handler:
            return

        try:
            from datetime import datetime, timezone

            event = type('SecurityEvent', (), {
                "timestamp": datetime.now(timezone.utc),
                "event_type": event_type,
                "ip_address": "system",
                "action_taken": action_taken,
                "reason": reason,
                "metadata": kwargs,
            })()
            await self.agent_handler.send_event(event)
        except Exception as e:
            # Don't let agent errors break detector functionality
            self.logger.error(f"Failed to send detector event to agent: {e}")
