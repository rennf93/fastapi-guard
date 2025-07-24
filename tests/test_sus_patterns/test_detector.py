"""
Comprehensive tests for the ThreatDetector module.
"""

import logging
import re
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard.detection_engine.detector import ThreatDetector


def test_initialization() -> None:
    """Test ThreatDetector initialization."""
    patterns = [r"test\d+", r"pattern[a-z]+"]
    detector = ThreatDetector(
        patterns=patterns,
        enable_preprocessing=False,
        enable_semantic=False,
        enable_monitoring=False,
        pattern_timeout=10.0,
        semantic_threshold=0.8,
    )

    assert detector.patterns == patterns
    assert len(detector.compiled_patterns) == 2
    assert detector.enable_preprocessing is False
    assert detector.enable_semantic is False
    assert detector.enable_monitoring is False
    assert detector.semantic_threshold == 0.8
    assert detector.monitor is None


def test_compile_patterns_sync_with_invalid_pattern(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test _compile_patterns_sync with invalid regex pattern."""
    # Create patterns including an invalid one that passes safety check
    # but fails to compile
    patterns = [
        r"valid_pattern",
        r"(?P<invalid_name_with_bad_chars>test)",  # Invalid group name
        r"another_valid",
    ]

    # Mock validate_pattern_safety to pass for our invalid pattern
    with patch(
        'guard.detection_engine.detector.PatternCompiler'
    ) as mock_compiler_class:
        mock_compiler = MagicMock()
        mock_compiler_class.return_value = mock_compiler

        # Make validate_pattern_safety return True for all
        mock_compiler.validate_pattern_safety.return_value = (
            True, "Pattern appears safe"
        )

        # Make compile_pattern_sync raise error for our invalid pattern
        def compile_side_effect(pattern: str, flags: int | None = None) -> re.Pattern:
            if "invalid_name" in pattern:
                raise re.error("bad character in group name")
            return re.compile(pattern, flags or 0)

        mock_compiler.compile_pattern_sync.side_effect = compile_side_effect

        with caplog.at_level(logging.ERROR):
            detector = ThreatDetector(patterns=patterns, enable_monitoring=False)

        # Check that only valid patterns were compiled
        assert len(detector.compiled_patterns) == 2
        assert any(
            p for p in patterns
            if "valid_pattern" in p and p in detector.compiled_patterns
        )
        assert not any(
            p for p in patterns
            if "invalid_name" in p and p in detector.compiled_patterns
        )
        assert any(
            p for p in patterns
            if "another_valid" in p and p in detector.compiled_patterns
        )

        # Check error was logged
        assert "Failed to compile pattern" in caplog.text
        # The error message is stored in the 'extra' field, not in the main message


def test_compile_patterns_sync_with_unsafe_pattern(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test _compile_patterns_sync with unsafe pattern."""
    # Create patterns including a dangerous one
    patterns = [
        r"safe_pattern",
        r"(.*)+",  # Dangerous ReDoS pattern
        r"another_safe",
    ]

    with caplog.at_level(logging.WARNING):
        detector = ThreatDetector(patterns=patterns, enable_monitoring=False)

    # Check that only safe patterns were compiled
    assert len(detector.compiled_patterns) == 2
    assert "safe_pattern" in detector.compiled_patterns
    assert r"(.*)+" not in detector.compiled_patterns
    assert "another_safe" in detector.compiled_patterns

    # Check warning was logged
    assert "Pattern rejected as unsafe" in caplog.text


@pytest.mark.asyncio
async def test_compile_patterns_async_with_invalid_pattern() -> None:
    """Test _compile_patterns async method with invalid pattern."""
    detector_with_agent = ThreatDetector(
        patterns=[],
        enable_monitoring=False,
        agent_handler=MagicMock()
    )
    detector_with_agent.agent_handler.send_event = AsyncMock()

    # Add invalid patterns for async compilation
    detector_with_agent.patterns = [
        r"valid_pattern",
        r"(?P<invalid-name>test)",  # Invalid group name with hyphen
    ]

    # Clear compiled patterns to force recompilation
    detector_with_agent.compiled_patterns.clear()

    # Mock invalid pattern pass safety check but fail compilation
    with patch.object(
        detector_with_agent.compiler,
        'validate_pattern_safety',
    ) as mock_validate:
        with patch.object(
            detector_with_agent.compiler,
            'compile_pattern',
        ) as mock_compile:
            # All patterns pass safety check
            mock_validate.return_value = (True, "Pattern appears safe")

            # Make compile raise error for invalid pattern
            async def compile_side_effect(
                pattern: str,
                flags: int | None = None,
            ) -> re.Pattern:
                if "invalid-name" in pattern:
                    raise re.error("bad character in group name")
                return re.compile(pattern, flags or re.IGNORECASE | re.MULTILINE)

            mock_compile.side_effect = compile_side_effect

            # Run async compilation
            await detector_with_agent._compile_patterns()

    # Check only valid pattern was compiled
    assert len(detector_with_agent.compiled_patterns) == 1
    assert "valid_pattern" in detector_with_agent.compiled_patterns

    # Check event was sent to agent
    detector_with_agent.agent_handler.send_event.assert_called()
    call_args = detector_with_agent.agent_handler.send_event.call_args[0][0]
    assert call_args.event_type == "pattern_compilation_error"
    assert call_args.action_taken == "compilation_failed"
    assert "Failed to compile pattern" in call_args.reason


@pytest.mark.asyncio
async def test_compile_patterns_async_with_unsafe_pattern() -> None:
    """Test _compile_patterns async method with unsafe pattern."""
    detector_with_agent = ThreatDetector(
        patterns=[],
        enable_monitoring=False,
        agent_handler=MagicMock()
    )
    detector_with_agent.agent_handler.send_event = AsyncMock()

    # Add unsafe patterns for async compilation
    detector_with_agent.patterns = [
        r"safe_pattern",
        r"(.*)+",  # Dangerous ReDoS pattern
    ]

    # Clear compiled patterns to force recompilation
    detector_with_agent.compiled_patterns.clear()

    # Run async compilation
    await detector_with_agent._compile_patterns()

    # Check only safe pattern was compiled
    assert len(detector_with_agent.compiled_patterns) == 1
    assert "safe_pattern" in detector_with_agent.compiled_patterns

    # Check event was sent to agent
    detector_with_agent.agent_handler.send_event.assert_called()
    call_args = detector_with_agent.agent_handler.send_event.call_args[0][0]
    assert call_args.event_type == "unsafe_pattern_detected"
    assert call_args.action_taken == "pattern_rejected"
    assert "Pattern rejected as unsafe" in call_args.reason


@pytest.mark.asyncio
async def test_add_pattern_unsafe() -> None:
    """Test add_pattern with unsafe pattern."""
    detector = ThreatDetector(patterns=[], enable_monitoring=False)

    # Try to add a dangerous pattern
    dangerous_pattern = r"(.*)+$"
    result = await detector.add_pattern(dangerous_pattern)

    assert result is False
    assert dangerous_pattern not in detector.patterns
    assert dangerous_pattern not in detector.compiled_patterns


@pytest.mark.asyncio
async def test_add_pattern_invalid() -> None:
    """Test add_pattern with invalid regex."""
    detector = ThreatDetector(patterns=[], enable_monitoring=False)

    # Mock to make pattern pass safety check but fail compilation
    with patch.object(
        detector.compiler,
        'validate_pattern_safety',
        return_value=(True, "safe"),
    ):
        with patch.object(
            detector.compiler,
            'compile_pattern',
            side_effect=re.error("invalid pattern"),
        ):
            # Try to add an invalid pattern
            invalid_pattern = r"invalid(pattern"
            result = await detector.add_pattern(invalid_pattern)

            assert result is False
            assert invalid_pattern not in detector.patterns
            assert invalid_pattern not in detector.compiled_patterns


@pytest.mark.asyncio
async def test_add_pattern_success() -> None:
    """Test successful pattern addition."""
    detector = ThreatDetector(patterns=[], enable_monitoring=False)

    # Add a valid pattern
    valid_pattern = r"test_pattern_\d+"
    result = await detector.add_pattern(valid_pattern)

    assert result is True
    assert valid_pattern in detector.patterns
    assert valid_pattern in detector.compiled_patterns


@pytest.mark.asyncio
async def test_remove_pattern_success() -> None:
    """Test successful pattern removal."""
    # Create detector with monitoring enabled
    patterns = [r"pattern1", r"pattern2"]
    detector = ThreatDetector(patterns=patterns, enable_monitoring=True)

    # Mock the monitor's remove_pattern_stats method
    if detector.monitor:
        mock_remove_stats = AsyncMock()
        with patch.object(detector.monitor, 'remove_pattern_stats', mock_remove_stats):
            # Remove a pattern
            result = await detector.remove_pattern("pattern1")

            assert result is True
            assert "pattern1" not in detector.patterns
            assert "pattern1" not in detector.compiled_patterns
            mock_remove_stats.assert_called_once_with("pattern1")


@pytest.mark.asyncio
async def test_remove_pattern_not_found() -> None:
    """Test removing non-existent pattern."""
    detector = ThreatDetector(patterns=[r"pattern1"], enable_monitoring=False)

    result = await detector.remove_pattern("non_existent")

    assert result is False
    assert len(detector.patterns) == 1


@pytest.mark.asyncio
async def test_detect_regex_threats_with_timeout() -> None:
    """Test detect_regex_threats with timeout exception."""
    detector = ThreatDetector(patterns=[r"test_pattern"], enable_monitoring=True)

    # Mock the safe matcher to raise a timeout exception
    def mock_match_func(text: str) -> bool:
        raise Exception("timeout occurred")

    with patch.object(
        detector.compiler,
        'create_safe_matcher',
        return_value=mock_match_func,
    ):
        threats = await detector.detect_regex_threats("test content")

        # Should handle the timeout gracefully
        assert threats == []

        # Check that timeout was recorded in monitor
        if detector.monitor:
            # Look for patterns with timeouts
            problematic = detector.monitor.get_problematic_patterns()
            timeout_patterns = [p for p in problematic if p.get('timeout_rate', 0) > 0]
            assert len(timeout_patterns) > 0


def test_detect_semantic_threats_disabled() -> None:
    """Test detect_semantic_threats when semantic analysis is disabled."""
    detector = ThreatDetector(
        patterns=[r"test"],
        enable_semantic=False,
        enable_monitoring=False
    )

    threats = detector.detect_semantic_threats("malicious content")

    assert threats == []


def test_detect_semantic_threats_with_specific_attacks() -> None:
    """Test detect_semantic_threats with specific attack types."""
    detector = ThreatDetector(
        patterns=[],
        enable_semantic=True,
        enable_monitoring=False,
        semantic_threshold=0.5
    )

    # Mock semantic analyzer to return high probabilities
    mock_analysis = {
        "attack_probabilities": {
            "xss": 0.8,
            "sql": 0.6,
            "command": 0.3  # Below threshold
        }
    }

    with patch.object(
        detector.semantic_analyzer,
        'analyze',
        return_value=mock_analysis,
    ):
        with patch.object(
            detector.semantic_analyzer,
            'get_threat_score',
            return_value=0.8,
        ):
            threats = detector.detect_semantic_threats("<script>alert(1)</script>")

    # Should detect xss and sql but not command
    assert len(threats) == 2
    assert any(t["attack_type"] == "xss" for t in threats)
    assert any(t["attack_type"] == "sql" for t in threats)
    assert not any(t["attack_type"] == "command" for t in threats)


def test_detect_semantic_threats_general_suspicious() -> None:
    """Test detect_semantic_threats with general suspicious behavior."""
    detector = ThreatDetector(
        patterns=[],
        enable_semantic=True,
        enable_monitoring=False,
        semantic_threshold=0.7
    )

    # Mock semantic analyzer to return high score but no specific attacks
    mock_analysis = {
        "attack_probabilities": {
            "xss": 0.3,
            "sql": 0.2,
        }
    }

    with patch.object(
        detector.semantic_analyzer,
        'analyze',
        return_value=mock_analysis,
    ):
        with patch.object(
            detector.semantic_analyzer,
            'get_threat_score',
            return_value=0.8,
        ):
            threats = detector.detect_semantic_threats("suspicious content")

    # Should detect general suspicious behavior
    assert len(threats) == 1
    assert threats[0]["attack_type"] == "suspicious"
    assert threats[0]["threat_score"] == 0.8


def test_get_performance_stats_disabled() -> None:
    """Test get_performance_stats when monitoring is disabled."""
    detector = ThreatDetector(
        patterns=[r"test"],
        enable_monitoring=False
    )

    stats = detector.get_performance_stats()

    assert stats is None


def test_get_performance_stats_enabled() -> None:
    """Test get_performance_stats when monitoring is enabled."""
    detector = ThreatDetector(
        patterns=[r"test"],
        enable_monitoring=True
    )

    # Mock monitor methods
    if detector.monitor:
        with patch.object(
            detector.monitor, 'get_summary_stats', return_value={"total": 10}
        ):
            with patch.object(
                detector.monitor,
                'get_slow_patterns',
                return_value=[],
            ):
                with patch.object(
                    detector.monitor,
                    'get_problematic_patterns',
                    return_value=[],
                ):
                    stats = detector.get_performance_stats()

                    assert stats is not None
                    assert "summary" in stats
                    assert "slow_patterns" in stats
                    assert "problematic_patterns" in stats
                    assert stats["summary"]["total"] == 10


def test_register_anomaly_callback() -> None:
    """Test register_anomaly_callback."""
    detector = ThreatDetector(
        patterns=[r"test"],
        enable_monitoring=True
    )

    # Register a callback
    def callback(anomaly: Any) -> None:
        pass  # pragma: no cover

    if detector.monitor:
        with patch.object(
            detector.monitor,
            'register_anomaly_callback',
        ) as mock_register:
            detector.register_anomaly_callback(callback)
            mock_register.assert_called_once_with(callback)


def test_register_anomaly_callback_no_monitor() -> None:
    """Test register_anomaly_callback when monitoring is disabled."""
    detector = ThreatDetector(
        patterns=[r"test"],
        enable_monitoring=False
    )

    # Should not raise an error
    def callback(anomaly: Any) -> None:
        pass  # pragma: no cover

    detector.register_anomaly_callback(callback)  # Should do nothing


@pytest.mark.asyncio
async def test_send_detector_event_no_agent() -> None:
    """Test _send_detector_event when no agent handler."""
    detector = ThreatDetector(
        patterns=[r"test"],
        enable_monitoring=False,
        agent_handler=None
    )

    # Should return early without error
    await detector._send_detector_event(
        event_type="test_event",
        action_taken="test_action",
        reason="test_reason"
    )


@pytest.mark.asyncio
async def test_send_detector_event_with_agent() -> None:
    """Test _send_detector_event with agent handler."""
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock()

    detector = ThreatDetector(
        patterns=[r"test"],
        enable_monitoring=False,
        agent_handler=agent_handler
    )

    await detector._send_detector_event(
        event_type="test_event",
        action_taken="test_action",
        reason="test_reason",
        extra_data="test_value"
    )

    # Check event was sent
    agent_handler.send_event.assert_called_once()
    event = agent_handler.send_event.call_args[0][0]
    assert event.event_type == "test_event"
    assert event.action_taken == "test_action"
    assert event.reason == "test_reason"
    assert event.metadata["extra_data"] == "test_value"


@pytest.mark.asyncio
async def test_send_detector_event_with_error(caplog: pytest.LogCaptureFixture) -> None:
    """Test _send_detector_event with agent error."""
    agent_handler = MagicMock()
    agent_handler.send_event = AsyncMock(side_effect=Exception("Agent error"))

    detector = ThreatDetector(
        patterns=[r"test"],
        enable_monitoring=False,
        agent_handler=agent_handler
    )

    with caplog.at_level(logging.ERROR):
        await detector._send_detector_event(
            event_type="test_event",
            action_taken="test_action",
            reason="test_reason"
        )

    # Should log error but not raise
    assert "Failed to send detector event to agent" in caplog.text
    assert "Agent error" in caplog.text


@pytest.mark.asyncio
async def test_detect_full_flow() -> None:
    """Test the full detect flow with all components enabled."""
    detector = ThreatDetector(
        patterns=[r"<script[^>]*>", r"SELECT\s+.*\s+FROM"],
        enable_preprocessing=True,
        enable_semantic=True,
        enable_monitoring=True,
        semantic_threshold=0.5
    )

    # Mock semantic analyzer
    mock_analysis = {
        "attack_probabilities": {
            "xss": 0.9,
        }
    }
    with patch.object(
        detector.semantic_analyzer,
        'analyze',
        return_value=mock_analysis,
    ):
        with patch.object(
            detector.semantic_analyzer,
            'get_threat_score',
            return_value=0.9,
        ):
            # Test with XSS content
            result = await detector.detect("<script>alert(1)</script>", context="body")

    assert result["is_threat"] is True
    assert result["threat_score"] == 1.0  # Max of regex (1.0) and semantic (0.9)
    assert len(result["threats"]) >= 2  # At least regex and semantic
    assert result["context"] == "body"
    assert result["execution_time"] > 0


@pytest.mark.asyncio
async def test_detect_with_preprocessing() -> None:
    """Test detect with content preprocessing."""
    detector = ThreatDetector(
        patterns=[r"<script[^>]*>"],
        enable_preprocessing=True,
        enable_semantic=False,
        enable_monitoring=False
    )

    # Test with URL-encoded XSS
    encoded_xss = "%3Cscript%3Ealert(1)%3C/script%3E"

    # Mock preprocessor to decode the content
    with patch.object(
        detector.preprocessor,
        'preprocess',
        return_value="<script>alert(1)</script>"
    ) as mock_preprocess:
        result = await detector.detect(encoded_xss)

    mock_preprocess.assert_called_once_with(encoded_xss)
    assert result["is_threat"] is True
    assert result["original_length"] == len(encoded_xss)
    assert result["processed_length"] == len("<script>alert(1)</script>")