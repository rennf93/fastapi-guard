from guard.detection_engine import (
    ContentPreprocessor,
    PatternCompiler,
    PerformanceMonitor,
    SemanticAnalyzer,
    ThreatDetector,
)


def test_pattern_compiler() -> None:
    """Test pattern compilation and validation."""
    compiler = PatternCompiler()

    # Test safe pattern
    safe_pattern = r"<script[^>]*>"
    is_safe, reason = compiler.validate_pattern_safety(safe_pattern)
    assert is_safe is True

    # Test dangerous pattern
    dangerous_pattern = r"(.*)+"
    is_safe, reason = compiler.validate_pattern_safety(dangerous_pattern)
    assert is_safe is False
    assert "dangerous" in reason.lower()


async def test_content_preprocessor() -> None:
    """Test content preprocessing."""
    preprocessor = ContentPreprocessor()

    # Test Unicode normalization
    content = "ｓｃｒｉｐｔ"  # Full-width characters
    processed = await preprocessor.preprocess(content)
    assert "script" in processed.lower()

    # Test truncation preserves attack patterns
    attack = "<script>alert('xss')</script>" + "a" * 10000
    processed = await preprocessor.preprocess(attack)
    assert "<script>" in processed
    assert len(processed) <= preprocessor.max_content_length


async def test_semantic_analyzer() -> None:
    """Test semantic analysis."""
    analyzer = SemanticAnalyzer()

    # Test XSS detection
    xss_content = "<script>alert('xss')</script>"
    analysis = analyzer.analyze(xss_content)
    assert analysis["attack_probabilities"]["xss"] > 0.4

    # Test SQL injection detection
    sql_content = "' OR '1'='1' UNION SELECT * FROM users--"
    analysis = analyzer.analyze(sql_content)
    assert analysis["attack_probabilities"]["sql"] > 0.4


async def test_performance_monitor() -> None:
    """Test performance monitoring."""
    monitor = PerformanceMonitor()

    # Record some metrics
    await monitor.record_metric("test_pattern", 0.01, 100, True)
    await monitor.record_metric("test_pattern", 0.05, 200, False)
    await monitor.record_metric("slow_pattern", 0.2, 300, False)

    # Get stats
    stats = monitor.get_summary_stats()
    assert stats["total_executions"] == 3
    assert stats["match_rate"] > 0

    # Get slow patterns
    slow = monitor.get_slow_patterns()
    assert len(slow) > 0
    assert slow[0]["pattern"] == "slow_pattern"


async def test_threat_detector() -> None:
    """Test integrated threat detection."""
    patterns = [
        r"<script[^>]*>",
        r"javascript:",
        r"SELECT\s+.*\s+FROM",
    ]

    detector = ThreatDetector(
        patterns=patterns,
        enable_preprocessing=True,
        enable_semantic=True,
        enable_monitoring=True,
    )

    # Test XSS detection
    xss_content = "<script>alert('xss')</script>"
    result = await detector.detect(xss_content, "test")
    assert result["is_threat"] is True
    assert len(result["threats"]) > 0

    # Test SQL injection detection
    sql_content = "SELECT * FROM users WHERE id=1"
    result = await detector.detect(sql_content, "test")
    assert result["is_threat"] is True

    # Test clean content
    clean_content = "This is a normal message"
    result = await detector.detect(clean_content, "test")
    assert result["is_threat"] is False
