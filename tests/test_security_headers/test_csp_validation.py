from typing import Any

import pytest

from guard.handlers.security_headers_handler import SecurityHeadersManager


@pytest.mark.asyncio
async def test_csp_report_validation() -> None:
    """Test CSP violation report validation."""
    manager = SecurityHeadersManager()

    # Valid report
    valid_report = {
        "csp-report": {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
        }
    }
    assert await manager.validate_csp_report(valid_report) is True

    # Invalid report (missing required fields)
    invalid_report = {
        "csp-report": {
            "document-uri": "https://example.com",
        }
    }
    assert await manager.validate_csp_report(invalid_report) is False

    # Empty report
    empty_report: dict[str, Any] = {}
    assert await manager.validate_csp_report(empty_report) is False


@pytest.mark.asyncio
async def test_build_csp_with_empty_sources() -> None:
    """Test CSP building with directives that have empty sources."""
    manager = SecurityHeadersManager()

    csp_config = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdn.com"],
        "upgrade-insecure-requests": [],  # Directive with no sources
        "block-all-mixed-content": [],  # Another directive with no sources
    }

    csp_header = manager._build_csp(csp_config)

    # Should include directives with sources
    assert "default-src 'self'" in csp_header
    assert "script-src 'self' https://cdn.com" in csp_header

    # Should include directives without sources (standalone directives)
    assert "upgrade-insecure-requests" in csp_header
    assert "block-all-mixed-content" in csp_header

    # These should not have sources after them
    assert "upgrade-insecure-requests;" in csp_header or csp_header.endswith(
        "upgrade-insecure-requests"
    )
    assert "block-all-mixed-content;" in csp_header or csp_header.endswith(
        "block-all-mixed-content"
    )


@pytest.mark.asyncio
async def test_csp_unsafe_inline_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Test that unsafe-inline in CSP triggers a warning."""
    manager = SecurityHeadersManager()

    manager.configure(
        csp={
            "script-src": ["'self'", "'unsafe-inline'"],
            "style-src": ["'self'", "'unsafe-eval'"],
        }
    )

    # Check warnings were logged
    assert "CSP directive 'script-src' contains unsafe sources" in caplog.text
    assert "CSP directive 'style-src' contains unsafe sources" in caplog.text


@pytest.mark.asyncio
async def test_csp_safe_directives_no_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Test that safe CSP directives don't trigger warnings."""
    manager = SecurityHeadersManager()

    manager.configure(
        csp={
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://trusted.com"],
            "style-src": ["'self'", "'nonce-abc123'"],
        }
    )

    # No warnings should be logged
    assert "unsafe sources" not in caplog.text
