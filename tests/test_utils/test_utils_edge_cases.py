from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi import Request

from guard.core.checks.helpers import is_referrer_domain_allowed
from guard.models import SecurityConfig
from guard.utils import (
    _extract_from_forwarded_header,
    _sanitize_for_log,
    detect_penetration_attempt,
    extract_client_ip,
)


class TestSanitizeForLog:
    """Test _sanitize_for_log edge cases."""

    def test_sanitize_empty_string(self) -> None:
        """Test sanitize with empty string returns empty string."""
        result = _sanitize_for_log("")
        assert result == ""

    def test_sanitize_none(self) -> None:
        """Test sanitize with None returns None."""
        result = _sanitize_for_log(None)  # type: ignore[arg-type]
        assert result is None

    def test_sanitize_with_content(self) -> None:
        """Test sanitize with actual content works."""
        result = _sanitize_for_log("test\nvalue")
        assert result == "test\\nvalue"


class TestExtractFromForwardedHeader:
    """Test _extract_from_forwarded_header edge cases."""

    def test_extract_empty_header(self) -> None:
        """Test extract with empty header returns None."""
        result = _extract_from_forwarded_header("", 1)
        assert result is None

    def test_extract_with_valid_header(self) -> None:
        """Test extract with valid header."""
        result = _extract_from_forwarded_header("1.2.3.4, 5.6.7.8", 2)
        assert result == "1.2.3.4"


class TestExtractClientIPExceptionHandling:
    """Test extract_client_ip exception handling."""

    @pytest.mark.asyncio
    async def test_extract_client_ip_with_invalid_forwarded_for(self) -> None:
        """Test extract_client_ip handles ValueError/IndexError gracefully."""
        request = Mock(spec=Request)
        request.client = Mock()
        request.client.host = "192.168.1.1"
        request.headers = {"X-Forwarded-For": "invalid-ip-format"}

        config = SecurityConfig()
        config.trusted_proxies = ["192.168.1.1"]
        config.trusted_proxy_depth = 999  # Force IndexError

        with patch(
            "guard.utils._extract_from_forwarded_header",
            side_effect=ValueError("Invalid IP"),
        ):
            # Should fall back to connecting IP without raising exception
            result = await extract_client_ip(request, config, None)
            assert result == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_extract_client_ip_logs_warning_on_error(self) -> None:
        """Test that extract_client_ip logs warning when exception occurs."""
        request = Mock(spec=Request)
        request.client = Mock()
        request.client.host = "192.168.1.1"
        request.headers = {"X-Forwarded-For": "1.2.3.4"}

        config = SecurityConfig()
        config.trusted_proxies = ["192.168.1.1"]
        config.trusted_proxy_depth = 1

        with (
            patch(
                "guard.utils._extract_from_forwarded_header",
                side_effect=IndexError("Test error"),
            ),
            patch("guard.utils.logging") as mock_logging,
        ):
            result = await extract_client_ip(request, config, None)

            # Should log warning about error processing
            assert result == "192.168.1.1"
            mock_logging.warning.assert_any_call(
                "Error processing client IP: Test error"
            )


class TestDetectPenetrationAttemptURLPath:
    """Test detect_penetration_attempt URL path checking."""

    @pytest.mark.asyncio
    async def test_detect_penetration_url_path_with_real_threat(self) -> None:
        """Test penetration detection in URL path with REAL threat."""
        # sus_patterns_handler is already initialized on import
        request = Mock(spec=Request)
        request.client = Mock()
        request.client.host = "1.2.3.4"
        request.query_params = {}  # Empty query params
        request.url = Mock()
        # Use REAL directory traversal pattern in URL path
        request.url.path = "/../../etc/passwd"
        request.headers = {}
        request.body = AsyncMock(return_value=b"")

        detected, trigger = await detect_penetration_attempt(request)

        # Should detect threat in URL path
        assert detected is True
        assert "URL path" in trigger


class TestReferrerDomainAllowedExceptionHandling:
    """Test is_referrer_domain_allowed exception handling."""

    def test_is_referrer_domain_allowed_with_none(self) -> None:
        """Test exception handling when referrer is None."""
        # exception handler returns False
        result = is_referrer_domain_allowed(None, ["example.com"])  # type: ignore
        assert result is False

    def test_is_referrer_domain_allowed_with_invalid_type(self) -> None:
        """Test exception handling when referrer is invalid type."""
        # exception handler returns False
        result = is_referrer_domain_allowed(12345, ["example.com"])  # type: ignore
        assert result is False

    def test_is_referrer_domain_allowed_with_malformed_url(self) -> None:
        """Test exception handling when URL parsing fails."""
        # exception handler returns False
        result = is_referrer_domain_allowed("://no-scheme", ["example.com"])
        assert result is False
