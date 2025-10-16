# guard/handlers/security_headers_handler.py
import hashlib
import json
import logging
import threading
from datetime import datetime, timezone
from typing import Any

from cachetools import TTLCache


class SecurityHeadersManager:
    """
    Manages security headers for HTTP responses following OWASP best practices.
    Implements singleton pattern for consistent header management across the app.
    """

    _instance: "SecurityHeadersManager | None" = None
    _lock = threading.Lock()
    headers_cache: TTLCache
    redis_handler: Any = None
    agent_handler: Any = None
    logger: logging.Logger
    enabled: bool
    custom_headers: dict[str, str]
    csp_config: dict[str, list[str]] | None
    hsts_config: dict[str, Any] | None
    cors_config: dict[str, Any] | None

    # Default security headers configuration
    default_headers: dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "X-Permitted-Cross-Domain-Policies": "none",
        "X-Download-Options": "noopen",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
    }

    def __new__(cls: type["SecurityHeadersManager"]) -> "SecurityHeadersManager":
        if cls._instance is None:
            with cls._lock:
                # Double-check inside lock to prevent race conditions
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.headers_cache = TTLCache(maxsize=1000, ttl=300)
                    cls._instance.redis_handler = None
                    cls._instance.agent_handler = None
                    cls._instance.logger = logging.getLogger(
                        "fastapi_guard.handlers.security_headers"
                    )
                    cls._instance.enabled = True
                    cls._instance.custom_headers = {}
                    cls._instance.csp_config = None
                    cls._instance.hsts_config = None
                    cls._instance.cors_config = None
                    # Create instance copy of default headers
                    cls._instance.default_headers = cls.default_headers.copy()
        return cls._instance

    def _validate_header_value(self, value: str) -> str:
        """Validate and sanitize header values to prevent injection attacks."""
        if "\r" in value or "\n" in value:
            raise ValueError(f"Invalid header value contains newline: {value}")
        if len(value) > 8192:
            raise ValueError(f"Header value too long: {len(value)} bytes")
        # Remove control characters except tab
        sanitized = "".join(char for char in value if ord(char) >= 32 or char == "\t")
        return sanitized

    def _generate_cache_key(self, request_path: str | None) -> str:
        """Generate secure cache key using hashing."""
        if not request_path:
            return "default"
        normalized = request_path.lower().strip("/")
        hash_obj = hashlib.sha256(normalized.encode())
        return f"path_{hash_obj.hexdigest()[:16]}"

    async def initialize_redis(self, redis_handler: Any) -> None:
        """Initialize Redis connection for caching header configurations."""
        self.redis_handler = redis_handler
        await self._load_cached_config()
        await self._cache_configuration()

    async def initialize_agent(self, agent_handler: Any) -> None:
        """Initialize agent integration for security event tracking."""
        self.agent_handler = agent_handler

    async def _load_cached_config(self) -> None:
        """Load header configuration from Redis if available."""
        if not self.redis_handler:
            return

        try:
            # Load CSP configuration
            csp_config = await self.redis_handler.get_key(
                "security_headers", "csp_config"
            )
            if csp_config:
                self.csp_config = json.loads(csp_config)

            # Load HSTS configuration
            hsts_config = await self.redis_handler.get_key(
                "security_headers", "hsts_config"
            )
            if hsts_config:
                self.hsts_config = json.loads(hsts_config)

            # Load custom headers
            custom_headers = await self.redis_handler.get_key(
                "security_headers", "custom_headers"
            )
            if custom_headers:
                self.custom_headers = json.loads(custom_headers)

        except Exception as e:
            self.logger.warning(f"Failed to load cached header config: {e}")

    def _configure_csp(self, csp: dict[str, list[str]] | None) -> None:
        """Configure Content Security Policy with validation."""
        if not csp:
            return

        self.csp_config = csp
        # Warn about unsafe directives
        for directive, sources in csp.items():
            if "'unsafe-inline'" in sources or "'unsafe-eval'" in sources:
                self.logger.warning(
                    f"CSP directive '{directive}' contains unsafe sources"
                )

    def _configure_hsts(
        self,
        hsts_max_age: int | None,
        hsts_include_subdomains: bool,
        hsts_preload: bool,
    ) -> None:
        """Configure HSTS with validation."""
        if hsts_max_age is None:
            return

        # Validate HSTS preload requirements
        if hsts_preload:
            if hsts_max_age < 31536000:
                self.logger.warning("HSTS preload requires max_age >= 31536000")
                hsts_preload = False
            if not hsts_include_subdomains:
                self.logger.warning("HSTS preload requires includeSubDomains")
                hsts_include_subdomains = True

        self.hsts_config = {
            "max_age": hsts_max_age,
            "include_subdomains": hsts_include_subdomains,
            "preload": hsts_preload,
        }

    def _configure_cors(
        self,
        cors_origins: list[str] | None,
        cors_allow_credentials: bool,
        cors_allow_methods: list[str] | None,
        cors_allow_headers: list[str] | None,
    ) -> None:
        """Configure CORS with security validation."""
        if not cors_origins:
            return

        # NOTE: Never allow credentials when using wildcard
        if "*" in cors_origins and cors_allow_credentials:
            self.logger.error(
                "CORS config error: Wildcard origin disallowed with credentials"
            )
            cors_allow_credentials = False

        self.cors_config = {
            "origins": cors_origins,
            "allow_credentials": cors_allow_credentials,
            "allow_methods": cors_allow_methods or ["GET", "POST"],
            "allow_headers": cors_allow_headers or ["*"],
        }

    def _update_default_headers(
        self,
        frame_options: str | None,
        content_type_options: str | None,
        xss_protection: str | None,
        referrer_policy: str | None,
        permissions_policy: str | None,
    ) -> None:
        """Update default security headers with validation."""
        if frame_options is not None:
            self.default_headers["X-Frame-Options"] = self._validate_header_value(
                frame_options
            )
        if content_type_options is not None:
            self.default_headers["X-Content-Type-Options"] = (
                self._validate_header_value(content_type_options)
            )
        if xss_protection is not None:
            self.default_headers["X-XSS-Protection"] = self._validate_header_value(
                xss_protection
            )
        if referrer_policy is not None:
            self.default_headers["Referrer-Policy"] = self._validate_header_value(
                referrer_policy
            )
        if permissions_policy != "UNSET":
            if permissions_policy:
                self.default_headers["Permissions-Policy"] = (
                    self._validate_header_value(permissions_policy)
                )
            else:
                # Remove Permissions-Policy only if
                # explicitly set to None, empty string or False
                self.default_headers.pop("Permissions-Policy", None)

    def _add_custom_headers(self, custom_headers: dict[str, str] | None) -> None:
        """Add custom headers with validation."""
        if not custom_headers:
            return

        for name, value in custom_headers.items():
            self.custom_headers[name] = self._validate_header_value(value)

    def configure(
        self,
        *,
        enabled: bool = True,
        csp: dict[str, list[str]] | None = None,
        hsts_max_age: int | None = None,
        hsts_include_subdomains: bool = True,
        hsts_preload: bool = False,
        frame_options: str | None = None,
        content_type_options: str | None = None,
        xss_protection: str | None = None,
        referrer_policy: str | None = None,
        permissions_policy: str | None = "UNSET",
        custom_headers: dict[str, str] | None = None,
        cors_origins: list[str] | None = None,
        cors_allow_credentials: bool = False,
        cors_allow_methods: list[str] | None = None,
        cors_allow_headers: list[str] | None = None,
    ) -> None:
        """
        Configure security headers settings.

        Args:
            enabled: Enable/disable security headers
            csp: Content Security Policy directives
            hsts_max_age: HSTS max-age in seconds (e.g., 31536000 for 1 year)
            hsts_include_subdomains: Include subdomains in HSTS
            hsts_preload: Enable HSTS preload
            frame_options: X-Frame-Options value (DENY, SAMEORIGIN)
            content_type_options: X-Content-Type-Options value
            xss_protection: X-XSS-Protection value
            referrer_policy: Referrer-Policy value
            permissions_policy: Permissions-Policy value
            custom_headers: Additional custom security headers
            cors_origins: Allowed CORS origins
            cors_allow_credentials: Allow credentials in CORS
            cors_allow_methods: Allowed CORS methods
            cors_allow_headers: Allowed CORS headers
        """
        self.enabled = enabled

        # Configure each component
        self._configure_csp(csp)
        self._configure_hsts(hsts_max_age, hsts_include_subdomains, hsts_preload)
        self._configure_cors(
            cors_origins, cors_allow_credentials, cors_allow_methods, cors_allow_headers
        )
        self._update_default_headers(
            frame_options,
            content_type_options,
            xss_protection,
            referrer_policy,
            permissions_policy,
        )
        self._add_custom_headers(custom_headers)

    async def _cache_configuration(self) -> None:
        """Cache current configuration in Redis for persistence."""
        if not self.redis_handler:
            return

        try:
            # Store configurations as JSON
            if self.csp_config:
                await self.redis_handler.set_key(
                    "security_headers",
                    "csp_config",
                    json.dumps(self.csp_config),
                    ttl=86400,
                )
            if self.hsts_config:
                await self.redis_handler.set_key(
                    "security_headers",
                    "hsts_config",
                    json.dumps(self.hsts_config),
                    ttl=86400,
                )
            if self.custom_headers:
                await self.redis_handler.set_key(
                    "security_headers",
                    "custom_headers",
                    json.dumps(self.custom_headers),
                    ttl=86400,
                )
        except Exception as e:
            self.logger.warning(f"Failed to cache header configuration: {e}")

    def _build_csp(self, csp_config: dict[str, list[str]]) -> str:
        """
        Build Content Security Policy string from configuration.

        Args:
            csp_config: Dictionary of CSP directives

        Returns:
            CSP header value
        """
        directives = []
        for directive, sources in csp_config.items():
            if sources:
                sources_str = " ".join(sources)
                directives.append(f"{directive} {sources_str}")
            else:
                directives.append(directive)
        return "; ".join(directives)

    def _build_hsts(self, hsts_config: dict[str, Any]) -> str:
        """
        Build HTTP Strict Transport Security header.

        Args:
            hsts_config: HSTS configuration

        Returns:
            HSTS header value
        """
        parts = [f"max-age={hsts_config['max_age']}"]
        if hsts_config.get("include_subdomains"):
            parts.append("includeSubDomains")
        if hsts_config.get("preload"):
            parts.append("preload")
        return "; ".join(parts)

    async def get_headers(self, request_path: str | None = None) -> dict[str, str]:
        """
        Get security headers for a response.

        Args:
            request_path: Optional request path for path-specific headers

        Returns:
            Dictionary of security headers
        """
        if not self.enabled:
            return {}

        # Check cache first with secure key generation
        cache_key = self._generate_cache_key(request_path)
        if cache_key in self.headers_cache:
            cached = self.headers_cache[cache_key]
            if isinstance(cached, dict):
                return cached

        headers = self.default_headers.copy()

        # Add CSP header
        if self.csp_config:
            headers["Content-Security-Policy"] = self._build_csp(self.csp_config)

        # Add HSTS header
        if self.hsts_config:
            headers["Strict-Transport-Security"] = self._build_hsts(self.hsts_config)

        # Add custom headers
        headers.update(self.custom_headers)

        # Cache the result
        self.headers_cache[cache_key] = headers

        # Send event to agent if configured
        if self.agent_handler and request_path:
            await self._send_headers_applied_event(request_path, headers)

        return headers

    def _is_wildcard_with_credentials(self, allowed_origins: list[str]) -> bool:
        """Check if invalid wildcard + credentials configuration."""
        if "*" not in allowed_origins:
            return False

        # NOTE: Never allow credentials when using wildcard
        if self.cors_config and self.cors_config.get("allow_credentials"):
            self.logger.warning(
                "Credentials cannot be used with wildcard origin - blocking CORS"
            )
            return True

        return False

    def _is_origin_allowed(self, origin: str, allowed_origins: list[str]) -> bool:
        """Check if origin is in allowed list."""
        return "*" in allowed_origins or origin in allowed_origins

    def _get_validated_cors_config(self) -> tuple[list[str], list[str]]:
        """
        Get validated CORS methods and headers.

        Returns:
            Tuple of (allow_methods, allow_headers)
        """
        if not self.cors_config:
            return ["GET", "POST"], ["*"]

        allow_methods = self.cors_config.get("allow_methods", ["GET", "POST"])
        allow_headers = self.cors_config.get("allow_headers", ["*"])

        # Validate types
        if not isinstance(allow_methods, list):
            allow_methods = ["GET", "POST"]
        if not isinstance(allow_headers, list):
            allow_headers = ["*"]

        return allow_methods, allow_headers

    def _build_cors_headers(
        self,
        origin: str,
        allowed_origins: list[str],
        allow_methods: list[str],
        allow_headers: list[str],
    ) -> dict[str, str]:
        """Build CORS response headers."""
        cors_headers = {
            "Access-Control-Allow-Origin": origin if origin in allowed_origins else "*",
            "Access-Control-Allow-Methods": ", ".join(allow_methods),
            "Access-Control-Allow-Headers": ", ".join(allow_headers),
            "Access-Control-Max-Age": "3600",
        }

        if self.cors_config and self.cors_config.get("allow_credentials"):
            cors_headers["Access-Control-Allow-Credentials"] = "true"

        return cors_headers

    async def get_cors_headers(self, origin: str) -> dict[str, str]:
        """
        Get CORS headers if origin is allowed.

        Args:
            origin: Request origin

        Returns:
            Dictionary of CORS headers
        """
        if not self.cors_config:
            return {}

        allowed_origins = self.cors_config.get("origins", [])
        if not isinstance(allowed_origins, list):
            return {}

        # Check for invalid wildcard + credentials configuration
        if self._is_wildcard_with_credentials(allowed_origins):
            return {}

        # Check if origin is allowed
        if not self._is_origin_allowed(origin, allowed_origins):
            return {}

        # Get validated config and build headers
        allow_methods, allow_headers = self._get_validated_cors_config()
        return self._build_cors_headers(
            origin, allowed_origins, allow_methods, allow_headers
        )

    async def _send_headers_applied_event(
        self, path: str, headers: dict[str, str]
    ) -> None:
        """Send security headers applied event to agent."""
        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="security_headers_applied",
                action_taken="headers_added",
                metadata={
                    "path": path,
                    "headers_count": len(headers),
                    "has_csp": "Content-Security-Policy" in headers,
                    "has_hsts": "Strict-Transport-Security" in headers,
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.debug(f"Failed to send headers event to agent: {e}")

    async def validate_csp_report(self, report: dict[str, Any]) -> bool:
        """
        Validate and process CSP violation reports.

        Args:
            report: CSP violation report

        Returns:
            True if report is valid
        """
        required_fields = ["document-uri", "violated-directive", "blocked-uri"]

        csp_report = report.get("csp-report", {})
        if not all(field in csp_report for field in required_fields):
            return False

        # Log the violation
        self.logger.warning(
            f"CSP Violation: {csp_report.get('violated-directive')} "
            f"blocked {csp_report.get('blocked-uri')} "
            f"on {csp_report.get('document-uri')}"
        )

        # Send to agent if configured
        if self.agent_handler:
            await self._send_csp_violation_event(csp_report)

        return True

    async def _send_csp_violation_event(self, report: dict[str, Any]) -> None:
        """Send CSP violation event to agent."""
        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="csp_violation",
                action_taken="logged",
                metadata={
                    "document_uri": report.get("document-uri"),
                    "violated_directive": report.get("violated-directive"),
                    "blocked_uri": report.get("blocked-uri"),
                    "source_file": report.get("source-file"),
                    "line_number": report.get("line-number"),
                },
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.debug(f"Failed to send CSP violation event to agent: {e}")

    async def reset(self) -> None:
        """Reset all security headers configuration."""
        self.headers_cache.clear()
        self.custom_headers.clear()
        self.csp_config = None
        self.hsts_config = None
        self.cors_config = None
        self.enabled = True
        # Reset default headers to original state
        self.default_headers = self.__class__.default_headers.copy()

        if self.redis_handler:
            try:
                async with self.redis_handler.get_connection() as conn:
                    keys = await conn.keys(
                        f"{self.redis_handler.config.redis_prefix}security_headers:*"
                    )
                    if keys:
                        await conn.delete(*keys)
            except Exception as e:
                self.logger.warning(f"Failed to clear Redis cache: {e}")


# Singleton instance
security_headers_manager = SecurityHeadersManager()


async def reset_global_state() -> None:
    """Reset global state for testing."""
    global security_headers_manager
    security_headers_manager = SecurityHeadersManager()
