# fastapi_guard/middleware.py
import logging
import re
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from guard.checks.pipeline import SecurityCheckPipeline
from guard.decorators.base import BaseSecurityDecorator, RouteConfig
from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ipban_handler import ip_ban_manager
from guard.handlers.ratelimit_handler import RateLimitManager
from guard.handlers.security_headers_handler import security_headers_manager
from guard.handlers.suspatterns_handler import sus_patterns_handler
from guard.models import SecurityConfig
from guard.utils import (
    detect_penetration_attempt,
    extract_client_ip,
    is_ip_allowed,
    is_user_agent_allowed,
    log_activity,
    setup_custom_logging,
)


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Middleware for implementing various
    security measures in a FastAPI application.

    This middleware handles rate limiting,
    IP filtering, user agent filtering,
    and detection of potential
    penetration attempts.
    """

    def __init__(self, app: ASGIApp, *, config: SecurityConfig) -> None:
        """
        Initialize the SecurityMiddleware.

        Args:
            app (FastAPI):
                The FastAPI application.
            config (SecurityConfig):
                Configuration object for security settings.
        """
        super().__init__(app)
        self.app = app
        self.config = config
        self.logger = setup_custom_logging(config.custom_log_file)
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, int] = {}
        self.last_cleanup = time.time()
        self.rate_limit_handler = RateLimitManager(config)
        self.guard_decorator: BaseSecurityDecorator | None = None

        self._configure_security_headers(config)

        self.geo_ip_handler = None
        if config.whitelist_countries or config.blocked_countries:
            self.geo_ip_handler = config.geo_ip_handler

        # Initialize Redis handler if enabled
        self.redis_handler = None
        if config.enable_redis:
            from guard.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(config)

        # Initialize agent handler if enabled
        self.agent_handler = None
        if config.enable_agent:
            agent_config = config.to_agent_config()
            if agent_config:
                try:
                    from guard_agent import guard_agent

                    self.agent_handler = guard_agent(agent_config)
                    self.logger.info("Guard Agent initialized successfully")
                except ImportError:
                    self.logger.warning(
                        "Agent enabled but guard_agent package not installed. "
                        "Install with: pip install fastapi-guard-agent"
                    )
                except Exception as e:
                    self.logger.error(f"Failed to initialize Guard Agent: {e}")
                    self.logger.warning("Continuing without agent functionality")
            else:
                self.logger.warning(
                    "Agent enabled but configuration is invalid. "
                    "Check agent_api_key and other required fields."
                )

        # Initialize security check pipeline (will be built in initialize())
        self.security_pipeline: SecurityCheckPipeline | None = None

    def _build_security_pipeline(self) -> None:
        """Build the security check pipeline with configured checks."""
        from guard.checks import (
            AuthenticationCheck,
            CloudIpRefreshCheck,
            CloudProviderCheck,
            CustomRequestCheck,
            CustomValidatorsCheck,
            HttpsEnforcementCheck,
            IpSecurityCheck,
            RateLimitCheck,
            ReferrerCheck,
            RequestLoggingCheck,
            RequestSizeContentCheck,
            RequiredHeadersCheck,
            RouteConfigCheck,
            SecurityCheckPipeline,
            SuspiciousActivityCheck,
            TimeWindowCheck,
            UserAgentCheck,
        )

        checks = [
            # Always first: extract route config and client IP
            RouteConfigCheck(self),
            # HTTPS enforcement (can redirect)
            HttpsEnforcementCheck(self),
            # Request logging
            RequestLoggingCheck(self),
            # Request validation checks
            RequestSizeContentCheck(self),
            RequiredHeadersCheck(self),
            AuthenticationCheck(self),
            ReferrerCheck(self),
            CustomValidatorsCheck(self),
            TimeWindowCheck(self),
            # Periodic maintenance
            CloudIpRefreshCheck(self),
            # IP-based checks
            IpSecurityCheck(self),
            CloudProviderCheck(self),
            UserAgentCheck(self),
            # Rate limiting
            RateLimitCheck(self),
            # Threat detection
            SuspiciousActivityCheck(self),
            # Custom checks
            CustomRequestCheck(self),
        ]

        self.security_pipeline = SecurityCheckPipeline(checks)
        self.logger.info(
            f"Security pipeline initialized with {len(checks)} checks: "
            f"{self.security_pipeline.get_check_names()}"
        )

    def _configure_security_headers(self, config: SecurityConfig) -> None:
        """Configure security headers manager if enabled."""
        if not config.security_headers:
            security_headers_manager.enabled = False
            return

        if not config.security_headers.get("enabled", True):
            security_headers_manager.enabled = False
            return

        security_headers_manager.enabled = True
        headers_config = config.security_headers
        hsts_config = headers_config.get("hsts", {})

        security_headers_manager.configure(
            enabled=headers_config.get("enabled", True),
            csp=headers_config.get("csp"),
            hsts_max_age=hsts_config.get("max_age"),
            hsts_include_subdomains=hsts_config.get("include_subdomains", True),
            hsts_preload=hsts_config.get("preload", False),
            frame_options=headers_config.get("frame_options", "SAMEORIGIN"),
            content_type_options=headers_config.get("content_type_options", "nosniff"),
            xss_protection=headers_config.get("xss_protection", "1; mode=block"),
            referrer_policy=headers_config.get(
                "referrer_policy", "strict-origin-when-cross-origin"
            ),
            permissions_policy=headers_config.get("permissions_policy", "UNSET"),
            custom_headers=headers_config.get("custom"),
            cors_origins=config.cors_allow_origins if config.enable_cors else None,
            cors_allow_credentials=config.cors_allow_credentials,
            cors_allow_methods=config.cors_allow_methods,
            cors_allow_headers=config.cors_allow_headers,
        )

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        """Set the SecurityDecorator instance for decorator support."""
        self.guard_decorator = decorator_handler

    async def _send_middleware_event(
        self,
        event_type: str,
        request: Request,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """
        Send middleware-specific events to agent if enabled.

        This method should only be used for middleware-specific events like
        decorator violations. Domain-specific events (IP bans, rate limits, etc.)
        should be sent by their respective handlers.
        """
        if not self.agent_handler or not self.config.agent_enable_events:
            return

        try:
            client_ip = await extract_client_ip(
                request, self.config, self.agent_handler
            )

            # Get country information if available
            country = None
            if self.geo_ip_handler:
                try:
                    country = self.geo_ip_handler.get_country(client_ip)
                except Exception:
                    # Don't let geo IP lookup failures break event sending
                    pass

            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=client_ip,
                country=country,
                user_agent=request.headers.get("User-Agent"),
                action_taken=action_taken,
                reason=reason,
                endpoint=str(request.url.path),
                method=request.method,
                metadata=kwargs,
            )

            await self.agent_handler.send_event(event)
        except Exception as e:
            # Don't let agent errors break the middleware
            self.logger.error(f"Failed to send security event to agent: {e}")

    async def _send_security_metric(
        self, metric_type: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        """Send performance metric to agent."""
        if self.agent_handler and self.config.agent_enable_metrics:
            try:
                from guard_agent import SecurityMetric

                metric = SecurityMetric(
                    timestamp=datetime.now(timezone.utc),
                    metric_type=metric_type,
                    value=value,
                    tags=tags or {},
                )
                await self.agent_handler.send_metric(metric)
            except Exception as e:
                # Don't let agent errors break middleware functionality
                logging.getLogger(__name__).error(
                    f"Failed to send metric to agent: {e}"
                )

    async def _collect_request_metrics(
        self, request: Request, response_time: float, status_code: int
    ) -> None:
        """Collect request metrics for agent."""
        if not self.agent_handler or not self.config.agent_enable_metrics:
            return

        endpoint = str(request.url.path)
        method = request.method

        # Response time metric
        await self._send_security_metric(
            "response_time",
            response_time,
            {"endpoint": endpoint, "method": method, "status": str(status_code)},
        )

        # Request count metric
        await self._send_security_metric(
            "request_count", 1.0, {"endpoint": endpoint, "method": method}
        )

        # Error rate metric (for non-2xx responses)
        if status_code >= 400:
            await self._send_security_metric(
                "error_rate",
                1.0,
                {"endpoint": endpoint, "method": method, "status": str(status_code)},
            )

    def _is_request_https(self, request: Request) -> bool:
        """
        Check if request is HTTPS, considering X-Forwarded-Proto from trusted proxies.

        Returns:
            True if request is HTTPS or forwarded as HTTPS from trusted proxy
        """
        # Direct HTTPS check
        is_https = request.url.scheme == "https"

        # Check X-Forwarded-Proto from trusted proxies
        if (
            self.config.trust_x_forwarded_proto
            and self.config.trusted_proxies
            and request.client
        ):
            if self._is_trusted_proxy(request.client.host):
                forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
                is_https = is_https or forwarded_proto.lower() == "https"

        return is_https

    def _is_trusted_proxy(self, connecting_ip: str) -> bool:
        """Check if connecting IP is a trusted proxy."""
        for proxy in self.config.trusted_proxies:
            if "/" not in proxy:
                # Single IP comparison
                if connecting_ip == proxy:
                    return True
            else:
                # CIDR range comparison
                if ip_address(connecting_ip) in ip_network(proxy, strict=False):
                    return True
        return False

    async def _send_https_violation_event(
        self, request: Request, route_config: RouteConfig | None
    ) -> None:
        """Send appropriate HTTPS violation event based on route config."""
        https_url = str(request.url.replace(scheme="https"))

        if route_config and route_config.require_https:
            # Route-specific HTTPS requirement
            await self._send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="https_redirect",
                reason="Route requires HTTPS but request was HTTP",
                decorator_type="authentication",
                violation_type="require_https",
                original_scheme=request.url.scheme,
                redirect_url=https_url,
            )
        else:
            # Global HTTPS enforcement
            await self._send_middleware_event(
                event_type="https_enforced",
                request=request,
                action_taken="https_redirect",
                reason="HTTP request redirected to HTTPS for security",
                original_scheme=request.url.scheme,
                redirect_url=https_url,
            )

    async def _create_https_redirect(self, request: Request) -> Response:
        """Create HTTPS redirect response with custom modifier if configured."""
        https_url = request.url.replace(scheme="https")
        redirect_response = RedirectResponse(
            https_url, status_code=status.HTTP_301_MOVED_PERMANENTLY
        )

        if self.config.custom_response_modifier:
            return await self.config.custom_response_modifier(redirect_response)

        return redirect_response

    async def _check_https_enforcement(
        self, request: Request, route_config: RouteConfig | None
    ) -> Response | None:
        """Check and enforce HTTPS requirements."""
        # Check if HTTPS is required
        https_required = (
            route_config.require_https if route_config else self.config.enforce_https
        )
        if not https_required:
            return None

        # Check if request is HTTPS
        if self._is_request_https(request):
            return None

        # HTTPS required but not present - send event and redirect
        await self._send_https_violation_event(request, route_config)

        if not self.config.passive_mode:
            return await self._create_https_redirect(request)

        return None

    async def _check_emergency_mode(
        self, request: Request, client_ip: str
    ) -> Response | None:
        """Check emergency mode restrictions."""
        if not self.config.emergency_mode:
            return None

        # Allow only emergency whitelist IPs
        if client_ip not in self.config.emergency_whitelist:
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"[EMERGENCY MODE] Access denied for IP {client_ip}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )

            # Send emergency mode blocking event
            await self._send_middleware_event(
                event_type="emergency_mode_block",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason=f"[EMERGENCY MODE] IP {client_ip} not in whitelist",
                emergency_whitelist_count=len(self.config.emergency_whitelist),
                emergency_active=True,
            )

            if not self.config.passive_mode:
                return await self.create_error_response(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    default_message="Service temporarily unavailable",
                )
        else:
            message = "[EMERGENCY MODE] Allowed access for whitelisted IP"
            # Log allowed emergency access
            await log_activity(
                request,
                self.logger,
                log_type="info",
                reason=f"{message}: {client_ip}",
                level="INFO",
            )
        return None

    async def _check_request_size_limit(
        self, request: Request, route_config: RouteConfig
    ) -> Response | None:
        """Check if request size exceeds configured limit."""
        if not route_config.max_request_size:
            return None

        content_length = request.headers.get("content-length")
        if not content_length or int(content_length) <= route_config.max_request_size:
            return None

        # Request size exceeds limit
        message = f"Request size {content_length} exceeds limit"

        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"{message}: {route_config.max_request_size}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        await self._send_middleware_event(
            event_type="content_filtered",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"{message}: {route_config.max_request_size}",
            decorator_type="content_filtering",
            violation_type="max_request_size",
        )

        if not self.config.passive_mode:
            return await self.create_error_response(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                default_message="Request too large",
            )

        return None

    async def _check_content_type_allowed(
        self, request: Request, route_config: RouteConfig
    ) -> Response | None:
        """Check if content type is in allowed list."""
        if not route_config.allowed_content_types:
            return None

        content_type = request.headers.get("content-type", "").split(";")[0]
        if content_type in route_config.allowed_content_types:
            return None

        # Content type not allowed
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Invalid content type: {content_type}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        message = f"Content type {content_type} not in allowed types"

        await self._send_middleware_event(
            event_type="content_filtered",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"{message}: {route_config.allowed_content_types}",
            decorator_type="content_filtering",
            violation_type="content_type",
        )

        if not self.config.passive_mode:
            return await self.create_error_response(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                default_message="Unsupported content type",
            )

        return None

    async def _check_request_size_and_content(
        self, request: Request, route_config: RouteConfig | None
    ) -> Response | None:
        """Check request size and content type restrictions."""
        if not route_config:
            return None

        # Check request size limit
        size_response = await self._check_request_size_limit(request, route_config)
        if size_response:
            return size_response

        # Check content type allowed
        return await self._check_content_type_allowed(request, route_config)

    async def _check_required_headers(
        self, request: Request, route_config: RouteConfig | None
    ) -> Response | None:
        """Check for required headers."""
        if not route_config or not route_config.required_headers:
            return None

        for header, expected in route_config.required_headers.items():
            if expected == "required" and not request.headers.get(header):
                # Log suspicious activity for missing required header
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason=f"Missing required header: {header}",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )

                # Determine decorator type based on header name
                decorator_type = (
                    "authentication"
                    if header.lower() in ["x-api-key", "authorization"]
                    else "advanced"
                )
                violation_type = (
                    "api_key_required"
                    if header.lower() == "x-api-key"
                    else "required_header"
                )

                # Send decorator violation event to agent
                await self._send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"Missing required header: {header}",
                    decorator_type=decorator_type,
                    violation_type=violation_type,
                    missing_header=header,
                )
                if not self.config.passive_mode:
                    return await self.create_error_response(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        default_message=f"Missing required header: {header}",
                    )
        return None

    def _validate_auth_header(
        self, auth_header: str, auth_type: str
    ) -> tuple[bool, str]:
        """
        Validate authentication header against required type.

        Returns:
            Tuple of (is_valid, failure_reason)
        """
        if auth_type == "bearer":
            if not auth_header.startswith("Bearer "):
                return False, "Missing or invalid Bearer token"
        elif auth_type == "basic":
            if not auth_header.startswith("Basic "):
                return False, "Missing or invalid Basic authentication"
        else:
            # Generic auth requirement
            if not auth_header:
                return False, f"Missing {auth_type} authentication"

        return True, ""

    async def _handle_auth_failure(
        self, request: Request, auth_reason: str, route_config: RouteConfig
    ) -> Response | None:
        """Handle authentication failure with logging and events."""
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Authentication failure: {auth_reason}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        await self._send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=auth_reason,
            decorator_type="authentication",
            violation_type="require_auth",
            auth_type=route_config.auth_required,
        )

        if not self.config.passive_mode:
            return await self.create_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                default_message="Authentication required",
            )

        return None

    async def _check_authentication(
        self, request: Request, route_config: RouteConfig | None
    ) -> Response | None:
        """Check authentication requirements."""
        if not route_config or not route_config.auth_required:
            return None

        auth_header = request.headers.get("authorization", "")

        # Validate authentication header
        is_valid, auth_reason = self._validate_auth_header(
            auth_header, route_config.auth_required
        )

        # Handle authentication failure
        if not is_valid:
            return await self._handle_auth_failure(request, auth_reason, route_config)

        return None

    async def _is_path_excluded(self, request: Request) -> bool:
        """Check if the request path is excluded from security checks."""
        if any(request.url.path.startswith(path) for path in self.config.exclude_paths):
            # Send path exclusion event for monitoring
            await self._send_middleware_event(
                event_type="path_excluded",
                request=request,
                action_taken="security_checks_bypassed",
                reason=f"Path {request.url.path} excluded from security checks",
                excluded_path=request.url.path,
                configured_exclusions=self.config.exclude_paths,
            )
            return True
        return False

    async def _check_custom_request(self, request: Request) -> Response | None:
        """Check custom request validation."""
        if not self.config.custom_request_check:
            return None

        custom_response = await self.config.custom_request_check(request)
        if custom_response:
            # Send custom request check event
            await self._send_middleware_event(
                event_type="custom_request_check",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason="Custom request check returned blocking response",
                response_status=custom_response.status_code
                if hasattr(custom_response, "status_code")
                else "unknown",
                check_function=self.config.custom_request_check.__name__
                if hasattr(self.config.custom_request_check, "__name__")
                else "anonymous",
            )

            if not self.config.passive_mode:
                if self.config.custom_response_modifier:
                    modified_response = await self.config.custom_response_modifier(
                        custom_response
                    )
                    return modified_response
                return custom_response
        return None

    async def _detect_penetration_patterns(
        self, request: Request, route_config: RouteConfig | None
    ) -> tuple[bool, str]:
        """
        Determine if penetration detection should run and execute if enabled.

        Returns:
            Tuple of (detection_result, trigger_info)
        """
        penetration_enabled = self.config.enable_penetration_detection
        route_specific_detection = None

        if route_config and hasattr(route_config, "enable_suspicious_detection"):
            route_specific_detection = route_config.enable_suspicious_detection
            penetration_enabled = route_specific_detection

        # Run detection if enabled and not bypassed
        if penetration_enabled and not self._should_bypass_check(
            "penetration", route_config
        ):
            return await detect_penetration_attempt(request)

        # Detection disabled by decorator - send event
        if (
            route_specific_detection is False
            and self.config.enable_penetration_detection
        ):
            await self._send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="detection_disabled",
                reason="Suspicious pattern detection disabled by route decorator",
                decorator_type="advanced",
                violation_type="suspicious_detection_disabled",
            )
            return False, "disabled_by_decorator"

        # Detection not enabled
        return False, "not_enabled"

    async def _handle_suspicious_passive_mode(
        self, request: Request, client_ip: str, trigger_info: str
    ) -> None:
        """Handle suspicious activity detection in passive mode (logging only)."""
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Suspicious activity detected: {client_ip}",
            passive_mode=True,
            trigger_info=trigger_info,
            level=self.config.log_suspicious_level,
        )

        message = "Suspicious pattern detected (passive mode)"

        await self._send_middleware_event(
            event_type="penetration_attempt",
            request=request,
            action_taken="logged_only",
            reason=f"{message}: {trigger_info}",
            request_count=self.suspicious_request_counts[client_ip],
            passive_mode=True,
            trigger_info=trigger_info,
        )

    async def _handle_suspicious_active_mode(
        self, request: Request, client_ip: str, trigger_info: str
    ) -> Response:
        """Handle suspicious activity detection in active mode (blocking)."""
        sus_specs = f"{client_ip} - {trigger_info}"

        # Check if IP should be banned
        if (
            self.config.enable_ip_banning
            and self.suspicious_request_counts[client_ip]
            >= self.config.auto_ban_threshold
        ):
            await ip_ban_manager.ban_ip(
                client_ip,
                self.config.auto_ban_duration,
                "penetration_attempt",
            )
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"IP banned due to suspicious activity: {sus_specs}",
                level=self.config.log_suspicious_level,
            )

            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="IP has been banned",
            )

        # Block request without banning
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Suspicious activity detected for IP: {sus_specs}",
            level=self.config.log_suspicious_level,
        )

        await self._send_middleware_event(
            event_type="penetration_attempt",
            request=request,
            action_taken="request_blocked",
            reason=f"Penetration attempt detected: {trigger_info}",
            request_count=self.suspicious_request_counts[client_ip],
            trigger_info=trigger_info,
        )

        return await self.create_error_response(
            status_code=status.HTTP_400_BAD_REQUEST,
            default_message="Suspicious activity detected",
        )

    async def _check_suspicious_activity(
        self, request: Request, client_ip: str, route_config: RouteConfig | None
    ) -> Response | None:
        """Check for suspicious/penetration attempt patterns."""
        # Detect penetration patterns
        detection_result, trigger_info = await self._detect_penetration_patterns(
            request, route_config
        )

        if not detection_result:
            return None

        # Update request count for this IP
        self.suspicious_request_counts[client_ip] = (
            self.suspicious_request_counts.get(client_ip, 0) + 1
        )

        # Handle based on mode
        if self.config.passive_mode:
            await self._handle_suspicious_passive_mode(request, client_ip, trigger_info)
            return None

        return await self._handle_suspicious_active_mode(
            request, client_ip, trigger_info
        )

    async def _check_custom_validators(
        self, request: Request, route_config: RouteConfig | None
    ) -> Response | None:
        """Check custom validators."""
        if not route_config or not route_config.custom_validators:
            return None

        for validator in route_config.custom_validators:
            validation_response = await validator(request)
            if validation_response:
                # Log suspicious activity for custom validation failure
                await log_activity(
                    request,
                    self.logger,
                    log_type="suspicious",
                    reason="Custom validation failed",
                    level=self.config.log_suspicious_level,
                    passive_mode=self.config.passive_mode,
                )

                # Send decorator violation event for custom validation failure
                await self._send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason="Custom validation failed",
                    decorator_type="content_filtering",
                    violation_type="custom_validation",
                    validator_name=getattr(validator, "__name__", "anonymous"),
                )
                if not self.config.passive_mode and isinstance(
                    validation_response, Response
                ):
                    return validation_response
        return None

    async def _check_time_window_restrictions(
        self, request: Request, route_config: RouteConfig | None
    ) -> Response | None:
        """Check time window restrictions."""
        if not route_config or not route_config.time_restrictions:
            return None

        time_allowed = await self._check_time_window(route_config.time_restrictions)
        if not time_allowed:
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason="Access outside allowed time window",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )
            # Send decorator violation event to agent
            await self._send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason="Access outside allowed time window",
                decorator_type="advanced",
                violation_type="time_restriction",
            )
            if not self.config.passive_mode:
                return await self.create_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    default_message="Access not allowed at this time",
                )
        return None

    async def _check_banned_ip(
        self, request: Request, client_ip: str, route_config: RouteConfig | None
    ) -> Response | None:
        """Check if IP is banned and handle accordingly."""
        if self._should_bypass_check("ip_ban", route_config):
            return None

        if not await ip_ban_manager.is_ip_banned(client_ip):
            return None

        # Log banned IP access attempt
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Banned IP attempted access: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        if not self.config.passive_mode:
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="IP address banned",
            )

        return None

    async def _check_route_ip_restrictions(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> Response | None:
        """Check route-specific IP restrictions."""
        route_allowed = await self._check_route_ip_access(client_ip, route_config)

        # None means no route-specific rules, fall back to global
        if route_allowed is None or route_allowed:
            return None

        # IP not allowed by route config
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP not allowed by route config: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        # Send decorator violation event to agent
        await self._send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"IP {client_ip} blocked",
            decorator_type="access_control",
            violation_type="ip_restriction",
        )

        if not self.config.passive_mode:
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Forbidden",
            )

        return None

    async def _check_global_ip_restrictions(
        self, request: Request, client_ip: str
    ) -> Response | None:
        """Check global IP allowlist/blocklist."""
        if await is_ip_allowed(client_ip, self.config, self.geo_ip_handler):
            return None

        # Log blocked IP
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"IP not allowed: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        # Send global IP filtering event to agent
        await self._send_middleware_event(
            event_type="ip_blocked",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"IP {client_ip} not in global allowlist/blocklist",
            ip_address=client_ip,
            filter_type="global",
        )

        if not self.config.passive_mode:
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Forbidden",
            )

        return None

    async def _check_ip_security(
        self, request: Request, client_ip: str, route_config: RouteConfig | None
    ) -> Response | None:
        """Check IP-based security (banning, allowlist/blocklist)."""
        # Check IP banning first
        ban_response = await self._check_banned_ip(request, client_ip, route_config)
        if ban_response:
            return ban_response

        # Check IP allowlist/blocklist (with route overrides)
        if self._should_bypass_check("ip", route_config):
            return None

        # Route-specific IP restrictions
        if route_config:
            return await self._check_route_ip_restrictions(
                request, client_ip, route_config
            )

        # Global IP restrictions
        return await self._check_global_ip_restrictions(request, client_ip)

    async def _check_user_agent(
        self, request: Request, route_config: RouteConfig | None
    ) -> Response | None:
        """Check user agent restrictions."""
        user_agent = request.headers.get("User-Agent", "")
        if not await self._check_user_agent_allowed(user_agent, route_config):
            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"Blocked user agent: {user_agent}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )
            # Send decorator violation event only for route-specific blocks
            if route_config and route_config.blocked_user_agents:
                # Route-specific user agent block
                await self._send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"User agent '{user_agent}' blocked",
                    decorator_type="access_control",
                    violation_type="user_agent",
                    blocked_user_agent=user_agent,
                )
            else:
                # Global user agent block
                await self._send_middleware_event(
                    event_type="user_agent_blocked",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"User agent '{user_agent}' in global blocklist",
                    user_agent=user_agent,
                    filter_type="global",
                )

            if not self.config.passive_mode:
                return await self.create_error_response(
                    status_code=status.HTTP_403_FORBIDDEN,
                    default_message="User-Agent not allowed",
                )
        return None

    async def _handle_passthrough_cases(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response | None:
        """
        Handle special cases that require immediate passthrough.

        This includes requests with no client information and excluded paths.
        """
        # No client information
        if not request.client:
            response = await call_next(request)
            if self.config.custom_response_modifier:
                return await self.config.custom_response_modifier(response)
            return response

        # Excluded paths
        if await self._is_path_excluded(request):
            response = await call_next(request)
            if self.config.custom_response_modifier:
                return await self.config.custom_response_modifier(response)
            return response

        return None

    async def _handle_security_bypass(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
        route_config: RouteConfig | None,
    ) -> Response | None:
        """Handle bypassed security checks."""
        if not route_config or not self._should_bypass_check("all", route_config):
            return None

        # Send security bypass event for monitoring
        await self._send_middleware_event(
            event_type="security_bypass",
            request=request,
            action_taken="all_checks_bypassed",
            reason="Route configured to bypass all security checks",
            bypassed_checks=list(route_config.bypassed_checks),
            endpoint=str(request.url.path),
        )

        if not self.config.passive_mode:
            response = await call_next(request)
            if self.config.custom_response_modifier:
                return await self.config.custom_response_modifier(response)
            return response

        return None

    async def _handle_no_client(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response | None:
        """Handle requests with no client information."""
        if not request.client:
            response = await call_next(request)
            if self.config.custom_response_modifier:
                modified_response = await self.config.custom_response_modifier(response)
                return modified_response
            return response
        return None

    async def _handle_bypass_and_excluded(
        self,
        request: Request,
        route_config: RouteConfig | None,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response | None:
        """Handle bypassed security checks and return response if applicable."""
        if route_config and self._should_bypass_check("all", route_config):
            # Send security bypass event for monitoring
            await self._send_middleware_event(
                event_type="security_bypass",
                request=request,
                action_taken="all_checks_bypassed",
                reason="Route configured to bypass all security checks",
                bypassed_checks=list(route_config.bypassed_checks),
                endpoint=str(request.url.path),
            )

            # In passive mode, log but don't actually bypass
            if not self.config.passive_mode:
                response = await call_next(request)
                if self.config.custom_response_modifier:
                    modified_response = await self.config.custom_response_modifier(
                        response
                    )
                    return modified_response
                return response
        return None

    async def _process_response(
        self,
        request: Request,
        response: Response,
        response_time: float,
        route_config: RouteConfig | None,
    ) -> Response:
        """Process the response with behavioral rules, metrics, and headers."""
        # Process behavioral rules after response
        if route_config and route_config.behavior_rules:
            client_ip = await extract_client_ip(
                request, self.config, self.agent_handler
            )
            await self._process_decorator_return_rules(
                request, response, client_ip, route_config
            )

        await self._collect_request_metrics(
            request, response_time, response.status_code
        )

        # Add security headers if enabled
        if self.config.security_headers and self.config.security_headers.get(
            "enabled", True
        ):
            security_headers = await security_headers_manager.get_headers(
                str(request.url.path)
            )
            for header_name, header_value in security_headers.items():
                response.headers[header_name] = header_value

            # Add CORS headers if origin is present
            origin = request.headers.get("origin")
            if origin:
                cors_headers = await security_headers_manager.get_cors_headers(origin)
                for header_name, header_value in cors_headers.items():
                    response.headers[header_name] = header_value

        if self.config.custom_response_modifier:
            modified_response = await self.config.custom_response_modifier(response)
            return modified_response

        return response

    def _get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        """Get list of cloud providers to check (route-specific or global)."""
        if route_config and route_config.block_cloud_providers:
            return list(route_config.block_cloud_providers)
        if self.config.block_cloud_providers:
            return list(self.config.block_cloud_providers)
        return None

    async def _send_cloud_detection_events(
        self,
        request: Request,
        client_ip: str,
        cloud_providers_to_check: list[str],
        route_config: RouteConfig | None,
    ) -> None:
        """Send cloud provider detection events to handler and middleware."""
        # Send event to cloud handler if details available
        cloud_details = cloud_handler.get_cloud_provider_details(
            client_ip, set(cloud_providers_to_check)
        )
        if cloud_details and cloud_handler.agent_handler:
            provider, network = cloud_details
            await cloud_handler.send_cloud_detection_event(
                client_ip,
                provider,
                network,
                "request_blocked" if not self.config.passive_mode else "logged_only",
            )

        # Send decorator violation event for route-specific blocks
        if route_config and route_config.block_cloud_providers:
            await self._send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason=f"Cloud provider IP {client_ip} blocked",
                decorator_type="access_control",
                violation_type="cloud_provider",
                blocked_providers=list(cloud_providers_to_check),
            )

    async def _check_cloud_providers(
        self, request: Request, client_ip: str, route_config: RouteConfig | None
    ) -> Response | None:
        """Check cloud provider blocking."""
        if self._should_bypass_check("clouds", route_config):
            return None

        # Get cloud providers to check
        cloud_providers_to_check = self._get_cloud_providers_to_check(route_config)
        if not cloud_providers_to_check:
            return None

        # Check if IP is from blocked cloud provider
        if not cloud_handler.is_cloud_ip(client_ip, set(cloud_providers_to_check)):
            return None

        # Log suspicious activity
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Blocked cloud provider IP: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        # Send cloud detection events
        await self._send_cloud_detection_events(
            request, client_ip, cloud_providers_to_check, route_config
        )

        # Return error response if not in passive mode
        if not self.config.passive_mode:
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Cloud provider IP not allowed",
            )

        return None

    async def _handle_missing_referrer(
        self, request: Request, route_config: RouteConfig
    ) -> Response | None:
        """Handle missing referrer header violation."""
        # Log suspicious activity for missing referrer
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason="Missing referrer header",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        # Send decorator violation event for missing referrer
        await self._send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason="Missing referrer header",
            decorator_type="content_filtering",
            violation_type="require_referrer",
            allowed_domains=route_config.require_referrer,
        )

        if not self.config.passive_mode:
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Referrer required",
            )

        return None

    def _is_referrer_domain_allowed(
        self, referrer: str, allowed_domains: list[str]
    ) -> bool:
        """
        Check if referrer domain matches allowed domains.

        Returns:
            True if referrer domain is in allowed list
        """
        try:
            from urllib.parse import urlparse

            referrer_domain = urlparse(referrer).netloc.lower()
            for allowed_domain in allowed_domains:
                if (
                    referrer_domain == allowed_domain.lower()
                    or referrer_domain.endswith(f".{allowed_domain.lower()}")
                ):
                    return True
            return False
        except Exception:
            return False

    async def _handle_invalid_referrer(
        self, request: Request, referrer: str, route_config: RouteConfig
    ) -> Response | None:
        """Handle invalid referrer domain violation."""
        # Log suspicious activity for invalid referrer
        await log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Invalid referrer: {referrer}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        # Send decorator violation event for invalid referrer
        await self._send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason=f"Referrer '{referrer}' not in allowed domains",
            decorator_type="content_filtering",
            violation_type="require_referrer",
            referrer=referrer,
            allowed_domains=route_config.require_referrer,
        )

        if not self.config.passive_mode:
            return await self.create_error_response(
                status_code=status.HTTP_403_FORBIDDEN,
                default_message="Invalid referrer",
            )

        return None

    async def _check_referrer(
        self, request: Request, route_config: RouteConfig | None
    ) -> Response | None:
        """Check referrer requirements."""
        if not route_config or not route_config.require_referrer:
            return None

        referrer = request.headers.get("referer", "")

        # Handle missing referrer
        if not referrer:
            return await self._handle_missing_referrer(request, route_config)

        # Check if referrer domain is allowed
        if not self._is_referrer_domain_allowed(
            referrer, route_config.require_referrer
        ):
            return await self._handle_invalid_referrer(request, referrer, route_config)

        return None

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Dispatch method to handle incoming requests and apply security measures.

        This method uses a security check pipeline to process requests through
        multiple security validations in sequence. Special cases (no client,
        excluded paths, bypassed checks) are handled separately to allow
        request passthrough when appropriate.

        Args:
            request: The incoming request object.
            call_next: The next middleware or route handler in the chain.

        Returns:
            Response: The response object, either from the next handler
            or a security-related blocking response.
        """
        # Handle special cases that require immediate passthrough
        passthrough_response = await self._handle_passthrough_cases(request, call_next)
        if passthrough_response:
            return passthrough_response

        # Get route config to check for emergency mode and bypass before pipeline
        client_ip = await extract_client_ip(request, self.config, self.agent_handler)
        route_config = self._get_route_decorator_config(request)

        # Emergency mode check (highest priority security control)
        emergency_response = await self._check_emergency_mode(request, client_ip)
        if emergency_response:
            return emergency_response

        # Handle bypassed security checks
        bypass_response = await self._handle_security_bypass(
            request, call_next, route_config
        )
        if bypass_response:
            return bypass_response

        # Execute security check pipeline
        # Build pipeline if not already initialized (for backwards compatibility)
        if not self.security_pipeline:
            self._build_security_pipeline()

        # Type narrowing: pipeline is now guaranteed to exist
        assert self.security_pipeline is not None
        blocking_response = await self.security_pipeline.execute(request)
        if blocking_response:
            return blocking_response

        # Note: client_ip and route_config are already set from lines 1277-1278
        # They may also be set by pipeline checks, but we use the original values here

        # Process behavioral rules before calling next
        if route_config and route_config.behavior_rules and client_ip:
            await self._process_decorator_usage_rules(request, client_ip, route_config)

        # Call next middleware/handler
        start_time = time.time()
        response = await call_next(request)
        response_time = time.time() - start_time

        # Process response with rules, metrics, and headers
        return await self._process_response(
            request, response, response_time, route_config
        )

    def _get_guard_decorator(self, app: Any) -> BaseSecurityDecorator | None:
        """
        Get the guard decorator instance from app state or middleware.

        Returns:
            BaseSecurityDecorator instance or None if not available
        """
        # Try to get decorator from app state first
        if app and hasattr(app, "state") and hasattr(app.state, "guard_decorator"):
            app_guard_decorator = app.state.guard_decorator
            if isinstance(app_guard_decorator, BaseSecurityDecorator):
                return app_guard_decorator

        # Fall back to middleware-level decorator
        return self.guard_decorator if self.guard_decorator else None

    def _is_matching_route(
        self, route: Any, path: str, method: str
    ) -> tuple[bool, str | None]:
        """
        Check if a route matches the request path and method, and has a guard route ID.

        Returns:
            Tuple of (is_match, route_id): is_match is True if route matches,
            route_id is the guard route ID if found, None otherwise
        """
        # Check if route has required attributes
        if not hasattr(route, "path") or not hasattr(route, "methods"):
            return False, None

        # Check path and method match
        if route.path != path or method not in route.methods:
            return False, None

        # Check for guard route ID
        if not hasattr(route, "endpoint") or not hasattr(
            route.endpoint, "_guard_route_id"
        ):
            return False, None

        return True, route.endpoint._guard_route_id

    def _get_route_decorator_config(self, request: Request) -> RouteConfig | None:
        """Get route-specific security configuration from decorators."""
        app = request.scope.get("app")

        # Get decorator instance
        guard_decorator = self._get_guard_decorator(app)
        if not guard_decorator:
            return None

        # Try to find matching route
        if not app:
            return None

        path = request.url.path
        method = request.method

        for route in app.routes:
            is_match, route_id = self._is_matching_route(route, path, method)
            if is_match and route_id:
                return guard_decorator.get_route_config(route_id)

        return None

    def _should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        """Check if a security check should be bypassed."""
        if not route_config:
            return False
        return (
            check_name in route_config.bypassed_checks
            or "all" in route_config.bypassed_checks
        )

    def _is_ip_in_blacklist(
        self, client_ip: str, ip_addr: object, blacklist: list[str]
    ) -> bool:
        """Check if IP is in blacklist (supports CIDR and single IPs)."""
        for blocked in blacklist:
            if "/" in blocked:
                if ip_addr in ip_network(blocked, strict=False):
                    return True
            elif client_ip == blocked:
                return True
        return False

    def _is_ip_in_whitelist(
        self, client_ip: str, ip_addr: object, whitelist: list[str]
    ) -> bool | None:
        """
        Check if IP is in whitelist (supports CIDR and single IPs).

        Returns:
            True if IP is whitelisted
            False if whitelist exists but IP not in it
            None if no whitelist configured
        """
        if not whitelist:
            return None

        for allowed in whitelist:
            if "/" in allowed:
                if ip_addr in ip_network(allowed, strict=False):
                    return True
            elif client_ip == allowed:
                return True
        return False  # Whitelist exists but IP not in it

    def _check_country_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        """
        Check country-based access control.

        Returns:
            False if blocked by country rules
            True if allowed by country whitelist
            None if no country rules apply
        """
        if not self.geo_ip_handler:
            return None

        country = None

        # Check blocked countries
        if route_config.blocked_countries:
            country = self.geo_ip_handler.get_country(client_ip)
            if country and country in route_config.blocked_countries:
                return False

        # Check whitelisted countries
        if route_config.whitelist_countries:
            if country is None:  # Get country if not already fetched
                country = self.geo_ip_handler.get_country(client_ip)

            if country:
                return country in route_config.whitelist_countries
            return False  # Whitelist exists but no country found

        return None

    async def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        """
        Check route-specific IP access rules. Returns None if no route rules apply.
        """
        try:
            ip_addr = ip_address(client_ip)

            # Check IP blacklist
            if route_config.ip_blacklist:
                if self._is_ip_in_blacklist(
                    client_ip, ip_addr, route_config.ip_blacklist
                ):
                    return False

            # Check IP whitelist
            whitelist_result = self._is_ip_in_whitelist(
                client_ip, ip_addr, route_config.ip_whitelist or []
            )
            if whitelist_result is not None:
                return whitelist_result

            # Check country-based access
            country_result = self._check_country_access(client_ip, route_config)
            if country_result is not None:
                return country_result

            return None  # No route-specific rules, fall back to global
        except ValueError:
            return False

    async def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        """Check user agent against both route and global rules."""
        # Check route-specific blocked user agents first
        if route_config and route_config.blocked_user_agents:
            for pattern in route_config.blocked_user_agents:
                if re.search(pattern, user_agent, re.IGNORECASE):
                    return False

        # Fall back to global check
        return await is_user_agent_allowed(user_agent, self.config)

    async def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        """Check if current time is within allowed time window."""
        try:
            start_time = time_restrictions["start"]
            end_time = time_restrictions["end"]

            # TODO: For simplicity, we'll use UTC for now
            # Production would need proper timezone handling
            # timezone_str = time_restrictions.get("timezone", "UTC")
            current_time = datetime.now(timezone.utc)
            current_hour_minute = current_time.strftime("%H:%M")

            # Handle overnight time windows (e.g., 22:00 to 06:00)
            if start_time > end_time:
                return (
                    current_hour_minute >= start_time or current_hour_minute <= end_time
                )
            else:
                return start_time <= current_hour_minute <= end_time

        except Exception as e:
            self.logger.error(f"Error checking time window: {str(e)}")
            return True  # Allow access if time check fails

    async def _apply_rate_limit_check(
        self,
        request: Request,
        client_ip: str,
        rate_limit: int,
        window: int,
        event_type: str,
        event_kwargs: dict[str, Any],
    ) -> Response | None:
        """
        Apply rate limit check with given configuration and send events if exceeded.

        Args:
            request: The request object
            client_ip: Client IP address
            rate_limit: Number of requests allowed
            window: Time window in seconds
            event_type: Type of event to send
            event_kwargs: Additional event metadata

        Returns:
            Response if rate limit exceeded, None otherwise
        """
        # Create temporary rate limit config and handler
        rate_config = SecurityConfig(
            rate_limit=rate_limit,
            rate_limit_window=window,
            enable_redis=self.config.enable_redis,
            redis_url=self.config.redis_url,
            redis_prefix=self.config.redis_prefix,
        )
        rate_handler = RateLimitManager(rate_config)
        if self.redis_handler:
            await rate_handler.initialize_redis(self.redis_handler)

        # Check rate limit
        response = await rate_handler.check_rate_limit(
            request, client_ip, self.create_error_response
        )

        # Send event if rate limit exceeded
        if response is not None:
            await self._send_middleware_event(
                event_type=event_type,
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                **event_kwargs,
            )

            if self.config.passive_mode:
                return None  # Don't block in passive mode

        return response

    async def _check_rate_limit(
        self, request: Request, client_ip: str, route_config: RouteConfig | None
    ) -> Response | None:
        """
        Check rate limiting with route overrides and dynamic endpoint-specific config.
        """
        endpoint_path = request.url.path

        # Priority 1: Endpoint-specific rate limit (dynamic rules)
        if endpoint_path in self.config.endpoint_rate_limits:
            rate_limit, window = self.config.endpoint_rate_limits[endpoint_path]
            return await self._apply_rate_limit_check(
                request,
                client_ip,
                rate_limit,
                window,
                "dynamic_rule_violation",
                {
                    "reason": (
                        f"Endpoint-specific rate limit exceeded: {rate_limit} "
                        f"requests per {window}s for {endpoint_path}"
                    ),
                    "rule_type": "endpoint_rate_limit",
                    "endpoint": endpoint_path,
                    "rate_limit": rate_limit,
                    "window": window,
                },
            )

        # Priority 2: Route-specific rate limit (decorator config)
        if route_config and route_config.rate_limit is not None:
            window = route_config.rate_limit_window or 60
            return await self._apply_rate_limit_check(
                request,
                client_ip,
                route_config.rate_limit,
                window,
                "decorator_violation",
                {
                    "reason": (
                        f"Route-specific rate limit exceeded: "
                        f"{route_config.rate_limit} requests per {window}s"
                    ),
                    "decorator_type": "rate_limiting",
                    "violation_type": "rate_limit",
                    "rate_limit": route_config.rate_limit,
                    "window": window,
                },
            )

        # Priority 3: Global rate limiting
        response = await self.rate_limit_handler.check_rate_limit(
            request, client_ip, self.create_error_response
        )

        if response is not None and self.config.passive_mode:
            return None  # Don't block in passive mode

        return response

    async def _process_decorator_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> None:
        """Process behavioral usage rules from decorators before request processing."""
        if not self.guard_decorator:
            return

        endpoint_id = self._get_endpoint_id(request)
        for rule in route_config.behavior_rules:
            if rule.rule_type in ["usage", "frequency"]:
                threshold_exceeded = (
                    await self.guard_decorator.behavior_tracker.track_endpoint_usage(
                        endpoint_id, client_ip, rule
                    )
                )
                if threshold_exceeded:
                    details = f"{rule.threshold} calls in {rule.window}s"
                    message = f"Behavioral {rule.rule_type}"
                    reason = "threshold exceeded"

                    # Send decorator violation event for behavioral rule violation
                    await self._send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="behavioral_action_triggered",
                        reason=f"{message} {reason}: {details}",
                        decorator_type="behavioral",
                        violation_type=rule.rule_type,
                        threshold=rule.threshold,
                        window=rule.window,
                        action=rule.action,
                        endpoint_id=endpoint_id,
                    )

                    await self.guard_decorator.behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Usage threshold exceeded: {details}",
                    )

    async def _process_decorator_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        """Process behavioral return pattern rules from decorators after response."""
        if not self.guard_decorator:
            return

        endpoint_id = self._get_endpoint_id(request)
        for rule in route_config.behavior_rules:
            if rule.rule_type == "return_pattern":
                pattern_detected = (
                    await self.guard_decorator.behavior_tracker.track_return_pattern(
                        endpoint_id, client_ip, response, rule
                    )
                )
                if pattern_detected:
                    details = f"{rule.threshold} for '{rule.pattern}' in {rule.window}s"

                    # Send decorator violation event for return pattern violation
                    await self._send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="behavioral_action_triggered",
                        reason=f"Return pattern threshold exceeded: {details}",
                        decorator_type="behavioral",
                        violation_type="return_pattern",
                        threshold=rule.threshold,
                        window=rule.window,
                        pattern=rule.pattern,
                        action=rule.action,
                        endpoint_id=endpoint_id,
                    )

                    await self.guard_decorator.behavior_tracker.apply_action(
                        rule,
                        client_ip,
                        endpoint_id,
                        f"Return pattern threshold exceeded: {details}",
                    )

    def _get_endpoint_id(self, request: Request) -> str:
        """Generate unique endpoint identifier."""
        if hasattr(request, "scope") and "route" in request.scope:
            route = request.scope["route"]
            if hasattr(route, "endpoint"):
                return f"{route.endpoint.__module__}.{route.endpoint.__qualname__}"
        return f"{request.method}:{request.url.path}"

    async def refresh_cloud_ip_ranges(self) -> None:
        """Refresh cloud IP ranges asynchronously."""
        if not self.config.block_cloud_providers:
            return

        if self.config.enable_redis and self.redis_handler:
            await cloud_handler.refresh_async(self.config.block_cloud_providers)
        else:
            cloud_handler.refresh(self.config.block_cloud_providers)
        self.last_cloud_ip_refresh = int(time.time())

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> Response:
        """
        Create an error response with a custom message.
        """
        custom_message = self.config.custom_error_responses.get(
            status_code, default_message
        )
        response = Response(custom_message, status_code=status_code)

        # Add security headers to error responses
        if self.config.security_headers and self.config.security_headers.get(
            "enabled", True
        ):
            security_headers = await security_headers_manager.get_headers()
            for header_name, header_value in security_headers.items():
                response.headers[header_name] = header_value

        if self.config.custom_response_modifier:
            response = await self.config.custom_response_modifier(response)

        return response

    async def reset(self) -> None:
        """Reset rate limiting state."""
        await self.rate_limit_handler.reset()

    @staticmethod
    def configure_cors(app: FastAPI, config: SecurityConfig) -> bool:
        """
        Configure FastAPI's CORS middleware
        based on SecurityConfig.
        """
        if config.enable_cors:
            cors_params: dict[str, Any] = {
                "allow_origins": config.cors_allow_origins,
                "allow_methods": config.cors_allow_methods,
                "allow_headers": config.cors_allow_headers,
                "allow_credentials": config.cors_allow_credentials,
                "max_age": config.cors_max_age,
            }

            if config.cors_expose_headers:
                cors_params["expose_headers"] = config.cors_expose_headers

            app.add_middleware(CORSMiddleware, **cors_params)
            return True
        return False

    async def _initialize_redis_handlers(self) -> None:
        """Initialize Redis for all handlers that support it."""
        if not (self.config.enable_redis and self.redis_handler):
            return

        await self.redis_handler.initialize()

        # Initialize cloud handler with Redis if cloud providers are blocked
        if self.config.block_cloud_providers:
            await cloud_handler.initialize_redis(
                self.redis_handler, self.config.block_cloud_providers
            )

        # Initialize core handlers
        await ip_ban_manager.initialize_redis(self.redis_handler)
        if self.geo_ip_handler is not None:
            await self.geo_ip_handler.initialize_redis(self.redis_handler)
        await self.rate_limit_handler.initialize_redis(self.redis_handler)
        await sus_patterns_handler.initialize_redis(self.redis_handler)

    async def _initialize_agent_for_handlers(self) -> None:
        """Initialize agent in all handlers that support it."""
        if not self.agent_handler:
            return

        # Initialize core handlers
        await ip_ban_manager.initialize_agent(self.agent_handler)
        await self.rate_limit_handler.initialize_agent(self.agent_handler)
        await sus_patterns_handler.initialize_agent(self.agent_handler)

        # Initialize cloud handler if enabled
        if self.config.block_cloud_providers:
            await cloud_handler.initialize_agent(self.agent_handler)

        # Initialize geo IP handler if it has agent support
        if self.geo_ip_handler and hasattr(self.geo_ip_handler, "initialize_agent"):
            await self.geo_ip_handler.initialize_agent(self.agent_handler)

    async def _initialize_agent_integrations(self) -> None:
        """Initialize agent and its integrations with Redis and decorators."""
        if not self.agent_handler:
            return

        await self.agent_handler.start()

        # Connect agent to Redis if available
        if self.redis_handler:
            await self.agent_handler.initialize_redis(self.redis_handler)
            await self.redis_handler.initialize_agent(self.agent_handler)

        # Initialize agent in all handlers
        await self._initialize_agent_for_handlers()

        # Initialize agent in decorator handler if it exists
        if self.guard_decorator and hasattr(self.guard_decorator, "initialize_agent"):
            await self.guard_decorator.initialize_agent(self.agent_handler)

        # Initialize dynamic rule manager if enabled
        await self._initialize_dynamic_rule_manager()

    async def _initialize_dynamic_rule_manager(self) -> None:
        """Initialize dynamic rule manager if enabled."""
        if not (self.agent_handler and self.config.enable_dynamic_rules):
            return

        from guard.handlers.dynamic_rule_handler import DynamicRuleManager

        dynamic_rule_manager = DynamicRuleManager(self.config)
        await dynamic_rule_manager.initialize_agent(self.agent_handler)

        if self.redis_handler:
            await dynamic_rule_manager.initialize_redis(self.redis_handler)

    async def initialize(self) -> None:
        """Initialize all components asynchronously."""
        # Build security check pipeline
        self._build_security_pipeline()

        # Initialize Redis handlers
        await self._initialize_redis_handlers()

        # Initialize agent and its integrations
        await self._initialize_agent_integrations()
