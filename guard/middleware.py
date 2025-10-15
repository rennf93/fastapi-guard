# fastapi_guard/middleware.py
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from guard.decorators.base import BaseSecurityDecorator, RouteConfig
from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ratelimit_handler import RateLimitManager
from guard.handlers.security_headers_handler import security_headers_manager
from guard.middleware_components.checks.pipeline import SecurityCheckPipeline
from guard.middleware_components.events import MetricsCollector, SecurityEventBus
from guard.middleware_components.initialization import HandlerInitializer
from guard.middleware_components.responses import ErrorResponseFactory, ResponseContext
from guard.middleware_components.routing import RouteConfigResolver, RoutingContext
from guard.models import SecurityConfig
from guard.utils import (
    extract_client_ip,
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

        # Initialize event bus and metrics collector
        self.event_bus = SecurityEventBus(
            self.agent_handler, self.config, self.geo_ip_handler
        )
        self.metrics_collector = MetricsCollector(self.agent_handler, self.config)

        # Initialize handler initializer
        self.handler_initializer = HandlerInitializer(
            config=self.config,
            redis_handler=self.redis_handler,
            agent_handler=self.agent_handler,
            geo_ip_handler=self.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
        )

        # Initialize response factory
        response_context = ResponseContext(
            config=self.config,
            logger=self.logger,
            metrics_collector=self.metrics_collector,
            agent_handler=self.agent_handler,
            guard_decorator=self.guard_decorator,
        )
        self.response_factory = ErrorResponseFactory(response_context)

        # Initialize route config resolver
        routing_context = RoutingContext(
            config=self.config,
            logger=self.logger,
            guard_decorator=self.guard_decorator,
        )
        self.route_resolver = RouteConfigResolver(routing_context)

    def _build_security_pipeline(self) -> None:
        """Build the security check pipeline with configured checks."""
        from guard.middleware_components.checks import (
            AuthenticationCheck,
            CloudIpRefreshCheck,
            CloudProviderCheck,
            CustomRequestCheck,
            CustomValidatorsCheck,
            EmergencyModeCheck,
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
            # Emergency mode (highest priority after routing)
            EmergencyModeCheck(self),
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

    async def _create_https_redirect(self, request: Request) -> Response:
        """
        Create HTTPS redirect response with custom modifier if configured.

        Delegates to ErrorResponseFactory for redirect creation.
        """
        return await self.response_factory.create_https_redirect(request)

    async def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        """Check if current time is within allowed time window (for tests)."""
        try:
            start_time = time_restrictions["start"]
            end_time = time_restrictions["end"]

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
            self.logger.error(f"Error checking time window: {e!s}")
            return True  # Allow access if time check fails

    async def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        """Check route-specific IP restrictions (for tests)."""
        from guard.middleware_components.checks.helpers import check_route_ip_access

        return await check_route_ip_access(client_ip, route_config, self)

    async def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        """Check if user agent is allowed (for tests)."""
        from guard.middleware_components.checks.helpers import check_user_agent_allowed

        return await check_user_agent_allowed(user_agent, route_config, self.config)

    async def _check_rate_limit(
        self, request: Request, client_ip: str, route_config: RouteConfig | None = None
    ) -> Response | None:
        """Check rate limiting (for tests)."""
        response = await self.rate_limit_handler.check_rate_limit(
            request, client_ip, self.create_error_response
        )

        # In passive mode, log but don't block
        if response and self.config.passive_mode:
            return None

        return response

    async def _is_path_excluded(self, request: Request) -> bool:
        """Check if the request path is excluded from security checks."""
        if any(request.url.path.startswith(path) for path in self.config.exclude_paths):
            # Send path exclusion event for monitoring
            await self.event_bus.send_middleware_event(
                event_type="path_excluded",
                request=request,
                action_taken="security_checks_bypassed",
                reason=f"Path {request.url.path} excluded from security checks",
                excluded_path=request.url.path,
                configured_exclusions=self.config.exclude_paths,
            )
            return True
        return False

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
            return await self.response_factory.apply_modifier(response)

        # Excluded paths
        if await self._is_path_excluded(request):
            response = await call_next(request)
            return await self.response_factory.apply_modifier(response)

        return None

    async def _handle_security_bypass(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
        route_config: RouteConfig | None,
    ) -> Response | None:
        """Handle bypassed security checks."""
        if not route_config or not self.route_resolver.should_bypass_check(
            "all", route_config
        ):
            return None

        # Send security bypass event for monitoring
        await self.event_bus.send_middleware_event(
            event_type="security_bypass",
            request=request,
            action_taken="all_checks_bypassed",
            reason="Route configured to bypass all security checks",
            bypassed_checks=list(route_config.bypassed_checks),
            endpoint=str(request.url.path),
        )

        if not self.config.passive_mode:
            response = await call_next(request)
            return await self.response_factory.apply_modifier(response)

        return None

    async def _handle_no_client(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response | None:
        """Handle requests with no client information."""
        if not request.client:
            response = await call_next(request)
            return await self.response_factory.apply_modifier(response)
        return None

    async def _handle_bypass_and_excluded(
        self,
        request: Request,
        route_config: RouteConfig | None,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response | None:
        """Handle bypassed security checks and return response if applicable."""
        if route_config and self.route_resolver.should_bypass_check(
            "all", route_config
        ):
            # Send security bypass event for monitoring
            await self.event_bus.send_middleware_event(
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
                return await self.response_factory.apply_modifier(response)
        return None

    async def _process_response(
        self,
        request: Request,
        response: Response,
        response_time: float,
        route_config: RouteConfig | None,
    ) -> Response:
        """
        Process the response with behavioral rules, metrics, and headers.

        Delegates to ErrorResponseFactory for response processing.
        """
        return await self.response_factory.process_response(
            request,
            response,
            response_time,
            route_config,
            process_behavioral_rules=self._process_decorator_return_rules,
        )


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

        # Get route config for bypass check before pipeline
        client_ip = await extract_client_ip(request, self.config, self.agent_handler)
        route_config = self.route_resolver.get_route_config(request)

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
                    await self.event_bus.send_middleware_event(
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
                    await self.event_bus.send_middleware_event(
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

        Delegates to ErrorResponseFactory for response creation.
        """
        return await self.response_factory.create_error_response(
            status_code, default_message
        )

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

    async def initialize(self) -> None:
        """Initialize all components asynchronously."""
        # Build security check pipeline
        self._build_security_pipeline()

        # Update handler initializer with current decorator (may have changed)
        self.handler_initializer.guard_decorator = self.guard_decorator

        # Initialize Redis handlers
        await self.handler_initializer.initialize_redis_handlers()

        # Initialize agent and its integrations
        await self.handler_initializer.initialize_agent_integrations()
