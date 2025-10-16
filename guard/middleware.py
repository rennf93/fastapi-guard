# guard/middleware.py
import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from guard.core.behavioral import (
    BehavioralContext,
    BehavioralProcessor,
)
from guard.core.bypass import BypassContext, BypassHandler
from guard.core.checks.pipeline import SecurityCheckPipeline
from guard.core.events import MetricsCollector, SecurityEventBus
from guard.core.initialization import HandlerInitializer
from guard.core.responses import ErrorResponseFactory, ResponseContext
from guard.core.routing import RouteConfigResolver, RoutingContext
from guard.core.validation import RequestValidator, ValidationContext
from guard.decorators.base import BaseSecurityDecorator, RouteConfig
from guard.handlers.cloud_handler import cloud_handler
from guard.handlers.ratelimit_handler import RateLimitManager
from guard.handlers.security_headers_handler import security_headers_manager
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

        # Initialize security check pipeline (built in initialize())
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

        # Initialize request validator
        validation_context = ValidationContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
        )
        self.validator = RequestValidator(validation_context)

        # Initialize bypass handler (requires validator and route_resolver)
        bypass_context = BypassContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            route_resolver=self.route_resolver,
            response_factory=self.response_factory,
            validator=self.validator,
        )
        self.bypass_handler = BypassHandler(bypass_context)

        # Initialize behavioral processor
        behavioral_context = BehavioralContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            guard_decorator=self.guard_decorator,
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)

    def _build_security_pipeline(self) -> None:
        """Build the security check pipeline with configured checks."""
        from guard.core.checks import (
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

    async def _create_https_redirect(self, request: Request) -> Response:
        """
        Create HTTPS redirect response with custom modifier if configured.

        Delegates to ErrorResponseFactory for redirect creation.
        """
        return await self.response_factory.create_https_redirect(request)

    async def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        """Check if current time is within allowed time window (for tests)."""
        return await self.validator.check_time_window(time_restrictions)

    async def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        """Check route-specific IP restrictions (for tests)."""
        from guard.core.checks.helpers import check_route_ip_access

        return await check_route_ip_access(client_ip, route_config, self)

    async def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        """Check if user agent is allowed (for tests)."""
        from guard.core.checks.helpers import check_user_agent_allowed

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

    async def _process_response(
        self,
        request: Request,
        response: Response,
        response_time: float,
        route_config: RouteConfig | None,
    ) -> Response:
        """
        Process the response with behavioral rules, metrics, and headers.

        Delegates to ErrorResponseFactory and BehavioralProcessor.
        """
        return await self.response_factory.process_response(
            request,
            response,
            response_time,
            route_config,
            process_behavioral_rules=self.behavioral_processor.process_return_rules,
        )

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """
        Dispatch method to handle incoming requests and apply security measures.

        Pure orchestration - delegates all logic to specialized handlers:
        - BypassHandler: Handles passthrough cases and security bypass
        - SecurityCheckPipeline: Executes security checks
        - BehavioralProcessor: Processes behavioral rules
        - ErrorResponseFactory: Processes response with metrics and headers

        Args:
            request: The incoming request object.
            call_next: The next middleware or route handler in the chain.

        Returns:
            Response: The response object, either from the next handler
            or a security-related blocking response.
        """
        # 1. Handle passthrough cases (no client, excluded paths)
        passthrough = await self.bypass_handler.handle_passthrough(request, call_next)
        if passthrough:
            return passthrough

        # 2. Get route config and client IP
        client_ip = await extract_client_ip(request, self.config, self.agent_handler)
        route_config = self.route_resolver.get_route_config(request)

        # 3. Handle bypassed security checks
        if bypass := await self.bypass_handler.handle_security_bypass(
            request, call_next, route_config
        ):
            return bypass

        # 4. Execute security pipeline
        if not self.security_pipeline:
            self._build_security_pipeline()
        assert self.security_pipeline is not None

        if blocking := await self.security_pipeline.execute(request):
            return blocking

        # 5. Process behavioral usage rules
        if route_config and route_config.behavior_rules and client_ip:
            await self.behavioral_processor.process_usage_rules(
                request, client_ip, route_config
            )

        # 6. Call next handler and measure time
        start_time = time.time()
        response = await call_next(request)
        response_time = time.time() - start_time

        # 7. Process response (rules, metrics, headers)
        return await self._process_response(
            request, response, response_time, route_config
        )

    async def _process_decorator_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> None:
        """Process behavioral usage rules (wrapper for tests)."""
        return await self.behavioral_processor.process_usage_rules(
            request, client_ip, route_config
        )

    async def _process_decorator_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        """Process behavioral return rules (wrapper for tests)."""
        return await self.behavioral_processor.process_return_rules(
            request, response, client_ip, route_config
        )

    def _get_endpoint_id(self, request: Request) -> str:
        """Generate unique endpoint identifier (wrapper for tests)."""
        return self.behavioral_processor.get_endpoint_id(request)

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
