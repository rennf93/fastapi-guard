import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, cast

from fastapi import Request, Response
from guard_core.core.behavioral import BehavioralContext, BehavioralProcessor
from guard_core.core.bypass import BypassContext, BypassHandler
from guard_core.core.checks.pipeline import SecurityCheckPipeline
from guard_core.core.events import MetricsCollector, SecurityEventBus
from guard_core.core.initialization import HandlerInitializer
from guard_core.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.core.routing import RouteConfigResolver, RoutingContext
from guard_core.core.validation import RequestValidator, ValidationContext
from guard_core.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.exceptions import AgentPackageNotInstalledError
from guard_core.handlers.cloud_handler import cloud_handler
from guard_core.handlers.cors_handler import CorsHandler, is_preflight
from guard_core.handlers.ratelimit_handler import RateLimitManager
from guard_core.handlers.security_headers_handler import security_headers_manager
from guard_core.models import SecurityConfig
from guard_core.protocols import AgentHandlerProtocol, GuardResponse
from guard_core.protocols.request_protocol import GuardRequest
from guard_core.utils import (
    extract_client_ip,
    invoke_error_hook,
    setup_custom_logging,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse
from starlette.routing import Match
from starlette.types import ASGIApp

from guard.adapters import (
    StarletteGuardRequest,
    StarletteResponseFactory,
    unwrap_response,
    wrap_call_next,
)

if TYPE_CHECKING:
    from guard._middleware_state import MiddlewareState


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, *, config: SecurityConfig) -> None:
        super().__init__(app)
        self.app = app
        self.config = config
        self.logger = setup_custom_logging(
            config.custom_log_file, log_format=config.log_format
        )
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
        self.last_cleanup = time.time()
        self.rate_limit_handler = RateLimitManager(config)
        self.guard_decorator: BaseSecurityDecorator | None = None

        self._configure_security_headers(config)

        self.geo_ip_handler = None
        if config.whitelist_countries or config.blocked_countries:
            self.geo_ip_handler = config.geo_ip_handler

        self.redis_handler = None
        if config.enable_redis:
            from guard_core.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(config)

        self.agent_handler: AgentHandlerProtocol | None = None
        self.agent_degraded = False
        if config.enable_agent:
            try:
                agent_config = config.to_agent_config()
                from guard_agent import guard_agent

                self.agent_handler = cast(
                    AgentHandlerProtocol, guard_agent(cast(Any, agent_config))
                )
                self.logger.info("Guard Agent initialized successfully")
            except AgentPackageNotInstalledError as e:
                self._on_agent_init_failed(
                    config,
                    e,
                    "Agent enabled but guard-agent is not installed. "
                    "Install with: pip install fastapi-guard[agent]",
                )
            except Exception as e:
                self._on_agent_init_failed(
                    config, e, f"Failed to initialize Guard Agent: {e}"
                )

        self.security_pipeline: SecurityCheckPipeline | None = None

        self._guard_response_factory = StarletteResponseFactory()

        self.event_bus = SecurityEventBus(
            self.agent_handler, self.config, self.geo_ip_handler
        )
        self.metrics_collector = MetricsCollector(self.agent_handler, self.config)

        self.handler_initializer = HandlerInitializer(
            config=self.config,
            redis_handler=self.redis_handler,
            agent_handler=self.agent_handler,
            geo_ip_handler=self.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
        )

        routing_context = RoutingContext(
            config=self.config,
            logger=self.logger,
            guard_decorator=self.guard_decorator,
        )
        self.route_resolver = RouteConfigResolver(routing_context)

        self._build_event_dependent_contexts()

        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._cors_handler: CorsHandler | None = (
            CorsHandler(config) if config.enable_cors else None
        )

    def _is_initialized(self) -> bool:
        return self._initialized

    def mark_initialized(self) -> None:
        self._initialized = True

    async def _ensure_initialized(self) -> None:
        if self._is_initialized():
            return
        async with self._init_lock:
            if self._is_initialized():
                return

            from guard._middleware_state import (
                MiddlewareState,
                get_state,
                register_state,
            )

            warm = get_state(self.config)
            if warm is not None:
                self._adopt_warm_state(warm)
                self._initialized = True
                return

            await self.initialize()
            register_state(
                self.config,
                MiddlewareState(
                    security_pipeline=self.security_pipeline,
                    composite_handler=self.handler_initializer.composite_handler,
                    event_bus=self.event_bus,
                    metrics_collector=self.metrics_collector,
                    response_factory=self.response_factory,
                    validator=self.validator,
                    bypass_handler=self.bypass_handler,
                    behavioral_processor=self.behavioral_processor,
                    handler_initializer=self.handler_initializer,
                    agent_handler=self.agent_handler,
                ),
            )
            self._initialized = True

    def _adopt_warm_state(self, state: "MiddlewareState") -> None:
        self.security_pipeline = cast(SecurityCheckPipeline, state.security_pipeline)
        self.event_bus = cast(SecurityEventBus, state.event_bus)
        self.metrics_collector = cast(MetricsCollector, state.metrics_collector)
        self.response_factory = cast(ErrorResponseFactory, state.response_factory)
        self.validator = cast(RequestValidator, state.validator)
        self.bypass_handler = cast(BypassHandler, state.bypass_handler)
        self.behavioral_processor = cast(
            BehavioralProcessor, state.behavioral_processor
        )
        self.handler_initializer = cast(HandlerInitializer, state.handler_initializer)
        if state.composite_handler is not None:
            self.agent_handler = cast(AgentHandlerProtocol, state.composite_handler)
        elif state.agent_handler is not None:
            self.agent_handler = cast(AgentHandlerProtocol, state.agent_handler)

    def _build_event_dependent_contexts(self) -> None:
        response_context = ResponseContext(
            config=self.config,
            logger=self.logger,
            metrics_collector=self.metrics_collector,
            agent_handler=self.agent_handler,
            guard_decorator=self.guard_decorator,
            response_factory=self._guard_response_factory,
        )
        self.response_factory = ErrorResponseFactory(response_context)

        validation_context = ValidationContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
        )
        self.validator = RequestValidator(validation_context)

        bypass_context = BypassContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            route_resolver=self.route_resolver,
            response_factory=self.response_factory,
            validator=self.validator,
        )
        self.bypass_handler = BypassHandler(bypass_context)

        behavioral_context = BehavioralContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            guard_decorator=self.guard_decorator,
            behavior_tracker=self.handler_initializer.behavior_tracker,
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)

    @property
    def guard_response_factory(self) -> StarletteResponseFactory:
        return self._guard_response_factory

    def _on_agent_init_failed(
        self, config: SecurityConfig, exc: Exception, message: str
    ) -> None:
        self.agent_degraded = True
        invoke_error_hook(config.on_error, "agent_init", exc, {})
        if config.agent_strict:
            raise exc
        self.logger.error(message)
        self.logger.warning("Continuing without agent functionality")

    @property
    def agent_stats(self) -> dict[str, Any]:
        if self.agent_handler is None:
            return {"enabled": False, "degraded": self.agent_degraded}
        handler_stats = cast(Any, self.agent_handler).get_stats()
        return {"enabled": True, "degraded": self.agent_degraded, **handler_stats}

    def _build_security_pipeline(self) -> None:
        from guard_core.core.checks import (
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
            RouteConfigCheck(self),
            EmergencyModeCheck(self),
            HttpsEnforcementCheck(self),
            RequestLoggingCheck(self),
            RequestSizeContentCheck(self),
            RequiredHeadersCheck(self),
            AuthenticationCheck(self),
            ReferrerCheck(self),
            CustomValidatorsCheck(self),
            TimeWindowCheck(self),
            CloudIpRefreshCheck(self),
            IpSecurityCheck(self),
            CloudProviderCheck(self),
            UserAgentCheck(self),
            RateLimitCheck(self),
            SuspiciousActivityCheck(self),
            CustomRequestCheck(self),
        ]

        self.security_pipeline = SecurityCheckPipeline(checks)
        self.logger.info(
            f"Security pipeline initialized with {len(checks)} checks: "
            f"{self.security_pipeline.get_check_names()}"
        )

    def _configure_security_headers(self, config: SecurityConfig) -> None:
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
        self.guard_decorator = decorator_handler

    async def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        result: bool = await self.validator.check_time_window(time_restrictions)
        return result

    async def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        from guard_core.core.checks.helpers import check_route_ip_access

        result: bool | None = await check_route_ip_access(client_ip, route_config, self)
        return result

    async def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        from guard_core.core.checks.helpers import check_user_agent_allowed

        result: bool = await check_user_agent_allowed(
            user_agent, route_config, self.config
        )
        return result

    async def _process_response(
        self,
        request: Request,
        response: Response,
        response_time: float,
        route_config: RouteConfig | None,
    ) -> Response:
        from guard.adapters import StarletteGuardResponse

        guard_request = StarletteGuardRequest(request)
        guard_response = StarletteGuardResponse(response)
        result = await self.response_factory.process_response(
            guard_request,
            guard_response,
            response_time,
            route_config,
            process_behavioral_rules=self.behavioral_processor.process_return_rules,
        )
        return unwrap_response(result)

    def _resolve_route(self, request: Request) -> Any:
        route = request.scope.get("route")
        if route:
            return route

        # This middleware is a BaseHTTPMiddleware, so it runs before the router
        # and scope["route"] is unset here. Replicate Starlette's own matching
        # against the app's routes so per-route decorator config resolves for
        # routes with path parameters (e.g. "/items/{id}") and routes added via
        # include_router. A plain ``r.path == request.url.path`` comparison never
        # matches a templated path, which silently drops per-route config on
        # every parameterised route.
        app = request.scope.get("app")
        routes = getattr(app, "routes", None)
        if not routes:
            return None
        for r in routes:
            if self._route_matches_request(r, request.scope):
                return r
        return None

    def _route_matches_request(self, route: Any, scope: Any) -> bool:
        if not hasattr(route, "endpoint"):
            return False
        matches = getattr(route, "matches", None)
        if matches is None:
            return False
        try:
            match, _ = matches(scope)
        except Exception:
            return False
        return bool(match == Match.FULL)

    def _populate_guard_state(
        self, guard_request: StarletteGuardRequest, request: Request
    ) -> None:
        app_obj = request.scope.get("app")
        if app_obj and hasattr(app_obj, "state"):
            app_decorator = getattr(app_obj.state, "guard_decorator", None)
            if app_decorator:
                guard_request.state.guard_decorator = app_decorator

        route = self._resolve_route(request)
        if not route or not hasattr(route, "endpoint"):
            return

        ep = route.endpoint
        if hasattr(ep, "_guard_route_id"):
            guard_request.state.guard_route_id = ep._guard_route_id
        if hasattr(ep, "__module__") and hasattr(ep, "__qualname__"):
            guard_request.state.guard_endpoint_id = f"{ep.__module__}.{ep.__qualname__}"

    def _build_preflight_starlette_response(
        self, request_headers: Any
    ) -> StarletteResponse:
        assert self._cors_handler is not None
        preflight = self._cors_handler.build_preflight_response(request_headers)
        return StarletteResponse(
            content=preflight.body,
            status_code=preflight.status_code,
            headers=preflight.headers,
        )

    def _inject_cors_headers(self, response: Response, request_headers: Any) -> None:
        if self._cors_handler is None:
            return
        cors_headers = self._cors_handler.build_response_headers(request_headers)
        for key, value in cors_headers.items():
            response.headers[key] = value

    async def _handle_preflight(
        self, request: Request, guard_request: StarletteGuardRequest
    ) -> Response | None:
        if self._cors_handler is None:
            return None
        if not is_preflight(request.method, request.headers):
            return None
        assert self.security_pipeline is not None
        blocking = await self.security_pipeline.execute(guard_request)
        if blocking is not None:
            blocked = unwrap_response(blocking)
            self._inject_cors_headers(blocked, request.headers)
            return blocked
        return self._build_preflight_starlette_response(request.headers)

    async def _handle_passthrough(
        self,
        request: Request,
        guard_request: StarletteGuardRequest,
        wrapped_call_next: Callable[[GuardRequest], Awaitable[GuardResponse]],
    ) -> Response | None:
        passthrough = await self.bypass_handler.handle_passthrough(
            guard_request, wrapped_call_next
        )
        if passthrough is None:
            return None
        passthrough_response = unwrap_response(passthrough)
        self._inject_cors_headers(passthrough_response, request.headers)
        return passthrough_response

    async def _handle_security_bypass(
        self,
        request: Request,
        guard_request: StarletteGuardRequest,
        wrapped_call_next: Callable[[GuardRequest], Awaitable[GuardResponse]],
        route_config: RouteConfig | None,
    ) -> Response | None:
        bypass = await self.bypass_handler.handle_security_bypass(
            guard_request, wrapped_call_next, route_config
        )
        if bypass is None:
            return None
        bypass_response = unwrap_response(bypass)
        self._inject_cors_headers(bypass_response, request.headers)
        return bypass_response

    async def _handle_pipeline_block(
        self, request: Request, guard_request: StarletteGuardRequest
    ) -> Response | None:
        assert self.security_pipeline is not None
        blocking = await self.security_pipeline.execute(guard_request)
        if blocking is None:
            return None
        blocked = unwrap_response(blocking)
        self._inject_cors_headers(blocked, request.headers)
        return blocked

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        await self._ensure_initialized()

        guard_request = StarletteGuardRequest(request)
        wrapped_call_next = wrap_call_next(call_next, request)
        self._populate_guard_state(guard_request, request)

        preflight_response = await self._handle_preflight(request, guard_request)
        if preflight_response is not None:
            return preflight_response

        passthrough_response = await self._handle_passthrough(
            request, guard_request, wrapped_call_next
        )
        if passthrough_response is not None:
            return passthrough_response

        client_ip = await extract_client_ip(
            guard_request, self.config, self.agent_handler
        )
        route_config = self.route_resolver.get_route_config(guard_request)

        bypass_response = await self._handle_security_bypass(
            request, guard_request, wrapped_call_next, route_config
        )
        if bypass_response is not None:
            return bypass_response

        blocked_response = await self._handle_pipeline_block(request, guard_request)
        if blocked_response is not None:
            return blocked_response

        if route_config and route_config.behavior_rules and client_ip:
            await self.behavioral_processor.process_usage_rules(
                guard_request, client_ip, route_config
            )

        start_time = time.time()
        response = await call_next(request)
        response_time = time.time() - start_time

        processed = await self._process_response(
            request, response, response_time, route_config
        )
        self._inject_cors_headers(processed, request.headers)
        return processed

    async def _process_decorator_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> None:
        guard_request = StarletteGuardRequest(request)
        await self.behavioral_processor.process_usage_rules(
            guard_request, client_ip, route_config
        )

    async def _process_decorator_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        from guard.adapters import StarletteGuardResponse

        guard_request = StarletteGuardRequest(request)
        guard_response = StarletteGuardResponse(response)
        await self.behavioral_processor.process_return_rules(
            guard_request, guard_response, client_ip, route_config
        )

    def _get_endpoint_id(self, request: Request) -> str:
        guard_request = StarletteGuardRequest(request)
        result: str = self.behavioral_processor.get_endpoint_id(guard_request)
        return result

    async def refresh_cloud_ip_ranges(self) -> None:
        if not self.config.block_cloud_providers:
            return

        providers: set[str] = {
            str(provider) for provider in self.config.block_cloud_providers
        }

        if self.config.enable_redis and self.redis_handler:
            await cloud_handler.refresh_async(
                providers,
                ttl=self.config.cloud_ip_refresh_interval,
            )
        else:
            await cloud_handler.refresh(providers)
        self.last_cloud_ip_refresh = int(time.time())

    async def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        return await self.response_factory.create_error_response(
            status_code, default_message
        )

    async def reset(self) -> None:
        await self.rate_limit_handler.reset()

    async def initialize(self) -> None:
        self._build_security_pipeline()

        self.handler_initializer.guard_decorator = self.guard_decorator

        await self.handler_initializer.initialize_redis_handlers()

        await self.handler_initializer.initialize_agent_integrations()

        if self.handler_initializer.composite_handler is not None:
            self.agent_handler = self.handler_initializer.composite_handler
            self.event_bus = self.handler_initializer.build_event_bus(
                geo_ip_handler=self.geo_ip_handler
            )
            self.metrics_collector = self.handler_initializer.build_metrics_collector()
            self._build_event_dependent_contexts()
