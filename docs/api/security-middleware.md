---

title: SecurityMiddleware API - FastAPI Guard
description: Complete API reference for FastAPI Guard's SecurityMiddleware class and its configuration options
keywords: security middleware, fastapi middleware, api security, middleware configuration
---

SecurityMiddleware
==================

The `SecurityMiddleware` class is the core component of FastAPI Guard that handles all security features.

!!! info "Architecture (v4.2.0+)"
    Since v4.2.0, SecurityMiddleware uses a modular architecture with specialized core modules. The middleware acts as an orchestration layer, delegating to specialized handlers. See [Core Architecture](core-architecture.md) for internal details.

___

Class Definition
----------------

```python
class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: Callable[[Request], Awaitable[Response]],
        config: SecurityConfig
    ):
        """
        Initialize the SecurityMiddleware.

        Args:
            app: The FastAPI/Starlette application
            config: Security configuration object

        Note:
            The middleware initializes all core components using
            dependency injection for clean separation of concerns.
        """
```

___

Architecture Overview
---------------------

Request Processing Flow
-----------------------

The middleware processes requests through a modular pipeline:

```text
Request → Middleware.dispatch()
    ↓
1. BypassHandler.handle_passthrough()
    ├─ No client IP? → Pass through
    └─ Excluded path? → Pass through
    ↓
2. Extract client IP and route config
    ↓
3. BypassHandler.handle_security_bypass()
    └─ Decorator bypass? → Pass through
    ↓
4. SecurityCheckPipeline.execute()
    ├─ RouteConfigCheck
    ├─ EmergencyModeCheck
    ├─ HttpsEnforcementCheck
    ├─ RequestLoggingCheck
    ├─ RequestSizeContentCheck
    ├─ RequiredHeadersCheck
    ├─ AuthenticationCheck
    ├─ ReferrerCheck
    ├─ CustomValidatorsCheck
    ├─ TimeWindowCheck
    ├─ CloudIpRefreshCheck
    ├─ IpSecurityCheck
    ├─ CloudProviderCheck
    ├─ UserAgentCheck
    ├─ RateLimitCheck
    ├─ SuspiciousActivityCheck
    └─ CustomRequestCheck
    ↓
5. BehavioralProcessor.process_usage_rules()
    ↓
6. call_next(request)  # Forward to app
    ↓
7. ErrorResponseFactory.process_response()
    ├─ Apply security headers
    ├─ Apply CORS headers
    ├─ Collect metrics
    └─ Process behavioral return rules
    ↓
Response
```

Core Components
---------------

The middleware delegates to these specialized modules:

- **SecurityCheckPipeline**: Executes security checks in sequence
- **SecurityEventBus**: Sends security events to monitoring agent
- **MetricsCollector**: Collects request/response metrics
- **HandlerInitializer**: Initializes Redis and Agent handlers
- **ErrorResponseFactory**: Creates and processes responses
- **RouteConfigResolver**: Resolves decorator configurations
- **RequestValidator**: Validates request properties
- **BypassHandler**: Handles security bypasses
- **BehavioralProcessor**: Processes behavioral rules

See [Core Architecture](core-architecture.md) for detailed documentation of each module.

___

Public Methods
--------------

dispatch
--------

```python
async def dispatch(
    self,
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """
    Main request handler that orchestrates security checks.

    This method is pure orchestration - it delegates all logic
    to specialized handlers and maintains no business logic itself.

    Args:
        request: The incoming request
        call_next: The next middleware/handler in the chain

    Returns:
        Response: Either from security checks (blocking) or from the app

    Flow:
        1. Handle passthrough cases (no client, excluded paths)
        2. Get route config and client IP
        3. Handle security bypasses
        4. Execute security pipeline
        5. Process behavioral usage rules
        6. Call next handler
        7. Process response (headers, metrics, behavioral return rules)
    """
```

create_error_response
---------------------

```python
async def create_error_response(
    self,
    status_code: int,
    default_message: str
) -> Response:
    """
    Create standardized error responses.

    Delegates to ErrorResponseFactory for response creation.

    Args:
        status_code: HTTP status code
        default_message: Default error message

    Returns:
        Response: Error response with optional custom message

    Note:
        Custom error messages can be configured in SecurityConfig
        via the custom_error_responses dict.
    """
```

initialize
----------

```python
async def initialize(self) -> None:
    """
    Initialize all components asynchronously.

    This method should be called after adding the middleware to the app,
    typically in a startup event handler.

    Tasks performed:
        - Build security check pipeline
        - Initialize Redis handlers (if enabled)
        - Initialize agent integrations (if enabled)
        - Initialize dynamic rule manager (if configured)

    Example:
        ```python
        @app.on_event("startup")
        async def startup():
            # Get middleware instance
            for middleware in app.user_middleware:
                if isinstance(middleware.cls, SecurityMiddleware):
                    await middleware.cls.initialize()
        ```
    """
```

set_decorator_handler
---------------------

```python
def set_decorator_handler(
    self,
    decorator_handler: BaseSecurityDecorator | None
) -> None:
    """
    Set the SecurityDecorator instance for decorator support.

    This enables route-level security configuration via decorators.

    Args:
        decorator_handler: SecurityDecorator instance or None

    Example:
        ```python
        guard_deco = SecurityDecorator(config)
        middleware.set_decorator_handler(guard_deco)
        # Or set on app state:
        app.state.guard_decorator = guard_deco
        ```
    """
```

configure_cors
--------------

```python
@staticmethod
def configure_cors(app: FastAPI, config: SecurityConfig) -> bool:
    """
    Configure FastAPI's CORS middleware based on SecurityConfig.

    This is a convenience method for setting up CORS.

    Args:
        app: FastAPI application instance
        config: Security configuration with CORS settings

    Returns:
        bool: True if CORS was configured, False otherwise

    Example:
        ```python
        SecurityMiddleware.configure_cors(app, config)
        app.add_middleware(SecurityMiddleware, config=config)
        ```
    """
```

___

Handler Integration
-------------------

The middleware works with singleton handler instances:

- All handler classes (IPBanManager, CloudManager, etc.) use the singleton pattern
- The middleware initializes these existing instances conditionally based on configuration
- IPInfoManager is only initialized when country filtering is enabled
- CloudManager is only loaded when cloud provider blocking is configured
- This selective loading improves performance when not all features are used

Initialization Process
-----------------------

The middleware uses `HandlerInitializer` to set up all handlers:

```python
# In __init__
self.handler_initializer = HandlerInitializer(
    config=self.config,
    redis_handler=self.redis_handler,
    agent_handler=self.agent_handler,
    geo_ip_handler=self.geo_ip_handler,
    rate_limit_handler=self.rate_limit_handler,
    guard_decorator=self.guard_decorator,
)

# In initialize()
await self.handler_initializer.initialize_redis_handlers()
await self.handler_initializer.initialize_agent_integrations()
```

___

Redis Configuration
-------------------

Enable Redis in SecurityConfig:

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://prod:6379/0",
    redis_prefix="prod_security:"
)
```

The middleware automatically initializes:
- CloudManager cloud provider IP ranges
- IPBanManager distributed banning
- IPInfoManager IP geolocation
- RateLimitManager rate limiting
- RedisManager Redis caching
- SusPatternsManager suspicious patterns

___

Proxy Security Configuration
----------------------------

The middleware supports secure handling of proxy headers:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # List of trusted proxy IPs/ranges
    trusted_proxy_depth=1,  # Number of proxies in the chain
    trust_x_forwarded_proto=True,  # Trust X-Forwarded-Proto header from trusted proxies
)
```

This prevents IP spoofing attacks through header manipulation.

___

Usage Examples
--------------

Basic Setup
-----------

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    rate_limit=100,
    enable_https=True,
    enable_cors=True
)

app.add_middleware(SecurityMiddleware, config=config)
```

With Decorators
---------------

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig
from guard.decorators import SecurityDecorator

app = FastAPI()

config = SecurityConfig(rate_limit=100)
guard_deco = SecurityDecorator(config)

# Apply decorators to routes
@app.get("/api/limited")
@guard_deco.rate_limit(requests=10, window=300)
def limited_endpoint():
    return {"data": "limited"}

# Add middleware and set decorator
app.add_middleware(SecurityMiddleware, config=config)
app.state.guard_decorator = guard_deco  # Required for decorator integration
```

With Async Initialization
-------------------------

```python
from fastapi import FastAPI
from guard.middleware import SecurityMiddleware
from guard.models import SecurityConfig

app = FastAPI()

config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://localhost:6379"
)

# Add middleware
middleware_instance = None
for mw in app.user_middleware:
    if isinstance(mw.cls, type) and issubclass(mw.cls, SecurityMiddleware):
        middleware_instance = mw.cls
        break

app.add_middleware(SecurityMiddleware, config=config)

@app.on_event("startup")
async def startup():
    # Initialize async components
    if middleware_instance:
        await middleware_instance.initialize()
```

___

Internal Architecture
---------------------

!!! note "For Contributors"
    The internal architecture is documented in [Core Architecture](core-architecture.md). This section provides a high-level overview.

Modular Design (v4.2.0+)
-------------------------

The middleware delegates to specialized modules in `guard/core/`:

- **checks/**: Security check implementations (Chain of Responsibility pattern)
- **events/**: Event bus and metrics collection
- **initialization/**: Handler initialization logic
- **responses/**: Response creation and processing
- **routing/**: Route configuration resolution
- **validation/**: Request validation utilities
- **bypass/**: Security bypass handling
- **behavioral/**: Behavioral rule processing

Benefits of Modular Architecture
--------------------------------

- **Maintainability**: Each module < 200 LOC, single responsibility
- **Testability**: Each component independently testable
- **Performance**: Better caching and optimization opportunities
- **Extensibility**: Easy to add new checks or modify behavior
- **Development Speed**: 2-3x faster feature additions (projected)

___

See Also
--------

- [Core Architecture](core-architecture.md) - Detailed internal architecture
- [SecurityConfig](../tutorial/configuration/security-config.md) - Configuration options
- [Decorators](decorators.md) - Route-level security
- [API Overview](overview.md) - Complete API reference
