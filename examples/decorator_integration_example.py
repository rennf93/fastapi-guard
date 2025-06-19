"""
FastAPI Guard - Decorator Integration Example

This example demonstrates how to use the new decorator system
alongside the existing SecurityMiddleware for enhanced route-specific security.
"""

from typing import Any

from fastapi import FastAPI

from guard import (
    BehaviorRule,
    SecurityConfig,
    SecurityDecorator,
    SecurityMiddleware,
)

# Initialize FastAPI app
app = FastAPI(title="FastAPI Guard Decorator Integration Example")

# Basic security configuration
config = SecurityConfig(
    rate_limit=100,
    rate_limit_window=3600,
    enable_penetration_detection=True,
    enable_redis=True,
    redis_url="redis://localhost:6379",
)

# Initialize decorator handler
guard_decorator = SecurityDecorator(config)

# Initialize and add middleware
middleware = SecurityMiddleware(app, config=config)
app.add_middleware(SecurityMiddleware, config=config)

# IMPORTANT: Connect the decorator handler to middleware for integration
middleware.set_decorator_handler(guard_decorator)


# EXAMPLE 1: Basic decorator usage - override global rate limiting
@app.get("/api/limited")
# NOTE: Override: 10 requests per minute vs global 100/hour
@guard_decorator.rate_limit(requests=10, window=60)
def limited_endpoint() -> dict[str, str]:
    return {"message": "This endpoint has strict rate limiting"}


# EXAMPLE 2: Behavioral monitoring - Reddit user's exact request
@app.get("/api/sensitive")
# NOTE: @guard_usage(8) equivalent
@guard_decorator.usage_monitor(
    max_calls=8,
    window=3600,
    action="ban",
)
def sensitive_endpoint() -> dict[str, str]:
    return {"data": "sensitive operation"}


# EXAMPLE 3: Return pattern monitoring - Gaming anti-cheat
@app.get("/api/lootbox")
# NOTE: @guard_return("win", 3, timespan=24) equivalent
@guard_decorator.return_monitor(
    "win",
    max_occurrences=3,
    window=86400,
    action="ban",
)
def lootbox_endpoint() -> dict[str, Any]:
    # Simulate lootbox logic
    import random

    if random.random() < 0.1:  # 10% win rate
        return {"result": {"status": "win", "item": "rare_sword"}}
    else:
        return {"result": {"status": "lose", "item": None}}


# EXAMPLE 4: Multiple security rules on one endpoint
@app.post("/api/admin")
# NOTE: Only internal IPs
@guard_decorator.require_ip(whitelist=["10.0.0.0/8"])
# NOTE: Block specific countries
@guard_decorator.block_countries(["CN", "RU"])
# NOTE: 5 requests per 5 minutes
@guard_decorator.rate_limit(requests=5, window=300)
# NOTE: Force HTTPS
@guard_decorator.require_https()
# NOTE: Require API key
@guard_decorator.api_key_auth("X-Admin-Key")
def admin_endpoint() -> dict[str, str]:
    return {"message": "Admin area accessed"}


# EXAMPLE 5: Cloud provider blocking
@app.get("/api/no-clouds")
# NOTE: Block AWS and GCP IPs
@guard_decorator.block_clouds(["AWS", "GCP"])
def no_clouds_endpoint() -> dict[str, str]:
    return {"message": "No cloud provider IPs allowed"}


# EXAMPLE 6: Complex behavioral analysis
complex_rules = [
    BehaviorRule(
        "usage",
        threshold=20,
        window=3600,
        action="throttle",
    ),
    BehaviorRule(
        "return_pattern",
        threshold=5,
        pattern="json:success==true",
        window=1800,
        action="log",
    ),
    BehaviorRule(
        "frequency",
        threshold=60,
        window=3600,
        action="ban",
    ),
]


@app.post("/api/complex")
@guard_decorator.behavior_analysis(complex_rules)
def complex_endpoint() -> dict[str, Any]:
    return {"success": True, "data": "complex operation"}


# EXAMPLE 7: Bypass security checks
@app.get("/api/public")
# NOTE: Skip rate limiting and penetration detection
@guard_decorator.bypass(["rate_limit", "penetration"])
def public_endpoint() -> dict[str, str]:
    return {"message": "Public endpoint with relaxed security"}


if __name__ == "__main__":
    import uvicorn

    # Initialize behavioral tracking if Redis is available
    async def startup() -> None:
        if config.enable_redis:
            await guard_decorator.initialize_behavior_tracking(middleware.redis_handler)

    app.add_event_handler("startup", startup)

    # Run the application
    uvicorn.run(app, host="0.0.0.0", port=8000)
