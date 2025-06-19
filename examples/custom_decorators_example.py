"""
Example: Creating Custom Security Decorators

This example shows how users can extend FastAPI Guard by creating their own
decorator mixins following the established patterns.
"""

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response

from guard import SecurityConfig, SecurityDecorator
from guard.decorators.base import BaseSecurityMixin


class CustomBusinessLogicMixin(BaseSecurityMixin):
    """Custom mixin for business-specific security decorators."""

    def require_subscription(
        self,
        tier: str = "premium",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Require a specific subscription tier."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            async def subscription_validator(request: Request) -> Response | None:
                # Example business logic - check user subscription
                user_id = request.headers.get("X-User-ID")
                subscription = request.headers.get("X-Subscription-Tier")

                if not user_id or subscription != tier:
                    return Response(
                        f"Subscription tier '{tier}' required",
                        status_code=402,  # Payment Required
                    )
                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(subscription_validator)
            return self._apply_route_config(func)

        return decorator

    def feature_flag(
        self,
        flag_name: str,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Require a feature flag to be enabled."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            async def feature_flag_validator(request: Request) -> Response | None:
                # Example: Check if feature is enabled for this user/account
                enabled_features = request.headers.get("X-Enabled-Features", "").split(
                    ","
                )

                if flag_name not in enabled_features:
                    return Response(
                        f"Feature '{flag_name}' not enabled",
                        status_code=403,
                    )
                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(feature_flag_validator)
            return self._apply_route_config(func)

        return decorator

    def ab_test_group(
        self,
        test_name: str,
        allowed_groups: list[str],
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Restrict access based on A/B test group."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            async def ab_test_validator(request: Request) -> Response | None:
                user_group = request.headers.get(f"X-AB-{test_name}")

                if user_group not in allowed_groups:
                    return Response(
                        "Access restricted for this test group",
                        status_code=403,
                    )
                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(ab_test_validator)
            return self._apply_route_config(func)

        return decorator


class DatabaseSecurityMixin(BaseSecurityMixin):
    """Custom mixin for database-specific security."""

    def tenant_isolation(
        self,
        tenant_header: str = "X-Tenant-ID",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Ensure proper tenant isolation."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            async def tenant_validator(request: Request) -> Response | None:
                tenant_id = request.headers.get(tenant_header)
                user_tenant = request.headers.get("X-User-Tenant")

                if not tenant_id or tenant_id != user_tenant:
                    return Response("Tenant mismatch", status_code=403)
                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(tenant_validator)
            return self._apply_route_config(func)

        return decorator

    def read_only_mode(
        self,
        maintenance_header: str = "X-Maintenance-Mode",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Block write operations during maintenance."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            async def maintenance_validator(request: Request) -> Response | None:
                if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
                    maintenance = request.headers.get(maintenance_header)
                    if maintenance == "read-only":
                        return Response(
                            "System in read-only mode",
                            status_code=503,
                        )
                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(maintenance_validator)
            return self._apply_route_config(func)

        return decorator


# Create custom SecurityDecorator with additional mixins
class CustomSecurityDecorator(
    SecurityDecorator,  # Inherit all existing functionality
    CustomBusinessLogicMixin,  # Add business logic decorators
    DatabaseSecurityMixin,  # Add database security decorators
):
    """
    Extended SecurityDecorator with custom business and database security features.

    This shows how users can easily extend the decorator system by creating
    their own mixins and combining them with the base SecurityDecorator.
    """

    def __init__(self, config: SecurityConfig, **custom_settings: Any) -> None:
        super().__init__(config)
        # Add any custom initialization here
        self.custom_settings = custom_settings


# Usage example
app = FastAPI()
config = SecurityConfig()
guard = CustomSecurityDecorator(config)


@app.get("/api/premium-feature")
@guard.require_subscription("premium")
@guard.rate_limit(requests=100, window=3600)
def premium_endpoint() -> dict[str, str]:
    """Endpoint that requires premium subscription."""
    return {"message": "Premium feature accessed"}


@app.get("/api/beta-feature")
@guard.feature_flag("new_algorithm")
@guard.ab_test_group("algorithm_test", ["group_a", "group_b"])
def beta_endpoint() -> dict[str, str]:
    """Endpoint behind feature flag and A/B test."""
    return {"message": "Beta feature accessed"}


@app.get("/api/tenant/{tenant_id}/data")
@guard.tenant_isolation()
@guard.block_countries(["CN", "RU"])
def tenant_data_endpoint(tenant_id: str) -> dict[str, str]:
    """Multi-tenant endpoint with isolation."""
    return {"tenant": tenant_id, "data": "sensitive"}


@app.post("/api/admin/update")
@guard.read_only_mode()
@guard.require_ip(whitelist=["10.0.0.0/8"])
def admin_update_endpoint() -> dict[str, str]:
    """Admin endpoint that respects maintenance mode."""
    return {"message": "Update completed"}


if __name__ == "__main__":
    print("Custom decorator examples loaded!")
    print("Available custom decorators:")
    print("- @guard.require_subscription(tier)")
    print("- @guard.feature_flag(flag_name)")
    print("- @guard.ab_test_group(test_name, allowed_groups)")
    print("- @guard.tenant_isolation(tenant_header)")
    print("- @guard.read_only_mode(maintenance_header)")
