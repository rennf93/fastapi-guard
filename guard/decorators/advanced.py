# guard/decorators/advanced.py
from collections.abc import Callable
from typing import Any

from fastapi import Request, Response

from guard.decorators.base import BaseSecurityMixin


class AdvancedMixin(BaseSecurityMixin):
    """Mixin for advanced detection decorators."""

    def time_window(
        self, start_time: str, end_time: str, timezone: str = "UTC"
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Restrict access to specific time windows.

        Args:
            start_time: Start time in HH:MM format
            end_time: End time in HH:MM format
            timezone: Timezone (default: UTC)

        Example:
            # NOTE: Business hours only
            @guard_decorator.time_window("09:00", "17:00", "UTC")
            def business_api():
                return {"message": "business hours only"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.time_restrictions = {
                "start": start_time,
                "end": end_time,
                "timezone": timezone,
            }
            return self._apply_route_config(func)

        return decorator

    def suspicious_detection(
        self, enabled: bool = True
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Enable/disable suspicious pattern detection (leverages sus_patterns_handler).

        Args:
            enabled: Whether to enable suspicious pattern detection

        Example:
            # NOTE: Disable for this endpoint
            @guard_decorator.suspicious_detection(enabled=False)
            def upload_endpoint():
                return {"status": "upload safe"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            route_config = self._ensure_route_config(func)
            route_config.enable_suspicious_detection = enabled
            return self._apply_route_config(func)

        return decorator

    def honeypot_detection(
        self, trap_fields: list[str]
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Detect bots using honeypot fields that humans shouldn't fill.

        Args:
            trap_fields: List of field names that should remain empty

        Example:
            @guard_decorator.honeypot_detection(["bot_trap", "hidden_field"])
            def form_endpoint():
                return {"message": "human verified"}
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            async def honeypot_validator(request: Request) -> Response | None:
                """Main validator that checks for honeypot trap fields."""

                def _has_trap_field_filled(data: dict[str, Any]) -> bool:
                    """Check if any trap field is filled in the data."""
                    return any(field in data and data[field] for field in trap_fields)

                async def _validate_form_data() -> Response | None:
                    """Validate honeypot fields in form data."""
                    try:
                        form = await request.form()
                        if _has_trap_field_filled(dict(form)):
                            return Response("Forbidden", status_code=403)
                    except Exception:
                        pass
                    return None

                async def _validate_json_data() -> Response | None:
                    """Validate honeypot fields in JSON data."""
                    try:
                        json_data = await request.json()
                        if _has_trap_field_filled(json_data):
                            return Response("Forbidden", status_code=403)
                    except Exception:
                        pass
                    return None

                if request.method not in ["POST", "PUT", "PATCH"]:
                    return None

                content_type = request.headers.get("content-type", "")

                if "application/x-www-form-urlencoded" in content_type:
                    return await _validate_form_data()
                elif "application/json" in content_type:
                    return await _validate_json_data()

                return None

            route_config = self._ensure_route_config(func)
            route_config.custom_validators.append(honeypot_validator)
            return self._apply_route_config(func)

        return decorator
