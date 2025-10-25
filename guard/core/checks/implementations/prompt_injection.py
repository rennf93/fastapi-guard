# guard/core/checks/implementations/prompt_injection.py
import json
from typing import TYPE_CHECKING

from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck
from guard.core.prompt_injection import PromptGuard, PromptInjectionAttempt

if TYPE_CHECKING:
    from guard.middleware import SecurityMiddleware


class PromptInjectionCheck(SecurityCheck):
    """
    Security check for prompt injection defense.

    Analyzes request bodies for potential prompt injection attempts
    and sanitizes inputs for LLM consumption.
    """

    def __init__(self, middleware: "SecurityMiddleware") -> None:
        """
        Initialize the prompt injection check.

        Args:
            middleware: Parent SecurityMiddleware instance.
        """
        super().__init__(middleware)

        # Initialize PromptGuard if enabled
        self.prompt_guard: PromptGuard | None = None
        if self.config.enable_prompt_injection_defense:
            self.prompt_guard = PromptGuard(
                protection_level=self.config.prompt_injection_protection_level,
                format_strategy=self.config.prompt_injection_format_strategy,
                pattern_sensitivity=self.config.prompt_injection_pattern_sensitivity,
                custom_patterns=self.config.prompt_injection_custom_patterns,
                enable_canary=self.config.prompt_injection_enable_canary,
                redis_manager=(
                    self.middleware.redis_handler
                    if self.config.enable_redis
                    else None
                ),
                use_redis_for_canaries=(
                    self.config.prompt_injection_store_canaries_redis
                ),
            )

    @property
    def check_name(self) -> str:
        """Return the name of this security check."""
        return "prompt_injection"

    async def check(self, request: Request) -> Response | None:
        """
        Check request for prompt injection attempts.

        Args:
            request: The incoming FastAPI request.

        Returns:
            Response if injection detected and request should be blocked.
            None if check passes or defense is not enabled.
        """
        # Skip if prompt injection defense is not enabled
        if not self.config.enable_prompt_injection_defense or not self.prompt_guard:
            return None

        # Only check POST/PUT/PATCH requests with body content
        if request.method not in ("POST", "PUT", "PATCH"):
            return None

        # Get request body for analysis
        body = await self._get_request_body(request)
        if not body:
            return None

        # Extract text content from request body
        text_content = self._extract_text_content(body)
        if not text_content:
            return None

        # Check for prompt injection
        try:
            # Get session ID from request if available
            session_id = self._get_session_id(request)

            # Protect input (will raise exception if injection detected)
            sanitized = self.prompt_guard.protect_input(text_content, session_id)

            # Store sanitized input in request state for LLM handler
            request.state.prompt_guard_sanitized = sanitized
            request.state.prompt_guard_session_id = session_id

            # If canary is enabled, store system prompt helper
            if self.prompt_guard.enable_canary:
                request.state.prompt_guard_inject_canary = (
                    self.prompt_guard.inject_system_canary
                )
                request.state.prompt_guard_verify_output = (
                    self.prompt_guard.verify_output
                )

            return None  # Check passed

        except PromptInjectionAttempt as e:
            # Log the attempt
            client_host = request.client.host if request.client else "unknown"
            self.logger.warning(
                f"Prompt injection attempt detected from {client_host}: "
                f"{str(e)} - Patterns: {e.matched_patterns}"
            )

            # Send security event
            await self.send_event(
                event_type="prompt_injection_attempt",
                request=request,
                action_taken="blocked",
                reason=f"Prompt injection patterns detected: {e.matched_patterns}",
                matched_patterns=e.matched_patterns,
            )

            # Return error response
            return await self.create_error_response(
                403,
                "Request blocked: Suspicious input patterns detected",
            )

    async def _get_request_body(self, request: Request) -> dict[str, str] | str | None:
        """
        Extract and parse request body.

        Args:
            request: FastAPI request.

        Returns:
            Parsed request body as dict/str, or None if empty/invalid.
        """
        try:
            # Read raw body
            body_bytes = await request.body()
            if not body_bytes:
                return None

            # Try to parse as JSON
            try:
                parsed: dict[str, str] = json.loads(body_bytes)
                return parsed
            except json.JSONDecodeError:
                # Return as string if not JSON
                return body_bytes.decode("utf-8", errors="ignore")

        except Exception:
            return None

    def _extract_text_content(self, body: dict[str, str] | str) -> str:
        """
        Extract text content from request body for analysis.

        Args:
            body: Parsed request body.

        Returns:
            Concatenated text content from the body.
        """
        if isinstance(body, str):
            return body

        if isinstance(body, dict):
            # Extract common fields that might contain prompts
            text_fields = [
                "prompt",
                "message",
                "content",
                "text",
                "query",
                "input",
                "instruction",
            ]

            texts = []
            for field in text_fields:
                if field in body and isinstance(body[field], str):
                    texts.append(body[field])

            # Also check nested structures
            for value in body.values():
                if isinstance(value, str):
                    texts.append(value)

            return " ".join(texts)

        return ""  # type: ignore[unreachable]

    def _get_session_id(self, request: Request) -> str | None:
        """
        Extract session ID from request if available.

        Args:
            request: FastAPI request.

        Returns:
            Session ID or None.
        """
        # Try to get from headers
        session_id = request.headers.get("X-Session-ID")
        if session_id:
            return session_id

        # Try to get from cookies
        session_id = request.cookies.get("session_id")
        if session_id:
            return session_id

        # Try to get from client host as fallback
        if request.client:
            return request.client.host

        return None
