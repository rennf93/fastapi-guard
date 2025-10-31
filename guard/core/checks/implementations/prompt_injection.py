# guard/core/checks/implementations/prompt_injection.py
import json
from typing import TYPE_CHECKING

from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck
from guard.core.prompt_injection import PromptGuard, PromptInjectionAttempt
from guard.utils import log_activity

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
                redis_manager=(
                    self.middleware.redis_handler if self.config.enable_redis else None
                ),
                enable_canary=self.config.prompt_injection_enable_canary,
                use_redis_for_canaries=self.config.prompt_injection_store_canaries_redis,
                # Semantic matching
                semantic_fuzzy_threshold=self.config.prompt_injection_semantic_fuzzy_threshold,
                semantic_proximity_window=self.config.prompt_injection_semantic_proximity_window,
                semantic_enable_synonym=self.config.prompt_injection_semantic_enable_synonym,
                semantic_enable_fuzzy=self.config.prompt_injection_semantic_enable_fuzzy,
                semantic_enable_proximity=self.config.prompt_injection_semantic_enable_proximity,
                # Semantic detection
                enable_embedding_detection=self.config.prompt_injection_enable_embedding_detection,
                enable_transformer_detection=self.config.prompt_injection_enable_transformer_detection,
                embedding_model=self.config.prompt_injection_embedding_model,
                embedding_threshold=self.config.prompt_injection_embedding_threshold,
                transformer_model=self.config.prompt_injection_transformer_model,
                transformer_threshold=self.config.prompt_injection_transformer_threshold,
                # Statistical detection
                enable_statistical_detection=self.config.prompt_injection_enable_statistical_detection,
                statistical_entropy_weight=self.config.prompt_injection_statistical_entropy_weight,
                statistical_char_dist_weight=self.config.prompt_injection_statistical_char_dist_weight,
                statistical_complexity_weight=self.config.prompt_injection_statistical_complexity_weight,
                statistical_delimiter_weight=self.config.prompt_injection_statistical_delimiter_weight,
                # Context detection
                context_max_history=self.config.prompt_injection_context_max_history,
                # Injection scorer
                scorer_pattern_weight=self.config.prompt_injection_scorer_pattern_weight,
                scorer_statistical_weight=self.config.prompt_injection_scorer_statistical_weight,
                scorer_context_weight=self.config.prompt_injection_scorer_context_weight,
                scorer_detection_threshold=self.config.prompt_injection_scorer_detection_threshold,
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

            # Store system prompt helpers for LLM integration
            request.state.prompt_guard_get_system_instruction = (
                self.prompt_guard.get_system_instruction
            )
            request.state.prompt_guard_prepare_system_prompt = (
                self.prompt_guard.prepare_system_prompt
            )

            # Canary system
            if self.prompt_guard.enable_canary:
                request.state.prompt_guard_inject_canary = (
                    self.prompt_guard.inject_system_canary
                )
                request.state.prompt_guard_verify_output = (
                    self.prompt_guard.verify_output
                )

            return None  # Check passed

        except PromptInjectionAttempt as e:
            # Get client info
            client_ip = getattr(request.state, "client_ip", "unknown")
            detection_details = e.to_dict()

            # Log using standard log_activity helper (consistent with other checks)
            trigger_info = (
                f"Layer: {e.detection_layer}, "
                f"Score: {e.threat_score}, "
                f"Patterns: {e.matched_patterns}"
            )

            await log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"Prompt injection detected from {client_ip}",
                trigger_info=trigger_info,
                level=self.config.log_suspicious_level,
            )

            # Store detection info for LLM to explain rejection
            # Users can access this via: request.state.prompt_guard_detection_info
            request.state.prompt_guard_detection_info = detection_details

            # The LLM can use this to explain what triggered the block:
            # system_prompt = request.state.prompt_guard_prepare_system_prompt(
            #     base_prompt,
            #     detection_info=request.state.prompt_guard_detection_info
            # )

            # Send security event with full details (ready for guard-agent)
            await self.send_event(
                event_type="prompt_injection_attempt",
                request=request,
                action_taken="blocked",
                reason=str(e),
                matched_patterns=e.matched_patterns,
                detection_layer=e.detection_layer,
                threat_score=e.threat_score,
                detection_metadata=e.detection_metadata,
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
