"""Security headers handler for FastAPI applications."""
from collections.abc import Awaitable, Callable
from typing import Any, Dict, List, Optional

from starlette.types import ASGIApp, Receive, Scope, Send


class SecurityHeadersMiddleware:
    """
    Middleware for adding security-related HTTP headers to responses.

    This middleware adds various security headers to help protect against common
    web vulnerabilities such as XSS, clickjacking, and MIME-type sniffing.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        csp: Optional[Dict[str, List[str]]] = None,
        hsts_max_age: int = 63072000,  # 2 years in seconds
        frame_options: str = "SAMEORIGIN",
        content_type_options: str = "nosniff",
        xss_protection: str = "1; mode=block",
        referrer_policy: str = "strict-origin-when-cross-origin",
        permissions_policy: Optional[Dict[str, List[str]]] = None,
        cross_origin_opener_policy: str = "same-origin",
        cross_origin_resource_policy: str = "same-origin",
        cross_origin_embedder_policy: str = "require-corp",
    ) -> None:
        """Initialize the SecurityHeadersMiddleware.

        Args:
            app: The ASGI application to wrap.
            csp: Content Security Policy directives.
            hsts_max_age: Max age for HSTS header in seconds.
            frame_options: Value for X-Frame-Options header.
            content_type_options: Value for X-Content-Type-Options header.
            xss_protection: Value for X-XSS-Protection header.
            referrer_policy: Value for Referrer-Policy header.
            permissions_policy: Permissions Policy directives.
            cross_origin_opener_policy: Value for Cross-Origin-Opener-Policy header.
            cross_origin_resource_policy: Value for Cross-Origin-Resource-Policy header.
            cross_origin_embedder_policy: Value for Cross-Origin-Embedder-Policy header.
        """
        self.app = app
        self.headers: List[tuple[bytes, bytes]] = []
        
        # Content Security Policy
        if csp:
            csp_value = self._build_csp(csp)
            self.headers.append((b"content-security-policy", csp_value.encode()))
        
        # HTTP Strict Transport Security
        self.headers.append((
            b"strict-transport-security",
            f"max-age={hsts_max_age}; includeSubDomains".encode(),
        ))
        
        # X-Frame-Options
        self.headers.append((b"x-frame-options", frame_options.encode()))
        
        # X-Content-Type-Options
        self.headers.append((b"x-content-type-options", content_type_options.encode()))
        
        # X-XSS-Protection
        self.headers.append((b"x-xss-protection", xss_protection.encode()))
        
        # Referrer-Policy
        self.headers.append((b"referrer-policy", referrer_policy.encode()))
        
        # Permissions Policy (formerly Feature Policy)
        if permissions_policy:
            policy_value = self._build_permissions_policy(permissions_policy)
            self.headers.append((b"permissions-policy", policy_value.encode()))
        
        # Cross-Origin-Opener-Policy
        self.headers.append((
            b"cross-origin-opener-policy", 
            cross_origin_opener_policy.encode()
        ))
        
        # Cross-Origin-Resource-Policy
        self.headers.append((
            b"cross-origin-resource-policy", 
            cross_origin_resource_policy.encode()
        ))
        
        # Cross-Origin-Embedder-Policy
        self.headers.append((
            b"cross-origin-embedder-policy", 
            cross_origin_embedder_policy.encode()
        ))
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # pragma: no cover
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                # Add our security headers
                for name, value in self.headers:
                    headers[name] = value
                message["headers"] = list(headers.items())
            await send(message)

        await self.app(scope, receive, send_with_headers)
    
    def _build_csp(self, csp: Dict[str, List[str]]) -> str:
        """Build Content-Security-Policy header value from directives.
        
        Args:
            csp: Dictionary of CSP directives and their values.
            
        Returns:
            Formatted CSP header value.
        """
        return "; ".join(
            f"{directive} {' '.join(sources)}"
            for directive, sources in csp.items()
        )
    
    def _build_permissions_policy(self, policy: Dict[str, List[str]]) -> str:
        """Build Permissions-Policy header value from features.
        
        Args:
            policy: Dictionary of feature policies and their allowed origins.
            
        Returns:
            Formatted Permissions-Policy header value.
        """
        def format_values(values):
            # Treat any form of 'none' (with or without quotes/case) or [] as disabled
            if not values or (len(values) == 1 and values[0].strip("'\" ").lower() == "none"):
                return "()"
            return f"({' '.join(values)})"
        return ", ".join(
            f"{feature}={format_values(values)}"
            for feature, values in policy.items()
        )
