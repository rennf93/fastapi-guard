import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.models import MessageResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/headers", tags=["Security Headers"])


@router.get("/", response_model=MessageResponse)
async def security_headers_info() -> MessageResponse:
    return MessageResponse(
        message="All responses include comprehensive security headers",
        details={
            "headers": [
                "X-Content-Type-Options: nosniff",
                "X-Frame-Options: SAMEORIGIN",
                "X-XSS-Protection: 1; mode=block",
                "Strict-Transport-Security: max-age=31536000",
                "Content-Security-Policy: default-src 'self'",
                "Referrer-Policy: strict-origin-when-cross-origin",
                "Permissions-Policy: accelerometer=(), camera=(), ...",
                "X-App-Name: FastAPI-Guard-Advanced-Example",
                "X-Security-Contact: security@example.com",
            ],
            "note": "Check browser developer tools to see all headers",
        },
    )


@router.get("/test-page", response_class=HTMLResponse)
async def security_headers_test_page() -> str:
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Headers Demo</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .header { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
            .demo-box { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .warning { color: #d63384; font-weight: bold; }
            .success { color: #198754; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1 class="header">FastAPI Guard Security Headers Demo</h1>
        <div class="demo-box">
            <h2>Content Security Policy Test</h2>
            <p>This page tests various CSP restrictions:</p>
            <ul>
                <li><strong>Inline Styles:</strong> <span id="style-test">Should be styled</span></li>
                <li><strong>Inline Scripts:</strong> <span id="script-test">Waiting for script...</span></li>
                <li><strong>External Resources:</strong> Limited by CSP directives</li>
            </ul>
        </div>
        <div class="demo-box">
            <h2>Security Headers Applied</h2>
            <p>Check the <strong>Network</strong> tab in Developer Tools to see all applied headers.</p>
        </div>
        <script>
            document.getElementById('script-test').textContent = 'Script executed successfully!';
            document.getElementById('script-test').className = 'success';
        </script>
    </body>
    </html>
    """  # noqa: E501


@router.post("/csp-report", response_model=MessageResponse)
async def receive_csp_report(report: dict[str, Any]) -> MessageResponse:
    violation = report.get("csp-report", {})
    logger.warning(
        f"CSP Violation: {violation.get('violated-directive', 'unknown')} "
        f"blocked {violation.get('blocked-uri', 'unknown')} "
        f"on {violation.get('document-uri', 'unknown')}"
    )
    return MessageResponse(
        message="CSP violation report received",
        details={
            "violated_directive": violation.get("violated-directive"),
            "blocked_uri": violation.get("blocked-uri"),
            "source_file": violation.get("source-file"),
            "line_number": violation.get("line-number"),
        },
    )


@router.get("/frame-test", response_class=HTMLResponse)
async def frame_test() -> str:
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Frame Options Test</title></head>
    <body>
        <h1>X-Frame-Options Test</h1>
        <p>This page has X-Frame-Options: SAMEORIGIN header.</p>
        <p>It can be embedded in iframes from the same origin, but not from external sites.</p>
    </body>
    </html>
    """  # noqa: E501


@router.get("/hsts-info", response_model=MessageResponse)
async def hsts_info() -> MessageResponse:
    return MessageResponse(
        message="HSTS (HTTP Strict Transport Security) is active",
        details={
            "max_age": "31536000 seconds (1 year)",
            "include_subdomains": True,
            "preload": False,
            "description": "Forces HTTPS connections for improved security",
            "note": "In production, enable preload and submit to HSTS preload list",
        },
    )


@router.get("/security-analysis", response_model=MessageResponse)
async def security_analysis(request: Request) -> MessageResponse:
    return MessageResponse(
        message="Security analysis of current request",
        details={
            "request_headers": {
                "user_agent": request.headers.get("user-agent", "Not provided"),
                "origin": request.headers.get("origin", "Not provided"),
                "referer": request.headers.get("referer", "Not provided"),
                "x_forwarded_for": request.headers.get(
                    "x-forwarded-for", "Not provided"
                ),
            },
            "security_features": [
                "Content-Type sniffing protection (X-Content-Type-Options)",
                "Clickjacking protection (X-Frame-Options)",
                "XSS filtering (X-XSS-Protection)",
                "HTTPS enforcement (Strict-Transport-Security)",
                "Content restrictions (Content-Security-Policy)",
                "Referrer policy control",
                "Feature permissions control",
                "Custom security headers",
            ],
            "recommendations": [
                "Always use HTTPS in production",
                "Regularly review and tighten CSP directives",
                "Monitor CSP violation reports",
                "Consider HSTS preload for production domains",
                "Test security headers with online tools",
            ],
        },
    )
