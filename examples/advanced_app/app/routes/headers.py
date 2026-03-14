import logging

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from app.models import CSPReportRequest, MessageResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/headers", tags=["Security Headers"])


@router.get(
    "/",
    response_model=MessageResponse,
    status_code=200,
    summary="Security Headers Overview",
    description=(
        "Lists all security headers applied to responses by the middleware, including"
        "HSTS, CSP, X-Frame-Options, and custom headers."
    ),
)
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


@router.get(
    "/test-page",
    response_class=HTMLResponse,
    status_code=200,
    summary="CSP Test Page",
    description=(
        "Serves an HTML page that tests Content Security Policy enforcement. Includes"
        "inline scripts and styles to verify CSP restrictions are applied correctly."
    ),
)
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


@router.post(
    "/csp-report",
    response_model=MessageResponse,
    status_code=200,
    summary="CSP Violation Report Receiver",
    description=(
        "Receives Content Security Policy violation reports sent by browsers. Logs the"
        "violated directive, blocked URI, and source file for security monitoring."
    ),
)
async def receive_csp_report(report: CSPReportRequest) -> MessageResponse:
    violation = report.csp_report
    logger.warning(
        f"CSP Violation: {violation.violated_directive or 'unknown'} "
        f"blocked {violation.blocked_uri or 'unknown'} "
        f"on {violation.document_uri or 'unknown'}"
    )
    return MessageResponse(
        message="CSP violation report received",
        details={
            "violated_directive": violation.violated_directive,
            "blocked_uri": violation.blocked_uri,
            "source_file": violation.source_file,
            "line_number": violation.line_number,
        },
    )


@router.get(
    "/frame-test",
    response_class=HTMLResponse,
    status_code=200,
    summary="X-Frame-Options Test Page",
    description=(
        "Serves an HTML page with X-Frame-Options: SAMEORIGIN header. Can be embedded"
        " in"
        "iframes from the same origin but not from external sites."
    ),
)
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


@router.get(
    "/hsts-info",
    response_model=MessageResponse,
    status_code=200,
    summary="HSTS Information",
    description=(
        "Returns the current HSTS (HTTP Strict Transport Security) configuration"
        "including max-age, includeSubDomains, and preload status."
    ),
)
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


@router.get(
    "/security-analysis",
    response_model=MessageResponse,
    status_code=200,
    summary="Request Security Analysis",
    description=(
        "Analyzes the current request's security-relevant headers and returns a summary"
        "of applied security features with recommendations."
    ),
)
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
