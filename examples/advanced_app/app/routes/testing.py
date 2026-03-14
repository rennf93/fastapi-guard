from fastapi import APIRouter, Body, Query

from app.models import MessageResponse, TestPayload

router = APIRouter(prefix="/test", tags=["Security Testing"])


@router.post(
    "/xss-test",
    response_model=MessageResponse,
    status_code=200,
    summary="XSS Detection Test",
    description=(
        "Submit a payload to test cross-site scripting (XSS) detection. The middleware"
        "inspects the payload for script tags, event handlers, and other XSS vectors."
    ),
    responses={403: {"description": "XSS pattern detected by middleware"}},
)
async def test_xss_detection(
    payload: str = Body(...),
) -> MessageResponse:
    return MessageResponse(
        message="XSS test payload processed",
        details={"payload": payload, "detected": False},
    )


@router.post(
    "/sql-injection",
    response_model=MessageResponse,
    status_code=200,
    summary="SQL Injection Detection Test",
    description=(
        "Submit a query to test SQL injection detection. The middleware scans for UNION"
        "SELECT, OR 1=1, DROP TABLE, and other SQL injection signatures."
    ),
    responses={403: {"description": "SQL injection pattern detected by middleware"}},
)
async def test_sql_injection(
    query: str = Query(...),
) -> MessageResponse:
    return MessageResponse(
        message="SQL injection test processed",
        details={"query": query, "detected": False},
    )


@router.get(
    "/path-traversal/{file_path:path}",
    response_model=MessageResponse,
    status_code=200,
    summary="Path Traversal Detection Test",
    description=(
        "Submit a file path to test path traversal detection. The middleware detects"
        " ../"
        "sequences, /etc/passwd probes, and other directory traversal patterns."
    ),
    responses={403: {"description": "Path traversal pattern detected by middleware"}},
)
async def test_path_traversal(file_path: str) -> MessageResponse:
    return MessageResponse(
        message="Path traversal test",
        details={"path": file_path, "detected": False},
    )


@router.post(
    "/command-injection",
    response_model=MessageResponse,
    status_code=200,
    summary="Command Injection Detection Test",
    description=(
        "Submit a command string to test OS command injection detection. The middleware"
        "detects shell metacharacters, pipe chains, and known command patterns."
    ),
    responses={
        403: {"description": "Command injection pattern detected by middleware"}
    },
)
async def test_command_injection(
    command: str = Body(...),
) -> MessageResponse:
    return MessageResponse(
        message="Command injection test processed",
        details={"command": command, "detected": False},
    )


@router.post(
    "/mixed-attack",
    response_model=MessageResponse,
    status_code=200,
    summary="Mixed Attack Vector Test",
    description=(
        "Submit a payload combining multiple attack vectors (XSS, SQL injection, path"
        "traversal, command injection, honeypot) to test the detection engine's ability"
        "to identify compound threats."
    ),
    responses={403: {"description": "Attack pattern detected by middleware"}},
)
async def test_mixed_attack(payload: TestPayload) -> MessageResponse:
    return MessageResponse(
        message="Mixed attack test processed",
        details={
            "xss_test": payload.input,
            "sql_test": payload.query,
            "path_test": payload.path,
            "cmd_test": payload.cmd,
            "honeypot": payload.honeypot_field,
        },
    )
