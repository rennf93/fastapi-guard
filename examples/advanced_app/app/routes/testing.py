from fastapi import APIRouter, Body, Query

from app.models import MessageResponse, TestPayload

router = APIRouter(prefix="/test", tags=["Security Testing"])


@router.post("/xss-test", response_model=MessageResponse)
async def test_xss_detection(
    payload: str = Body(..., description="XSS test payload"),
) -> MessageResponse:
    return MessageResponse(
        message="XSS test payload processed",
        details={"payload": payload, "detected": False},
    )


@router.post("/sql-injection", response_model=MessageResponse)
async def test_sql_injection(
    query: str = Query(..., description="SQL injection test"),
) -> MessageResponse:
    return MessageResponse(
        message="SQL injection test processed",
        details={"query": query, "detected": False},
    )


@router.get("/path-traversal/{file_path:path}")
async def test_path_traversal(file_path: str) -> MessageResponse:
    return MessageResponse(
        message="Path traversal test",
        details={"path": file_path, "detected": False},
    )


@router.post("/command-injection", response_model=MessageResponse)
async def test_command_injection(
    command: str = Body(..., description="Command injection test"),
) -> MessageResponse:
    return MessageResponse(
        message="Command injection test processed",
        details={"command": command, "detected": False},
    )


@router.post("/mixed-attack", response_model=MessageResponse)
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
