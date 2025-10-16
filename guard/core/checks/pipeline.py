# guard/middleware/checks/pipeline.py
import logging

from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck


class SecurityCheckPipeline:
    """
    Pipeline for executing security checks in sequence.

    Implements the Chain of Responsibility pattern where each check
    can either block the request or pass it to the next check.
    """

    def __init__(self, checks: list[SecurityCheck]) -> None:
        """
        Initialize the pipeline with a list of security checks.

        Args:
            checks: Ordered list of SecurityCheck instances to execute.
        """
        self.checks = checks
        self.logger = logging.getLogger(__name__)

    async def execute(self, request: Request) -> Response | None:
        """
        Execute all security checks in sequence.

        Checks are executed in order. If any check returns a Response,
        the pipeline stops and returns that Response (blocking the request).
        If all checks pass (return None), the pipeline returns None to
        allow the request to proceed.

        Args:
            request: The incoming FastAPI request.

        Returns:
            Response if any check blocks the request, None if all pass.
        """
        for check in self.checks:
            try:
                response = await check.check(request)
                if response is not None:
                    # Check failed and returned a blocking response
                    self.logger.info(
                        f"Request blocked by {check.check_name}",
                        extra={
                            "check": check.check_name,
                            "path": request.url.path,
                            "method": request.method,
                        },
                    )
                    return response

            except Exception as e:
                # Log error but don't let check failures break the pipeline
                self.logger.error(
                    f"Error in security check {check.check_name}: {e}",
                    extra={
                        "check": check.check_name,
                        "path": request.url.path,
                        "method": request.method,
                    },
                    exc_info=True,
                )

                # Fail-secure: if check errors and fail_secure is enabled, block
                if hasattr(check.config, "fail_secure") and check.config.fail_secure:
                    self.logger.warning(
                        f"Blocking request due to check error in fail-secure mode: {check.check_name}"  # noqa: E501
                    )
                    return await check.create_error_response(
                        status_code=500,
                        default_message="Security check failed",
                    )

                # Otherwise, continue to next check (fail-open)
                continue

        # All checks passed
        return None

    def add_check(self, check: SecurityCheck) -> None:
        """
        Add a check to the end of the pipeline.

        Args:
            check: SecurityCheck instance to add.
        """
        self.checks.append(check)

    def insert_check(self, index: int, check: SecurityCheck) -> None:
        """
        Insert a check at a specific position in the pipeline.

        Args:
            index: Position to insert the check.
            check: SecurityCheck instance to insert.
        """
        self.checks.insert(index, check)

    def remove_check(self, check_name: str) -> bool:
        """
        Remove a check from the pipeline by name.

        Args:
            check_name: Name of the check to remove.

        Returns:
            True if check was found and removed, False otherwise.
        """
        for i, check in enumerate(self.checks):
            if check.check_name == check_name:
                self.checks.pop(i)
                return True
        return False

    def get_check_names(self) -> list[str]:
        """
        Get the names of all checks in the pipeline.

        Returns:
            List of check names in execution order.
        """
        return [check.check_name for check in self.checks]

    def __len__(self) -> int:
        """Return the number of checks in the pipeline."""
        return len(self.checks)

    def __repr__(self) -> str:
        """Return string representation of the pipeline."""
        check_names = ", ".join(self.get_check_names())
        return f"SecurityCheckPipeline({len(self.checks)} checks: {check_names})"
