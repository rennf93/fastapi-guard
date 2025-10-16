from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import Request, Response

from guard.core.checks.base import SecurityCheck
from guard.core.checks.pipeline import SecurityCheckPipeline


class MockCheck(SecurityCheck):
    """Mock security check for testing."""

    def __init__(self, middleware: Mock, name: str, should_block: bool = False) -> None:
        super().__init__(middleware)
        self._name = name
        self._should_block = should_block

    @property
    def check_name(self) -> str:
        return self._name

    async def check(self, request: Request) -> Response | None:
        if self._should_block:
            return Response(content="Blocked", status_code=403)
        return None


class FailingCheck(SecurityCheck):
    """Check that raises an exception."""

    def __init__(self, middleware: Mock, name: str = "failing_check") -> None:
        super().__init__(middleware)
        self._name = name

    @property
    def check_name(self) -> str:
        return self._name

    async def check(self, request: Request) -> Response | None:
        raise ValueError("Check error")


@pytest.fixture
def mock_middleware() -> Mock:
    """Create a mock middleware instance."""
    middleware = Mock()
    # Use Mock for config to allow arbitrary attributes
    middleware.config = Mock()
    middleware.config.fail_secure = False  # Default to fail-open
    middleware.config.passive_mode = False
    middleware.logger = Mock()
    middleware.event_bus = Mock()
    middleware.create_error_response = AsyncMock(
        return_value=Response(content="Error", status_code=500)
    )
    return middleware


@pytest.fixture
def mock_request() -> Mock:
    """Create a mock request."""
    request = Mock(spec=Request)
    request.url = Mock()
    request.url.path = "/test"
    request.method = "GET"
    return request


class TestSecurityCheckPipeline:
    """Test SecurityCheckPipeline class."""

    def test_pipeline_initialization(self, mock_middleware: Mock) -> None:
        """Test pipeline initialization with checks."""
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])

        assert len(pipeline) == 2
        assert pipeline.get_check_names() == ["check1", "check2"]

    @pytest.mark.asyncio
    async def test_execute_all_checks_pass(
        self, mock_middleware: Mock, mock_request: Mock
    ) -> None:
        """Test pipeline execution when all checks pass."""
        check1 = MockCheck(mock_middleware, "check1", should_block=False)
        check2 = MockCheck(mock_middleware, "check2", should_block=False)

        pipeline = SecurityCheckPipeline([check1, check2])
        result = await pipeline.execute(mock_request)

        assert result is None

    @pytest.mark.asyncio
    async def test_execute_first_check_blocks(
        self, mock_middleware: Mock, mock_request: Mock
    ) -> None:
        """Test pipeline stops when first check blocks."""
        check1 = MockCheck(mock_middleware, "check1", should_block=True)
        check2 = MockCheck(mock_middleware, "check2", should_block=False)

        pipeline = SecurityCheckPipeline([check1, check2])
        result = await pipeline.execute(mock_request)

        assert result is not None
        assert result.status_code == 403

    @pytest.mark.asyncio
    async def test_execute_second_check_blocks(
        self, mock_middleware: Mock, mock_request: Mock
    ) -> None:
        """Test pipeline continues until second check blocks."""
        check1 = MockCheck(mock_middleware, "check1", should_block=False)
        check2 = MockCheck(mock_middleware, "check2", should_block=True)

        pipeline = SecurityCheckPipeline([check1, check2])
        result = await pipeline.execute(mock_request)

        assert result is not None
        assert result.status_code == 403

    @pytest.mark.asyncio
    async def test_execute_with_exception_fail_open(
        self, mock_middleware: Mock, mock_request: Mock
    ) -> None:
        """Test exception handling with fail-open (default)."""
        failing_check = FailingCheck(mock_middleware, "failing_check")
        passing_check = MockCheck(mock_middleware, "passing_check", should_block=False)

        # Ensure fail_secure is False (fail-open)
        mock_middleware.config.fail_secure = False

        pipeline = SecurityCheckPipeline([failing_check, passing_check])
        result = await pipeline.execute(mock_request)

        # Should continue after exception (fail-open)
        assert result is None

    @pytest.mark.asyncio
    async def test_execute_with_exception_fail_secure(
        self, mock_middleware: Mock, mock_request: Mock
    ) -> None:
        """Test exception handling with fail-secure mode."""
        failing_check = FailingCheck(mock_middleware, "failing_check")
        passing_check = MockCheck(mock_middleware, "passing_check", should_block=False)

        # Enable fail_secure mode
        mock_middleware.config.fail_secure = True

        pipeline = SecurityCheckPipeline([failing_check, passing_check])
        result = await pipeline.execute(mock_request)

        # Should block due to fail-secure
        assert result is not None
        assert result.status_code == 500

    @pytest.mark.asyncio
    async def test_execute_with_exception_no_fail_secure_attr(
        self, mock_middleware: Mock, mock_request: Mock
    ) -> None:
        """Test exception handling when fail_secure attribute doesn't exist."""
        failing_check = FailingCheck(mock_middleware, "failing_check")

        # Remove fail_secure attribute
        if hasattr(mock_middleware.config, "fail_secure"):
            delattr(mock_middleware.config, "fail_secure")

        pipeline = SecurityCheckPipeline([failing_check])
        result = await pipeline.execute(mock_request)

        # Should fail-open when no fail_secure attribute
        assert result is None

    def test_add_check(self, mock_middleware: Mock) -> None:
        """Test adding a check to the pipeline."""
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")

        pipeline = SecurityCheckPipeline([check1])
        assert len(pipeline) == 1

        pipeline.add_check(check2)
        assert len(pipeline) == 2
        assert pipeline.get_check_names() == ["check1", "check2"]

    def test_insert_check(self, mock_middleware: Mock) -> None:
        """Test inserting a check at specific position."""
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")
        check3 = MockCheck(mock_middleware, "check3")

        pipeline = SecurityCheckPipeline([check1, check3])
        pipeline.insert_check(1, check2)

        assert len(pipeline) == 3
        assert pipeline.get_check_names() == ["check1", "check2", "check3"]

    def test_remove_check_found(self, mock_middleware: Mock) -> None:
        """Test removing a check by name when found."""
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")
        check3 = MockCheck(mock_middleware, "check3")

        pipeline = SecurityCheckPipeline([check1, check2, check3])
        result = pipeline.remove_check("check2")

        assert result is True
        assert len(pipeline) == 2
        assert pipeline.get_check_names() == ["check1", "check3"]

    def test_remove_check_not_found(self, mock_middleware: Mock) -> None:
        """Test removing a check by name when not found."""
        check1 = MockCheck(mock_middleware, "check1")

        pipeline = SecurityCheckPipeline([check1])
        result = pipeline.remove_check("nonexistent")

        assert result is False
        assert len(pipeline) == 1

    def test_get_check_names(self, mock_middleware: Mock) -> None:
        """Test getting list of check names."""
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])
        names = pipeline.get_check_names()

        assert names == ["check1", "check2"]

    def test_len(self, mock_middleware: Mock) -> None:
        """Test __len__ returns correct number of checks."""
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])

        assert len(pipeline) == 2

    def test_repr(self, mock_middleware: Mock) -> None:
        """Test __repr__ returns readable string representation."""
        check1 = MockCheck(mock_middleware, "check1")
        check2 = MockCheck(mock_middleware, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])
        repr_str = repr(pipeline)

        assert "SecurityCheckPipeline" in repr_str
        assert "2 checks" in repr_str
        assert "check1" in repr_str
        assert "check2" in repr_str

    @pytest.mark.parametrize(
        "checks,expected_count",
        [
            ([], 0),
            (["check1"], 1),
            (["check1", "check2"], 2),
            (["check1", "check2", "check3"], 3),
        ],
    )
    def test_pipeline_various_sizes(
        self, mock_middleware: Mock, checks: list[str], expected_count: int
    ) -> None:
        """Test pipeline with various numbers of checks."""
        check_objects: list[SecurityCheck] = [
            MockCheck(mock_middleware, name) for name in checks
        ]
        pipeline = SecurityCheckPipeline(check_objects)

        assert len(pipeline) == expected_count
        assert pipeline.get_check_names() == checks
