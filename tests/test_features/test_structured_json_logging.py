import json
import logging

import pytest

from guard.utils import JsonFormatter, setup_custom_logging


def test_text_format_default() -> None:
    logger = setup_custom_logging(log_format="text")
    handler = logger.handlers[0]
    assert not isinstance(handler.formatter, JsonFormatter)


def test_json_format_produces_valid_json(
    capfd: pytest.CaptureFixture[str],
) -> None:
    logger = setup_custom_logging(log_format="json")
    logger.info("test message")

    captured = capfd.readouterr()
    parsed = json.loads(captured.err.strip())

    assert parsed["level"] == "INFO"
    assert parsed["message"] == "test message"
    assert parsed["logger"] == "fastapi_guard"
    assert "timestamp" in parsed


def test_json_format_fields_are_correct() -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.WARNING,
        pathname="test.py",
        lineno=1,
        msg="warning message",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed["level"] == "WARNING"
    assert parsed["logger"] == "test_logger"
    assert parsed["message"] == "warning message"
    assert "timestamp" in parsed


def test_json_format_with_file_handler(tmp_path: pytest.TempPathFactory) -> None:
    log_file = str(tmp_path / "test.log")
    logger = setup_custom_logging(log_file=log_file, log_format="json")
    logger.info("file test")

    with open(log_file) as f:
        line = f.readline().strip()
    parsed = json.loads(line)
    assert parsed["message"] == "file test"
    assert parsed["level"] == "INFO"


def test_text_format_not_json() -> None:
    formatter = logging.Formatter(
        "[%(name)s] %(asctime)s - %(levelname)s - %(message)s"
    )
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    output = formatter.format(record)
    with pytest.raises(json.JSONDecodeError):
        json.loads(output)


def test_config_log_format_default() -> None:
    from guard.models import SecurityConfig

    config = SecurityConfig(enable_redis=False)
    assert config.log_format == "text"


def test_config_log_format_json() -> None:
    from guard.models import SecurityConfig

    config = SecurityConfig(enable_redis=False, log_format="json")
    assert config.log_format == "json"
