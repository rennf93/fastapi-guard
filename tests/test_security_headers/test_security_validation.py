import threading
from collections.abc import AsyncGenerator

import pytest

from guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    reset_global_state,
)


@pytest.fixture(autouse=True)
async def cleanup() -> AsyncGenerator[None]:
    """Reset global state before each test."""
    await reset_global_state()
    yield
    await reset_global_state()


@pytest.mark.asyncio
async def test_header_value_with_newline_rejected() -> None:
    """Test that header values with newlines are rejected."""
    manager = SecurityHeadersManager()

    # Test with carriage return
    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(custom_headers={"X-Custom": "value\r\nX-Injected: evil"})

    # Test with line feed
    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(custom_headers={"X-Custom": "value\nX-Injected: evil"})


@pytest.mark.asyncio
async def test_header_value_too_long_rejected() -> None:
    """Test that excessively long header values are rejected."""
    manager = SecurityHeadersManager()

    # Exceed 8192 bytes
    long_value = "x" * 8193

    with pytest.raises(ValueError, match="Header value too long"):
        manager.configure(custom_headers={"X-Custom": long_value})


@pytest.mark.asyncio
async def test_control_characters_sanitized() -> None:
    """Test that control characters are removed from header values."""
    manager = SecurityHeadersManager()

    # Header with control characters (except tab)
    value_with_controls = "normal\x00\x01\x02\ttext\x1f"
    manager.configure(custom_headers={"X-Custom": value_with_controls})

    headers = await manager.get_headers()
    # Control chars removed except tab
    assert headers["X-Custom"] == "normal\ttext"


@pytest.mark.asyncio
async def test_standard_headers_validated() -> None:
    """Test that standard security headers are validated."""
    manager = SecurityHeadersManager()

    # Test X-Frame-Options validation
    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(frame_options="DENY\r\nX-Evil: true")

    # Test Referrer-Policy validation
    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(referrer_policy="no-referrer\nX-Evil: true")


@pytest.mark.asyncio
async def test_singleton_thread_safety() -> None:
    """Test that singleton is thread-safe under concurrent access."""
    instances = []
    barrier = threading.Barrier(10)

    def create_instance() -> None:
        barrier.wait()  # Synchronize thread start
        instance = SecurityHeadersManager()
        instances.append(instance)

    threads = []
    for _ in range(10):
        thread = threading.Thread(target=create_instance)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # All instances should be the same object
    assert len(set(id(inst) for inst in instances)) == 1
    assert all(inst is instances[0] for inst in instances)


@pytest.mark.asyncio
async def test_singleton_initialization_once() -> None:
    """Test that singleton initialization happens only once."""
    # Reset to ensure clean state
    await reset_global_state()

    # Create multiple instances
    inst1 = SecurityHeadersManager()
    inst2 = SecurityHeadersManager()
    inst3 = SecurityHeadersManager()

    # Should all be the same instance
    assert inst1 is inst2 is inst3
    assert id(inst1) == id(inst2) == id(inst3)


@pytest.mark.asyncio
async def test_cache_key_uses_hashing() -> None:
    """Test that cache keys are generated using secure hashing."""
    manager = SecurityHeadersManager()

    # Test path normalization and hashing
    test_paths = [
        "/api/users",
        "/API/USERS",  # Should normalize to same as above (case-insensitive)
        "/api/users/",  # Trailing slash should be normalized
        "api/users",  # No leading slash
    ]

    keys = []
    for path in test_paths:
        key = manager._generate_cache_key(path)
        keys.append(key)
        # Key should start with "path_" and contain hex hash
        assert key.startswith("path_")
        assert len(key) == 21  # "path_" + 16 hex chars
        # Verify it's a valid hex string
        assert all(c in "0123456789abcdef" for c in key[5:])

    # First three should generate the same key (normalization)
    # NOTE: paths are normalized to lowercase and without leading/trailing slashes
    assert keys[0] == keys[1] == keys[2] == keys[3]


@pytest.mark.asyncio
async def test_cache_key_collision_resistance() -> None:
    """Test that similar paths generate different cache keys."""
    manager = SecurityHeadersManager()

    paths = [
        "/api/users/1",
        "/api/users/2",
        "/api/user/s1",
        "/api/use/rs1",
    ]

    keys = [manager._generate_cache_key(path) for path in paths]

    # All keys should be unique
    assert len(set(keys)) == len(keys)


@pytest.mark.asyncio
async def test_cache_key_default_path() -> None:
    """Test cache key generation for default/None path."""
    manager = SecurityHeadersManager()

    assert manager._generate_cache_key(None) == "default"
    assert manager._generate_cache_key("") == "default"


@pytest.mark.asyncio
async def test_hsts_preload_requires_long_max_age(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test HSTS preload requires max_age >= 31536000."""
    manager = SecurityHeadersManager()

    # Configure with short max_age and preload
    manager.configure(
        hsts_max_age=86400,  # 1 day (too short)
        hsts_preload=True,
        hsts_include_subdomains=True,
    )

    # Preload should be disabled
    assert manager.hsts_config is not None
    assert manager.hsts_config["preload"] is False
    assert "HSTS preload requires max_age >= 31536000" in caplog.text


@pytest.mark.asyncio
async def test_hsts_preload_requires_include_subdomains(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test HSTS preload requires includeSubDomains."""
    manager = SecurityHeadersManager()

    # Configure with preload but without includeSubDomains
    manager.configure(
        hsts_max_age=31536000,  # 1 year
        hsts_preload=True,
        hsts_include_subdomains=False,
    )

    # includeSubDomains should be forced to True
    assert manager.hsts_config is not None
    assert manager.hsts_config["include_subdomains"] is True
    assert "HSTS preload requires includeSubDomains" in caplog.text


@pytest.mark.asyncio
async def test_hsts_valid_preload_configuration(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test valid HSTS preload configuration."""
    manager = SecurityHeadersManager()

    manager.configure(
        hsts_max_age=31536000,  # 1 year
        hsts_preload=True,
        hsts_include_subdomains=True,
    )

    # Configuration should be accepted as-is
    assert manager.hsts_config is not None
    assert manager.hsts_config["preload"] is True
    assert manager.hsts_config["include_subdomains"] is True
    assert manager.hsts_config["max_age"] == 31536000

    # No warnings
    assert "HSTS preload requires" not in caplog.text
