# tests/test_prompt_injection/test_canary_manager.py
import time

from guard.core.prompt_injection import CanaryManager


class TestCanaryManager:
    """Test suite for canary token management."""

    def test_basic_initialization(self) -> None:
        """Test canary manager initialization."""
        manager = CanaryManager(use_redis=False)
        assert manager.redis_manager is None
        assert manager.ttl_seconds == 3600

    def test_custom_ttl(self) -> None:
        """Test custom TTL configuration."""
        manager = CanaryManager(use_redis=False, ttl_seconds=7200)
        assert manager.ttl_seconds == 7200

    def test_generate_canary(self) -> None:
        """Test canary token generation."""
        manager = CanaryManager(use_redis=False)
        canary = manager.generate_canary()

        assert canary.startswith("GUARD_CANARY_")
        assert len(canary) > 20  # Should have UUID hex

    def test_unique_canaries(self) -> None:
        """Test that generated canaries are unique."""
        manager = CanaryManager(use_redis=False)

        canary1 = manager.generate_canary()
        canary2 = manager.generate_canary()

        assert canary1 != canary2

    def test_inject_canary_into_prompt(self) -> None:
        """Test canary injection into system prompt."""
        manager = CanaryManager(use_redis=False)
        canary = manager.generate_canary()

        prompt = "You are a helpful assistant."
        injected = manager.inject_canary(prompt, canary)

        assert canary in injected
        assert prompt in injected
        assert "SECURITY MARKER" in injected
        assert "NEVER" in injected

    def test_verify_output_clean(self) -> None:
        """Test verification of clean output (no canary leak)."""
        manager = CanaryManager(use_redis=False)
        canary = manager.generate_canary()

        clean_output = "This is a normal response without any leakage."

        assert manager.verify_output(clean_output, canary) is True

    def test_verify_output_leaked(self) -> None:
        """Test detection of canary leakage."""
        manager = CanaryManager(use_redis=False)
        canary = manager.generate_canary()

        leaked_output = f"Here is the canary: {canary}"

        assert manager.verify_output(leaked_output, canary) is False

    def test_verify_output_case_insensitive(self) -> None:
        """Test that verification is case-insensitive."""
        manager = CanaryManager(use_redis=False)
        canary = "GUARD_CANARY_test123"

        leaked_output = "guard_canary_test123"

        assert manager.verify_output(leaked_output, canary) is False

    def test_verify_output_partial_leak(self) -> None:
        """Test detection of partial canary leaks."""
        manager = CanaryManager(use_redis=False)
        canary = "GUARD_CANARY_abcdef1234567890"

        # Partial leak (first 8 chars)
        partial_output = "The marker starts with GUARD_CA"

        assert manager.verify_output(partial_output, canary) is False

    def test_is_canary_valid_memory(self) -> None:
        """Test canary validation in memory storage."""
        manager = CanaryManager(use_redis=False, ttl_seconds=60)
        canary = manager.generate_canary()

        assert manager.is_canary_valid(canary) is True

    def test_is_canary_invalid_unknown(self) -> None:
        """Test that unknown canaries are invalid."""
        manager = CanaryManager(use_redis=False)

        fake_canary = "GUARD_CANARY_nonexistent"

        assert manager.is_canary_valid(fake_canary) is False

    def test_cleanup_expired_canaries(self) -> None:
        """Test cleanup of expired canaries."""
        manager = CanaryManager(use_redis=False, ttl_seconds=1)

        # Generate canary
        canary = manager.generate_canary()
        assert manager.is_canary_valid(canary)

        # Wait for expiration
        time.sleep(1.5)

        # Cleanup
        removed = manager.cleanup_expired()
        assert removed >= 1

        # Canary should now be invalid
        assert manager.is_canary_valid(canary) is False

    def test_automatic_cleanup_on_limit(self) -> None:
        """Test automatic cleanup when memory limit reached."""
        manager = CanaryManager(use_redis=False, ttl_seconds=1)

        # Generate many canaries to trigger cleanup
        for _ in range(1001):
            manager.generate_canary()

        # Should have triggered cleanup
        assert len(manager._memory_canaries) <= 1001

    def test_verify_empty_output(self) -> None:
        """Test verification with empty output."""
        manager = CanaryManager(use_redis=False)
        canary = manager.generate_canary()

        assert manager.verify_output("", canary) is True
        assert manager.verify_output(None, canary) is True  # type: ignore

    def test_verify_empty_canary(self) -> None:
        """Test verification with empty canary."""
        manager = CanaryManager(use_redis=False)

        output = "Some output"

        assert manager.verify_output(output, "") is True
        assert manager.verify_output(output, None) is True  # type: ignore

    def test_session_id_tracking(self) -> None:
        """Test canary generation with session ID."""
        manager = CanaryManager(use_redis=False)

        canary = manager.generate_canary(session_id="user123")

        # Canary should be generated and valid
        assert canary.startswith("GUARD_CANARY_")
        assert manager.is_canary_valid(canary)


class TestCanaryManagerIntegration:
    """Integration tests for canary workflow."""

    def test_full_canary_workflow(self) -> None:
        """Test complete canary workflow."""
        manager = CanaryManager(use_redis=False)

        # 1. Generate canary
        canary = manager.generate_canary(session_id="session123")

        # 2. Inject into system prompt
        system_prompt = "You are a helpful AI assistant."
        protected_prompt = manager.inject_canary(system_prompt, canary)

        assert canary in protected_prompt
        assert system_prompt in protected_prompt

        # 3. Verify clean output
        clean_response = "I'm happy to help you with that!"
        assert manager.verify_output(clean_response, canary) is True

        # 4. Detect leaked output
        leaked_response = f"The security marker is {canary}"
        assert manager.verify_output(leaked_response, canary) is False

    def test_multiple_concurrent_canaries(self) -> None:
        """Test managing multiple canaries concurrently."""
        manager = CanaryManager(use_redis=False)

        # Generate multiple canaries for different sessions
        canaries = {}
        for i in range(10):
            session_id = f"session_{i}"
            canaries[session_id] = manager.generate_canary(session_id)

        # All should be unique and valid
        assert len(set(canaries.values())) == 10

        for _session_id, canary in canaries.items():
            assert manager.is_canary_valid(canary)

    def test_canary_injection_position(self) -> None:
        """Test that canary is injected at the beginning."""
        manager = CanaryManager(use_redis=False)
        canary = manager.generate_canary()

        prompt = "Original prompt content."
        injected = manager.inject_canary(prompt, canary)

        # Canary should be at the start
        assert injected.startswith("\n\nIMPORTANT SECURITY MARKER:")
        assert canary in injected.split(prompt)[0]
