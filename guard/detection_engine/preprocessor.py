# guard/detection_engine/preprocessor.py
import re
import unicodedata
from typing import Any


class ContentPreprocessor:
    """
    Normalizes content to improve detection while preserving attack signatures.

    This class handles content preprocessing to prevent bypass attempts
    while maintaining the ability to detect legitimate threats. It addresses
    the bypass vulnerability where attackers use padding to exceed regex bounds.

    Key Security Features:
    - Preserves critical attack elements during truncation
    - Normalizes content without destroying attack signatures
    - Removes padding while maintaining detection capability
    - Uses bounded operations to prevent ReDoS
    """

    def __init__(
        self,
        max_content_length: int = 10000,
        preserve_attack_patterns: bool = True,
        agent_handler: Any = None,
        correlation_id: str | None = None,
    ):
        """
        Initialize the ContentPreprocessor.

        Args:
            max_content_length:
                Maximum length of content to process
            preserve_attack_patterns:
                Whether to preserve attack patterns during truncation
            agent_handler:
                Optional agent handler for event logging
            correlation_id:
                Optional correlation ID for request tracking
        """
        self.max_content_length = max_content_length
        self.preserve_attack_patterns = preserve_attack_patterns
        self.agent_handler = agent_handler
        self.correlation_id = correlation_id

        # Attack indicators to preserve during truncation
        # Use non-greedy quantifiers and anchors
        self.attack_indicators = [
            r"<script",
            r"javascript:",
            r"on\w+=",
            r"SELECT\s+.{0,50}?\s+FROM",  # Limit to prevent DoS
            r"UNION\s+SELECT",
            r"\.\./",
            r"eval\s*\(",
            r"exec\s*\(",
            r"system\s*\(",
            r"<?php",
            r"<%",
            r"{{",
            r"{%",
            # Additional critical patterns
            r"<iframe",
            r"<object",
            r"<embed",
            r"onerror\s*=",
            r"onload\s*=",
            r"\$\{",  # Template injection
            r"\\x[0-9a-fA-F]{2}",  # Hex encoding
            r"%[0-9a-fA-F]{2}",  # URL encoding pattern
        ]

        # Compile attack indicators for efficiency
        self.compiled_indicators = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.attack_indicators
        ]

    async def _send_preprocessor_event(
        self,
        event_type: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """Send preprocessor-related events to agent."""
        if not self.agent_handler:
            return

        try:
            from datetime import datetime, timezone

            event = type(
                "SecurityEvent",
                (),
                {
                    "timestamp": datetime.now(timezone.utc),
                    "event_type": event_type,
                    "ip_address": "system",
                    "action_taken": action_taken,
                    "reason": reason,
                    "metadata": {
                        "component": "ContentPreprocessor",
                        "correlation_id": self.correlation_id,
                        **kwargs,
                    },
                },
            )()
            await self.agent_handler.send_event(event)
        except Exception as e:
            # Don't let agent errors break preprocessing
            import logging

            logging.getLogger("fastapi_guard.detection_engine").error(
                f"Failed to send preprocessor event to agent: {e}"
            )

    def normalize_unicode(self, content: str) -> str:
        """
        Normalize Unicode characters to prevent bypass using lookalikes.

        Args:
            content: The content to normalize

        Returns:
            Normalized content
        """
        # Normalize to NFKC form
        normalized = unicodedata.normalize("NFKC", content)

        # Replace common lookalike characters
        lookalikes = {
            "\u2044": "/",  # Fraction slash
            "\uff0f": "/",  # Fullwidth solidus
            "\u29f8": "/",  # Big solidus
            "\u0130": "I",  # Turkish capital I with dot
            "\u0131": "i",  # Turkish lowercase i without dot
            "\u200b": "",  # Zero-width space
            "\u200c": "",  # Zero-width non-joiner
            "\u200d": "",  # Zero-width joiner
            "\ufeff": "",  # Zero-width no-break space
            # Additional dangerous Unicode bypasses
            "\u00ad": "",  # Soft hyphen
            "\u034f": "",  # Combining grapheme joiner
            "\u180e": "",  # Mongolian vowel separator
            "\u2028": "\n",  # Line separator
            "\u2029": "\n",  # Paragraph separator
            "\ue000": "",  # Private use area start
            "\ufff0": "",  # Specials block
            # Homoglyphs for common attack characters
            "\u01c0": "|",  # Latin letter dental click
            "\u037e": ";",  # Greek question mark (looks like semicolon)
            "\u2215": "/",  # Division slash
            "\u2216": "\\",  # Set minus
            "\uff1c": "<",  # Fullwidth less-than
            "\uff1e": ">",  # Fullwidth greater-than
        }

        for char, replacement in lookalikes.items():
            normalized = normalized.replace(char, replacement)

        return normalized

    def remove_excessive_whitespace(self, content: str) -> str:
        """
        Remove excessive whitespace while preserving structure.

        Args:
            content: The content to clean

        Returns:
            Content with normalized whitespace
        """
        # Replace multiple spaces with single space
        content = re.sub(r"\s+", " ", content)

        # Remove leading/trailing whitespace
        content = content.strip()

        return content

    def extract_attack_regions(self, content: str) -> list[tuple[int, int]]:
        """
        Extract regions containing potential attack patterns.

        Args:
            content: The content to analyze

        Returns:
            List of (start, end) tuples for attack regions
        """
        # Limit number of regions to prevent memory DoS
        max_regions = min(100, self.max_content_length // 100)
        regions = []

        for indicator in self.compiled_indicators:
            # Use timeout protection for regex
            import concurrent.futures

            def _find_all(pattern: re.Pattern, text: str) -> list[tuple[int, int]]:
                found: list[tuple[int, int]] = []
                for match in pattern.finditer(text):
                    if len(found) >= max_regions:
                        break
                    # Extend region by 100 chars before and after
                    start = max(0, match.start() - 100)
                    end = min(len(text), match.end() + 100)
                    found.append((start, end))
                return found

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_find_all, indicator, content)
                try:
                    indicator_regions = future.result(timeout=0.5)  # 500ms timeout
                    regions.extend(indicator_regions)
                except concurrent.futures.TimeoutError:
                    # Skip this indicator if it times out
                    continue

            if len(regions) >= max_regions:
                break

        # Merge overlapping regions
        if regions:
            regions.sort()
            merged = [regions[0]]
            for start, end in regions[1:]:
                if start <= merged[-1][1]:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], end))
                else:
                    merged.append((start, end))
            return merged[:max_regions]  # Ensure we don't exceed limit

        return []

    def _extract_and_concatenate_attack_regions(
        self, content: str, attack_regions: list[tuple[int, int]]
    ) -> str:
        """
        Extract and concatenate attack regions when they exceed max length.

        This method handles the case where attack regions alone exceed
        the maximum content length, extracting chunks until the limit is reached.

        Args:
            content: The original content
            attack_regions: List of (start, end) tuples for attack regions

        Returns:
            Concatenated attack regions truncated to max_content_length
        """
        result = ""
        remaining = self.max_content_length

        for start, end in attack_regions:
            chunk_len = min(end - start, remaining)
            result += content[start : start + chunk_len]
            remaining -= chunk_len
            if remaining <= 0:
                break

        return result

    def _add_non_attack_content(
        self,
        content: str,
        attack_regions: list[tuple[int, int]],
        result_parts: list[str],
        remaining: int,
    ) -> None:
        """
        Add non-attack content to fill remaining space in result.

        This method inserts chunks of content between attack regions
        to utilize available space while maintaining attack signature visibility.

        Args:
            content: The original content
            attack_regions: List of (start, end) tuples for attack regions
            result_parts: List to prepend non-attack content chunks to
            remaining: Remaining bytes available in result
        """
        last_end = 0
        for start, end in attack_regions:
            if last_end < start and remaining > 0:
                chunk_len = min(start - last_end, remaining)
                result_parts.insert(0, content[last_end : last_end + chunk_len])
                remaining -= chunk_len
            last_end = end

    def _build_result_with_attack_regions_and_context(
        self, content: str, attack_regions: list[tuple[int, int]]
    ) -> str:
        """
        Build result including attack regions and surrounding context.

        This method constructs the final result by including all attack regions
        and filling remaining space with non-attack content for context.

        Args:
            content: The original content
            attack_regions: List of (start, end) tuples for attack regions

        Returns:
            Content with attack regions and context truncated to max_content_length
        """
        attack_length = sum(end - start for start, end in attack_regions)
        result_parts = []
        remaining = self.max_content_length - attack_length

        # Add attack regions
        for start, end in attack_regions:
            result_parts.append(content[start:end])

        # Add non-attack content to fill remaining space
        self._add_non_attack_content(content, attack_regions, result_parts, remaining)

        return "".join(result_parts)

    def truncate_safely(self, content: str) -> str:
        """
        Truncate content while preserving attack signatures.

        Args:
            content: The content to truncate

        Returns:
            Safely truncated content
        """
        if len(content) <= self.max_content_length:
            return content

        if not self.preserve_attack_patterns:
            return content[: self.max_content_length]

        # Find attack regions
        attack_regions = self.extract_attack_regions(content)

        if not attack_regions:
            # No attack patterns found, simple truncation
            return content[: self.max_content_length]

        # Calculate total length of attack regions
        attack_length = sum(end - start for start, end in attack_regions)

        if attack_length >= self.max_content_length:
            # Attack regions exceed max length, concatenate them
            return self._extract_and_concatenate_attack_regions(content, attack_regions)

        # Include attack regions and fill remaining space
        return self._build_result_with_attack_regions_and_context(
            content, attack_regions
        )

    def remove_null_bytes(self, content: str) -> str:
        """
        Remove null bytes and other control characters.

        Args:
            content: The content to clean

        Returns:
            Content without null bytes
        """
        # Remove null bytes
        content = content.replace("\x00", "")

        # Remove other dangerous control characters
        control_chars = "".join(chr(i) for i in range(32) if i not in (9, 10, 13))
        translator = str.maketrans("", "", control_chars)
        return content.translate(translator)

    async def decode_common_encodings(self, content: str) -> str:
        """
        Decode common attack encoding schemes.

        Args:
            content: The content to decode

        Returns:
            Decoded content
        """
        # Limit decoding iterations to prevent DoS
        max_decode_iterations = 3  # Configurable but with a safe default
        iterations = 0

        while iterations < max_decode_iterations:
            original = content

            # URL decode
            try:
                import urllib.parse

                decoded = urllib.parse.unquote(content, errors="ignore")
                if decoded != content:
                    content = decoded
            except Exception as e:
                # Log URL decode error but continue processing
                await self._send_preprocessor_event(
                    event_type="decoding_error",
                    action_taken="decode_failed",
                    reason="Failed to URL decode content",
                    error=str(e),
                    error_type="url_decode",
                )

            # HTML entity decode
            try:
                import html

                decoded = html.unescape(content)
                if decoded != content:
                    content = decoded
            except Exception as e:
                # Log HTML decode error but continue processing
                await self._send_preprocessor_event(
                    event_type="decoding_error",
                    action_taken="decode_failed",
                    reason="Failed to HTML decode content",
                    error=str(e),
                    error_type="html_decode",
                )

            # If nothing changed, stop decoding
            if content == original:
                break

            iterations += 1

        return content

    async def preprocess(self, content: str) -> str:
        """
        Apply all preprocessing steps to the content.

        Args:
            content: The content to preprocess

        Returns:
            Preprocessed content ready for pattern matching
        """
        if not content:
            return ""

        # Apply preprocessing steps in order
        content = self.normalize_unicode(content)
        content = await self.decode_common_encodings(content)
        content = self.remove_null_bytes(content)
        content = self.remove_excessive_whitespace(content)
        content = self.truncate_safely(content)

        return content

    async def preprocess_batch(self, contents: list[str]) -> list[str]:
        """
        Preprocess multiple content items.

        Args:
            contents: List of content strings to preprocess

        Returns:
            List of preprocessed content strings
        """
        return [await self.preprocess(content) for content in contents]
