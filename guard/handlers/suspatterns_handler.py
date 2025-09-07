# guard/handlers/suspatterns_handler.py
import re
import time
from datetime import datetime, timezone
from typing import Any

from guard.detection_engine import (
    ContentPreprocessor,
    PatternCompiler,
    PerformanceMonitor,
    SemanticAnalyzer,
)


class SusPatternsManager:
    """
    A singleton class that manages suspicious
    patterns for security checks.

    This class maintains two sets of patterns:
    default patterns and custom patterns.
    It provides methods to add, remove,
    and retrieve patterns.
    """

    _instance = None
    _config = None

    patterns: list[str] = [
        # XSS
        r"<script[^>]*>[^<]*<\/script\s*>",  # Basic script tag
        r"javascript:\s*[^\s]+",  # javascript: protocol
        # Event handlers
        r"(?:on(?:error|load|click|mouseover|submit|mouse|unload|change|focus|"
        r"blur|drag))=(?:[\"'][^\"']*[\"']|[^\s>]+)",
        # Malicious attributes
        r"(?:<[^>]+\s+(?:href|src|data|action)\s*=[\s\"\']*(?:javascript|"
        r"vbscript|data):)",
        # CSS expressions
        r"(?:<[^>]+style\s*=[\s\"\']*[^>\"\']*(?:expression|behavior|url)\s*\("
        r"[^)]*\))",
        r"(?:<object[^>]*>[\s\S]*<\/object\s*>)",  # Suspicious obj
        r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)",  # Suspicious embeds
        r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)",  # Java applets
        # SQL Injection
        # Basic SELECT statements
        r"(?i)SELECT\s+[\w\s,\*]+\s+FROM\s+[\w\s\._]+",
        # UNION-based queries
        r"(?i)UNION\s+(?:ALL\s+)?SELECT",
        # Logic-based
        r"(?i)('\s*(?:OR|AND)\s*[\(\s]*'?[\d\w]+\s*(?:=|LIKE|<|>|<=|>=)\s*"
        r"[\(\s]*'?[\d\w]+)",
        # UNION-based
        r"(?i)(UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL[,\s]*)+|\(\s*SELECT\s+"
        r"(?:@@|VERSION))",
        r"(?i)(?:INTO\s+(?:OUTFILE|DUMPFILE)\s+'[^']+')",  # File ops
        r"(?i)(?:LOAD_FILE\s*\([^)]+\))",  # File reading
        r"(?i)(?:BENCHMARK\s*\(\s*\d+\s*,)",  # Time-based
        r"(?i)(?:SLEEP\s*\(\s*\d+\s*\))",  # Time-based
        # Comment-based
        r"(?i)(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|"
        r"CONCAT|CHAR|UPDATE)\b)",
        # Directory Traversal
        r"(?:\.\.\/|\.\.\\)(?:\.\.\/|\.\.\\)+",  # Multiple traversal
        # Sensitive files
        r"(?:/etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my.cnf|ssh/"
        r"ssh_config)$)",
        r"(?:boot\.ini|win\.ini|system\.ini|config\.sys)\s*$",  # Windows files
        r"(?:\/proc\/self\/environ$)",  # Process information
        r"(?:\/var\/log\/[^\/]+$)",  # Log files
        # Command Injection
        # Basic commands
        r";\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\s+"
        r"-[a-zA-Z]+\s+",
        # Download commands
        r"\|\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\s+",
        # Command substitution
        r"(?:[;&|`]\s*(?:\$\([^)]+\)|\$\{[^}]+\}))",
        # Shell execution
        r"(?:^|;)\s*(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+",
        # PHP functions
        r"\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
        # File Inclusion
        # Protocols
        r"(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|"
        r"rar|ogg|expect)://[^\s]+",
        # URLs
        r"(?:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:[0-9]+)?(?:\/?)(?:"
        r"[a-zA-Z0-9\-\.\?,'/\\\+&amp;%\$#_]*)?)",
        # LDAP Injection
        r"\(\s*[|&]\s*\(\s*[^)]+=[*]",  # Wildcards
        r"(?:\*(?:[\s\d\w]+\s*=|=\s*[\d\w\s]+))",  # Attribute match
        r"(?:\(\s*[&|]\s*)",  # Logic operations
        # XML Injection
        r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>",  # XXE
        r"(?:<!\[CDATA\[.*?\]\]>)",  # CDATA sections
        r"(?:<\?xml.*?\?>)",  # XML declarations
        # SSRF
        # Local addresses
        r"(?:^|\s|/)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::(?:\d*)\]|(?:169\.254|192\.168|10\.|"
        r"172\.(?:1[6-9]|2[0-9]|3[01]))\.\d+)(?:\s|$|/)",
        r"(?:file|dict|gopher|jar|tftp)://[^\s]+",  # Dangerous protocols
        # NoSQL Injection
        # MongoDB
        r"\{\s*\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|"
        r"options):",
        r"(?:\{\s*\$[a-zA-Z]+\s*:\s*(?:\{|\[))",  # Nested operators
        # File Upload
        r"(?i)filename=[\"'].*?\.(?:php\d*|phar|phtml|exe|jsp|asp|aspx|sh|"
        r"bash|rb|py|pl|cgi|com|bat|cmd|vbs|vbe|js|ws|wsf|msi|hta)[\"\']",
        # Path Traversal
        # Encoded traversal
        r"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae"
        r"%e0%80%ae|%25c0%25ae)/",
        # Template Injection
        # Basic template injection
        r"\{\{\s*[^\}]+(?:system|exec|popen|eval|require|include)\s*\}\}",
        # Alternative syntax
        r"\{\%\s*[^\%]+(?:system|exec|popen|eval|require|include)\s*\%\}",
        # HTTP Response Splitting
        r"[\r\n]\s*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)",
    ]

    custom_patterns: set[str]
    compiled_patterns: list[re.Pattern]
    compiled_custom_patterns: set[re.Pattern]
    redis_handler: Any
    agent_handler: Any
    _compiler: PatternCompiler | None
    _preprocessor: ContentPreprocessor | None
    _semantic_analyzer: SemanticAnalyzer | None
    _performance_monitor: PerformanceMonitor | None
    _semantic_threshold: float

    def __new__(
        cls: type["SusPatternsManager"], config: Any = None
    ) -> "SusPatternsManager":
        """
        Ensure only one instance of SusPatternsManager
        is created (singleton pattern).

        Args:
            config: Optional SecurityConfig to use for initialization

        Returns:
            SusPatternsManager: The single instance
            of the SusPatternsManager class.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.custom_patterns = set()
            cls._instance.compiled_patterns = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in cls.patterns
            ]
            cls._instance.compiled_custom_patterns = set()
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None

            # Store config for later use
            cls._config = config

            # Initialize detection engine components with config if available
            if config and hasattr(config, "detection_compiler_timeout"):
                # Use config values
                cls._instance._compiler = PatternCompiler(
                    default_timeout=config.detection_compiler_timeout,
                    max_cache_size=config.detection_max_tracked_patterns,
                )
                cls._instance._preprocessor = ContentPreprocessor(
                    max_content_length=config.detection_max_content_length,
                    preserve_attack_patterns=config.detection_preserve_attack_patterns,
                )
                cls._instance._semantic_analyzer = SemanticAnalyzer()
                cls._instance._performance_monitor = PerformanceMonitor(
                    anomaly_threshold=config.detection_anomaly_threshold,
                    slow_pattern_threshold=config.detection_slow_pattern_threshold,
                    history_size=config.detection_monitor_history_size,
                    max_tracked_patterns=config.detection_max_tracked_patterns,
                )
                cls._instance._semantic_threshold = config.detection_semantic_threshold
            else:
                # Don't initialize by default - only when explicitly needed
                cls._instance._compiler = None
                cls._instance._preprocessor = None
                cls._instance._semantic_analyzer = None
                cls._instance._performance_monitor = None
                cls._instance._semantic_threshold = 0.7

        return cls._instance

    async def initialize_redis(self, redis_handler: Any) -> None:
        """Initialize Redis connection and load cached patterns"""
        self.redis_handler = redis_handler
        if self.redis_handler:
            cached_patterns = await self.redis_handler.get_key("patterns", "custom")
            if cached_patterns:
                patterns = cached_patterns.split(",")
                for pattern in patterns:
                    if pattern not in self.custom_patterns:
                        await self.add_pattern(pattern, custom=True)

    async def initialize_agent(self, agent_handler: Any) -> None:
        """Initialize agent integration."""
        self.agent_handler = agent_handler

    async def _send_pattern_event(
        self,
        event_type: str,
        ip_address: str,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """Send pattern detection events to agent."""
        if not self.agent_handler:
            return

        try:
            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=ip_address,
                action_taken=action_taken,
                reason=reason,
                metadata=kwargs,
            )
            await self.agent_handler.send_event(event)
        except Exception as e:
            # Don't let agent errors break pattern detection
            import logging

            logging.getLogger("fastapi_guard.handlers.suspatterns").error(
                f"Failed to send pattern event to agent: {e}"
            )

    async def detect(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Perform comprehensive threat detection with detailed results.

        This method provides a rich detection result similar to ThreatDetector,
        including threat scores, detailed threat information, and performance metrics.

        Args:
            content:
                Content to check against patterns
            ip_address:
                IP address of the request
            context:
                Context where the pattern was found
                (e.g., "query_param", "header", "body")
            correlation_id:
                Optional correlation ID for tracking

        Returns:
            Detection results dictionary containing:
            - is_threat: Whether a threat was detected
            - threat_score: Score from 0.0 to 1.0
            - threats: List of detected threats with details
            - context: The context where detection occurred
            - original_length: Length of original content
            - processed_length: Length after preprocessing
            - execution_time: Total detection time in seconds
            - detection_method: Method used (enhanced/legacy)
        """
        original_content = content

        # Preprocess content if preprocessor is available
        processed_content = content
        if self._preprocessor:
            context_preprocessor = ContentPreprocessor(
                max_content_length=self._preprocessor.max_content_length,
                preserve_attack_patterns=self._preprocessor.preserve_attack_patterns,
                agent_handler=self.agent_handler,
                correlation_id=correlation_id,
            )
            processed_content = await context_preprocessor.preprocess(content)

        # Initialize threat tracking
        threats = []
        matched_patterns = []
        regex_threats = []
        semantic_threats = []
        timeouts: list[str] = []

        # Check with compiled patterns
        all_patterns = await self.get_all_compiled_patterns()
        execution_start = time.time()

        # Try regex patterns with timeout protection
        for pattern in all_patterns:
            pattern_start = time.time()
            timeout_occurred = False
            try:
                if self._compiler:
                    # Use safe matcher with timeout when compiler is available
                    safe_matcher = self._compiler.create_safe_matcher(pattern.pattern)
                    match = safe_matcher(processed_content)

                    # Check if timeout occurred (safe_matcher returns None on timeout)
                    if match is None and time.time() - pattern_start >= 0.9 * 2.0:
                        # Likely a timeout (using 90% of default timeout as threshold)
                        timeout_occurred = True
                        timeouts.append(pattern.pattern)
                        import logging

                        logging.getLogger("fastapi_guard.handlers.suspatterns").warning(
                            f"Pattern timeout: {pattern.pattern[:50]}..."
                        )
                    elif match:
                        matched_patterns.append(pattern.pattern)
                        regex_threat = {
                            "type": "regex",
                            "pattern": pattern.pattern,
                            "match": match.group(),
                            "position": match.start(),
                            "execution_time": time.time() - pattern_start,
                        }
                        regex_threats.append(regex_threat)
                        threats.append(regex_threat)
                else:
                    # Fallback: Direct pattern matching with thread-based timeout
                    import concurrent.futures

                    def _search(p: re.Pattern = pattern) -> re.Match | None:
                        return p.search(processed_content)

                    executor_class = concurrent.futures.ThreadPoolExecutor
                    with executor_class(max_workers=1) as executor:
                        future = executor.submit(_search)
                        try:
                            match = future.result(timeout=2.0)  # Default timeout
                            if match:
                                matched_patterns.append(pattern.pattern)
                                regex_threat = {
                                    "type": "regex",
                                    "pattern": pattern.pattern,
                                    "match": match.group(),
                                    "position": match.start(),
                                    "execution_time": time.time() - pattern_start,
                                }
                                regex_threats.append(regex_threat)
                                threats.append(regex_threat)
                        except concurrent.futures.TimeoutError:
                            timeout_occurred = True
                            timeouts.append(pattern.pattern)
                            import logging

                            logger = logging.getLogger(
                                "fastapi_guard.handlers.suspatterns"
                            )
                            logger.warning(
                                f"Regex timeout exceeded for pattern: "
                                f"{pattern.pattern[:50]}... "
                                f"Potential ReDoS attack blocked. IP: {ip_address}"
                            )
                            future.cancel()
                        except Exception as e:
                            import logging

                            logger = logging.getLogger(
                                "fastapi_guard.handlers.suspatterns"
                            )
                            logger.error(
                                f"Error in regex search for pattern "
                                f"{pattern.pattern[:50]}...: {e}"
                            )

            finally:
                # Record performance metrics if monitor available
                if self._performance_monitor:
                    await self._performance_monitor.record_metric(
                        pattern=pattern.pattern,
                        execution_time=time.time() - pattern_start,
                        content_length=len(processed_content),
                        matched=bool(pattern.pattern in matched_patterns),
                        timeout=timeout_occurred,
                        agent_handler=self.agent_handler,
                        correlation_id=correlation_id,
                    )

        # Perform semantic analysis if analyzer available
        semantic_score = 0.0
        semantic_analysis = None
        if self._semantic_analyzer:
            semantic_analysis = self._semantic_analyzer.analyze(processed_content)
            semantic_score = self._semantic_analyzer.get_threat_score(semantic_analysis)

            if semantic_score > self._semantic_threshold:
                # Find the most likely attack type
                attack_probs = semantic_analysis.get("attack_probabilities", {})

                for attack_type, probability in attack_probs.items():
                    if probability >= self._semantic_threshold:
                        semantic_threat = {
                            "type": "semantic",
                            "attack_type": attack_type,
                            "probability": probability,
                            "analysis": semantic_analysis,
                        }
                        semantic_threats.append(semantic_threat)
                        threats.append(semantic_threat)

                # Add general suspicious behavior if no specific attacks found
                if not semantic_threats and semantic_score >= self._semantic_threshold:
                    semantic_threat = {
                        "type": "semantic",
                        "attack_type": "suspicious",
                        "threat_score": semantic_score,
                        "analysis": semantic_analysis,
                    }
                    semantic_threats.append(semantic_threat)
                    threats.append(semantic_threat)

        # Calculate total execution time
        total_execution_time = time.time() - execution_start

        # Determine if threat detected
        is_threat = len(threats) > 0

        # Calculate overall threat score
        threat_score = 0.0
        if threats:
            # Take the maximum threat score from all detections
            regex_score = 1.0 if regex_threats else 0.0
            semantic_scores = [
                t.get("probability", t.get("threat_score", 0.0))
                for t in semantic_threats
            ]
            semantic_max = max(semantic_scores) if semantic_scores else 0.0
            threat_score = max(regex_score, semantic_max)

        # Record overall detection metrics if monitor available
        if self._performance_monitor:
            await self._performance_monitor.record_metric(
                pattern="overall_detection",
                execution_time=total_execution_time,
                content_length=len(content),
                matched=is_threat,
                timeout=False,
                agent_handler=self.agent_handler,
                correlation_id=correlation_id,
            )

        # Send event if threat detected
        if is_threat:
            # Prepare pattern info for event
            pattern_info = "unknown"
            if matched_patterns:
                pattern_info = matched_patterns[0]  # First matched pattern
            elif semantic_threats:
                pattern_info = f"semantic:{semantic_threats[0]['attack_type']}"

            await self._send_pattern_event(
                event_type="pattern_detected",
                ip_address=ip_address,
                action_taken="threat_detected",
                reason=f"Threat detected in {context}",
                pattern=pattern_info,
                context=context,
                content_preview=content[:100] if len(content) > 100 else content,
                threat_score=threat_score,
                threats=len(threats),
                regex_threats=len(regex_threats),
                semantic_threats=len(semantic_threats),
                timeouts=len(timeouts),
                detection_method="enhanced" if self._compiler else "legacy",
                execution_time_ms=int(total_execution_time * 1000),
                correlation_id=correlation_id,
            )

        # Build comprehensive result
        result = {
            "is_threat": is_threat,
            "threat_score": threat_score,
            "threats": threats,
            "context": context,
            "original_length": len(original_content),
            "processed_length": len(processed_content),
            "execution_time": total_execution_time,
            "detection_method": "enhanced" if self._compiler else "legacy",
            "timeouts": timeouts,
            "correlation_id": correlation_id,
        }

        return result

    async def detect_pattern_match(
        self,
        content: str,
        ip_address: str,
        context: str = "unknown",
        correlation_id: str | None = None,
    ) -> tuple[bool, str | None]:
        """
        Legacy method for backward compatibility.

        Detect if content matches any suspicious patterns and send agent events.

        Args:
            content:
                Content to check against patterns
            ip_address:
                IP address of the request
            context:
                Context where the pattern was found
                (e.g., "query_param", "header", "body")

        Returns:
            Tuple of (pattern_detected, matched_pattern)
        """
        # Use the new detect method
        result = await self.detect(content, ip_address, context, correlation_id)

        # Extract legacy format from rich result
        if result["is_threat"]:
            # Get first matched pattern for backward compatibility
            if result["threats"]:
                threat = result["threats"][0]
                if threat["type"] == "regex":
                    return True, threat["pattern"]
                elif threat["type"] == "semantic":
                    return True, f"semantic:{threat.get('attack_type', 'suspicious')}"
            return True, "unknown"

        return False, None

    @classmethod
    async def add_pattern(cls, pattern: str, custom: bool = False) -> None:
        """
        Add a new pattern to either the custom or
        default patterns list.

        Args:
            pattern (str): The pattern to be added.
            custom (bool, optional): If True, add
            to custom patterns; otherwise, add to
            default patterns. Defaults to False.
        """
        instance = cls()

        compiled_pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        if custom:
            instance.compiled_custom_patterns.add(compiled_pattern)
            instance.custom_patterns.add(pattern)

            if instance.redis_handler:
                await instance.redis_handler.set_key(
                    "patterns", "custom", ",".join(instance.custom_patterns)
                )
        else:
            instance.compiled_patterns.append(compiled_pattern)
            instance.patterns.append(pattern)

        # Clear compiler cache if available
        if instance._compiler:
            await instance._compiler.clear_cache()

        # Send pattern addition event to agent
        if instance.agent_handler:
            details = f"{'Custom' if custom else 'Default'} pattern added"
            await instance._send_pattern_event(
                event_type="pattern_added",
                ip_address="system",
                action_taken="pattern_added",
                reason=f"{details} to detection system",
                pattern=pattern,
                pattern_type="custom" if custom else "default",
                total_patterns=len(instance.custom_patterns)
                if custom
                else len(instance.patterns),
            )

    @classmethod
    async def remove_pattern(cls, pattern: str, custom: bool = False) -> bool:
        """
        Remove a pattern from either the
        custom or default patterns list.

        Args:
            pattern (str): The pattern to be removed.
            custom (bool, optional): If True, remove
            from custom patterns; otherwise, remove
            from default patterns. Defaults to False.

        Returns:
            bool: True if pattern was successfully removed, False otherwise
        """
        instance = cls()

        pattern_removed = False

        if custom:
            # Handle custom patterns
            if pattern in instance.custom_patterns:
                # Remove the pattern
                instance.custom_patterns.discard(pattern)

                # Remove the compiled pattern by matching pattern string
                instance.compiled_custom_patterns = {
                    p for p in instance.compiled_custom_patterns if p.pattern != pattern
                }

                # Update Redis if available
                if instance.redis_handler:
                    await instance.redis_handler.set_key(
                        "patterns", "custom", ",".join(instance.custom_patterns)
                    )
                pattern_removed = True
        else:
            # Handle default patterns
            if pattern in instance.patterns:
                # Get the index of the pattern
                index = instance.patterns.index(pattern)

                # Remove the pattern
                instance.patterns.pop(index)

                # Remove the compiled pattern
                if 0 <= index < len(instance.compiled_patterns):
                    instance.compiled_patterns.pop(index)
                    pattern_removed = True

        # Clear compiler cache and remove from monitor if available
        if pattern_removed:
            if instance._compiler:
                await instance._compiler.clear_cache()
            if instance._performance_monitor:
                await instance._performance_monitor.remove_pattern_stats(pattern)

        # Send pattern removal event to agent
        if pattern_removed and instance.agent_handler:
            details = f"{'Custom' if custom else 'Default'} pattern removed"
            await instance._send_pattern_event(
                event_type="pattern_removed",
                ip_address="system",
                action_taken="pattern_removed",
                reason=f"{details} from detection system",
                pattern=pattern,
                pattern_type="custom" if custom else "default",
                total_patterns=len(instance.custom_patterns)
                if custom
                else len(instance.patterns),
            )

        return pattern_removed

    @classmethod
    async def get_default_patterns(cls) -> list[str]:
        """
        Retrieve only the default patterns.

        Returns:
            list[str]: A list containing only default patterns.
        """
        instance = cls()
        return instance.patterns.copy()

    @classmethod
    async def get_custom_patterns(cls) -> list[str]:
        """
        Retrieve only the custom patterns.

        Returns:
            list[str]: A list containing only custom patterns.
        """
        instance = cls()
        return list(instance.custom_patterns)

    @classmethod
    async def get_all_patterns(cls) -> list[str]:
        """
        Retrieve all patterns, including
        both default and custom patterns.

        Returns:
            list[str]: A list containing
            all default and custom patterns.
        """
        instance = cls()
        return instance.patterns + list(instance.custom_patterns)

    @classmethod
    async def get_default_compiled_patterns(cls) -> list[re.Pattern]:
        """
        Retrieve only the default compiled patterns.

        Returns:
            list[re.Pattern]: A list containing only default compiled patterns.
        """
        instance = cls()
        return instance.compiled_patterns.copy()

    @classmethod
    async def get_custom_compiled_patterns(cls) -> list[re.Pattern]:
        """
        Retrieve only the custom compiled patterns.

        Returns:
            list[re.Pattern]: A list containing only custom compiled patterns.
        """
        instance = cls()
        return list(instance.compiled_custom_patterns)

    @classmethod
    async def get_all_compiled_patterns(cls) -> list[re.Pattern]:
        """
        Retrieve all compiled patterns,
        including both default and custom patterns.

        Returns:
            list[re.Pattern]: A list containing
            all default and custom compiled patterns.
        """
        instance = cls()
        return instance.compiled_patterns + list(instance.compiled_custom_patterns)

    @classmethod
    async def get_performance_stats(cls) -> dict[str, Any] | None:
        """
        Get performance statistics from the performance monitor.

        Returns:
            Performance statistics or None if monitoring disabled
        """
        instance = cls()
        if instance._performance_monitor:
            return {
                "summary": instance._performance_monitor.get_summary_stats(),
                "slow_patterns": instance._performance_monitor.get_slow_patterns(),
                "problematic_patterns": (
                    instance._performance_monitor.get_problematic_patterns()
                ),
            }
        return None

    @classmethod
    async def get_component_status(cls) -> dict[str, bool]:
        """
        Get status of detection engine components.

        Returns:
            Dictionary showing which components are active
        """
        instance = cls()
        return {
            "compiler": instance._compiler is not None,
            "preprocessor": instance._preprocessor is not None,
            "semantic_analyzer": instance._semantic_analyzer is not None,
            "performance_monitor": instance._performance_monitor is not None,
        }

    async def configure_semantic_threshold(self, threshold: float) -> None:
        """
        Configure the semantic analysis threshold.

        Args:
            threshold: Threat score threshold (0.0 to 1.0)
        """
        # Store as class variable for now
        self._semantic_threshold = max(0.0, min(1.0, threshold))

    @classmethod
    async def reset(cls) -> None:
        """
        Reset the singleton instance to clean state.

        This method is primarily for testing to ensure clean state between tests.
        It clears all custom patterns and resets handlers to None.

        WARNING: This will clear all custom patterns and cached data.
        """
        if cls._instance is not None:
            # Clear custom patterns
            cls._instance.custom_patterns.clear()
            cls._instance.compiled_custom_patterns.clear()

            # Reset handlers
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None

            # Clear compiler cache if available
            if hasattr(cls._instance, "_compiler") and cls._instance._compiler:
                await cls._instance._compiler.clear_cache()

            # Clear performance monitor stats if available
            if (
                hasattr(cls._instance, "_performance_monitor")
                and cls._instance._performance_monitor
            ):
                cls._instance._performance_monitor.pattern_stats.clear()
                cls._instance._performance_monitor.recent_metrics.clear()

            # Reset config
            cls._config = None


# Instance
sus_patterns_handler = SusPatternsManager()
