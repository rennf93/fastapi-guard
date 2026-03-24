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

_CTX_XSS = frozenset({"query_param", "header", "request_body", "unknown"})
_CTX_SQLI = frozenset({"query_param", "request_body", "unknown"})
_CTX_DIR_TRAVERSAL = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_CMD_INJECTION = frozenset({"query_param", "request_body", "unknown"})
_CTX_FILE_INCLUSION = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_LDAP = frozenset({"query_param", "request_body", "unknown"})
_CTX_XML = frozenset({"header", "request_body", "unknown"})
_CTX_SSRF = frozenset({"query_param", "request_body", "unknown"})
_CTX_NOSQL = frozenset({"query_param", "request_body", "unknown"})
_CTX_FILE_UPLOAD = frozenset({"header", "request_body", "unknown"})
_CTX_PATH_TRAVERSAL = frozenset({"url_path", "query_param", "request_body", "unknown"})
_CTX_TEMPLATE = frozenset({"query_param", "request_body", "unknown"})
_CTX_HTTP_SPLIT = frozenset({"header", "query_param", "request_body", "unknown"})
_CTX_SENSITIVE_FILE = frozenset({"url_path", "request_body", "unknown"})
_CTX_CMS_PROBING = frozenset({"url_path", "request_body", "unknown"})
_CTX_RECON = frozenset({"url_path", "unknown"})
_CTX_ALL = frozenset({"query_param", "header", "url_path", "request_body", "unknown"})


class SusPatternsManager:
    _instance = None
    _config = None

    _pattern_definitions: list[tuple[str, frozenset[str]]] = [
        # XSS
        (r"<script[^>]*>[^<]*<\/script\s*>", _CTX_XSS),
        (r"javascript:\s*[^\s]+", _CTX_XSS),
        (
            r"(?:on(?:error|load|click|mouseover|submit|mouse|unload|change|focus|"
            r"blur|drag))=(?:[\"'][^\"']*[\"']|[^\s>]+)",
            _CTX_XSS,
        ),
        (
            r"(?:<[^>]+\s+(?:href|src|data|action)\s*=[\s\"\']*(?:javascript|"
            r"vbscript|data):)",
            _CTX_XSS,
        ),
        (
            r"(?:<[^>]+style\s*=[\s\"\']*[^>\"\']*(?:expression|behavior|url)\s*\("
            r"[^)]*\))",
            _CTX_XSS,
        ),
        (r"(?:<object[^>]*>[\s\S]*<\/object\s*>)", _CTX_XSS),
        (r"(?:<embed[^>]*>[\s\S]*<\/embed\s*>)", _CTX_XSS),
        (r"(?:<applet[^>]*>[\s\S]*<\/applet\s*>)", _CTX_XSS),
        # SQL Injection
        (r"(?i)SELECT\s+[\w\s,\*]+\s+FROM\s+[\w\s\._]+", _CTX_SQLI),
        (r"(?i)UNION\s+(?:ALL\s+)?SELECT", _CTX_SQLI),
        (
            r"(?i)('\s*(?:OR|AND)\s*[\(\s]*'?[\d\w]+\s*(?:=|LIKE|<|>|<=|>=)\s*"
            r"[\(\s]*'?[\d\w]+)",
            _CTX_SQLI,
        ),
        (
            r"(?i)(UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL[,\s]*)+|\(\s*SELECT\s+"
            r"(?:@@|VERSION))",
            _CTX_SQLI,
        ),
        (r"(?i)(?:INTO\s+(?:OUTFILE|DUMPFILE)\s+'[^']+')", _CTX_SQLI),
        (r"(?i)(?:LOAD_FILE\s*\([^)]+\))", _CTX_SQLI),
        (r"(?i)(?:BENCHMARK\s*\(\s*\d+\s*,)", _CTX_SQLI),
        (r"(?i)(?:SLEEP\s*\(\s*\d+\s*\))", _CTX_SQLI),
        (
            r"(?i)(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|"
            r"CONCAT|CHAR|UPDATE)\b)",
            _CTX_SQLI,
        ),
        # Directory Traversal
        (r"(?:\.\.\/|\.\.\\)(?:\.\.\/|\.\.\\)+", _CTX_DIR_TRAVERSAL),
        (
            r"(?:/etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my.cnf|ssh/"
            r"ssh_config)$)",
            _CTX_DIR_TRAVERSAL,
        ),
        (r"(?:boot\.ini|win\.ini|system\.ini|config\.sys)\s*$", _CTX_DIR_TRAVERSAL),
        (r"(?:\/proc\/self\/environ$)", _CTX_DIR_TRAVERSAL),
        (r"(?:\/var\/log\/[^\/]+$)", _CTX_DIR_TRAVERSAL),
        # Command Injection
        (
            r";\s*(?:ls|cat|rm|chmod|chown|wget|curl|nc|netcat|ping|telnet)\s+"
            r"-[a-zA-Z]+\s+",
            _CTX_CMD_INJECTION,
        ),
        (
            r"\|\s*(?:wget|curl|fetch|lwp-download|lynx|links|GET)\s+",
            _CTX_CMD_INJECTION,
        ),
        (
            r"(?:[;&|`]\s*(?:\$\([^)]+\)|\$\{[^}]+\}))",
            _CTX_CMD_INJECTION,
        ),
        (
            r"(?:^|;)\s*(?:bash|sh|ksh|csh|tsch|zsh|ash)\s+-[a-zA-Z]+",
            _CTX_CMD_INJECTION,
        ),
        (
            r"\b(?:eval|system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
            _CTX_CMD_INJECTION,
        ),
        # File Inclusion
        (
            r"(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|"
            r"rar|ogg|expect)://[^\s]+",
            _CTX_FILE_INCLUSION,
        ),
        (
            r"(?:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:[0-9]+)?(?:\/?)(?:"
            r"[a-zA-Z0-9\-\.\?,'/\\\+&amp;%\$#_]*)?)",
            _CTX_FILE_INCLUSION,
        ),
        # LDAP Injection
        (r"\(\s*[|&]\s*\(\s*[^)]+=[*]", _CTX_LDAP),
        (r"(?:\*(?:[\s\d\w]+\s*=|=\s*[\d\w\s]+))", _CTX_LDAP),
        (r"(?:\(\s*[&|]\s*)", _CTX_LDAP),
        # XML Injection
        (r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>", _CTX_XML),
        (r"(?:<!\[CDATA\[.*?\]\]>)", _CTX_XML),
        (r"(?:<\?xml.*?\?>)", _CTX_XML),
        # SSRF
        (
            r"(?:^|\s|/)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::(?:\d*)\]|(?:169\.254|192\.168|10\.|"
            r"172\.(?:1[6-9]|2[0-9]|3[01]))\.\d+)(?:\s|$|/)",
            _CTX_SSRF,
        ),
        (r"(?:file|dict|gopher|jar|tftp)://[^\s]+", _CTX_SSRF),
        # NoSQL Injection
        (
            r"\{\s*\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|"
            r"options):",
            _CTX_NOSQL,
        ),
        (r"(?:\{\s*\$[a-zA-Z]+\s*:\s*(?:\{|\[))", _CTX_NOSQL),
        # File Upload
        (
            r"(?i)filename=[\"'].*?\.(?:php\d*|phar|phtml|exe|jsp|asp|aspx|sh|"
            r"bash|rb|py|pl|cgi|com|bat|cmd|vbs|vbe|js|ws|wsf|msi|hta)[\"\']",
            _CTX_FILE_UPLOAD,
        ),
        # Path Traversal
        (
            r"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae"
            r"%e0%80%ae|%25c0%25ae)/",
            _CTX_PATH_TRAVERSAL,
        ),
        # Template Injection
        (
            r"\{\{\s*[^\}]+(?:system|exec|popen|eval|require|include)\s*\}\}",
            _CTX_TEMPLATE,
        ),
        (
            r"\{\%\s*[^\%]+(?:system|exec|popen|eval|require|include)\s*\%\}",
            _CTX_TEMPLATE,
        ),
        # HTTP Response Splitting
        (r"[\r\n]\s*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)", _CTX_HTTP_SPLIT),
        # Sensitive File Probing
        (r"(?:^|/)\.env(?:\.\w+)?(?:\?|$|/)", _CTX_SENSITIVE_FILE),
        (
            r"(?:^|/)[\w-]*config[\w-]*\."
            r"(?:env|yml|yaml|json|toml|ini|xml|conf)(?:\?|$)",
            _CTX_SENSITIVE_FILE,
        ),
        (r"(?:^|/)[\w./-]*\.map(?:\?|$)", _CTX_SENSITIVE_FILE),
        (
            r"(?:^|/)[\w./-]*\."
            r"(?:ts|tsx|jsx|py|rb|java|go|rs|php|pl|sh|sql)(?:\?|$)",
            _CTX_SENSITIVE_FILE,
        ),
        (r"(?:^|/)\.(?:git|svn|hg|bzr)(?:/|$)", _CTX_SENSITIVE_FILE),
        # CMS & Server Probing
        (
            r"(?:^|/)(?:wp-(?:admin|login|content|includes|config)"
            r"|administrator|xmlrpc)\.?(?:php)?(?:/|$|\?)",
            _CTX_CMS_PROBING,
        ),
        (r"(?:^|/)(?:phpinfo|info|test|php_info)\.php(?:\?|$)", _CTX_CMS_PROBING),
        (
            r"(?:^|/)[\w./-]*\."
            r"(?:bak|backup|old|orig|save|swp|swo|tmp|temp)(?:\?|$)",
            _CTX_CMS_PROBING,
        ),
        (
            r"(?:^|/)(?:\.htaccess|\.htpasswd|\.DS_Store|Thumbs\.db"
            r"|\.npmrc|\.dockerenv|web\.config)(?:\?|$)",
            _CTX_CMS_PROBING,
        ),
        # Reconnaissance & Fingerprinting
        (
            r"(?:^|/)[\w./-]*\.(?:asp|aspx|jsp|jsa|jhtml|shtml|cfm|cgi|do|action"
            r"|lua|inc|woa|nsf|esp|html?|js|css|properties|png|gif|jpg|jpeg"
            r"|svg|webp|bmp|pl)(?:\?|$)",
            _CTX_RECON,
        ),
        (
            r"^/(?:api|rest|v\d+|management|system|version|status|config"
            r"|config_dump|credentials)(?:/|$|\?)",
            _CTX_RECON,
        ),
        (r"^/admin(?:istrator)?(?:[./?\-]|$)", _CTX_RECON),
        (r"^/(?:login|logon|signin)(?:[./?\-]|$|/)", _CTX_RECON),
        (r"(?:^|/)account/login(?:\?|$|/)", _CTX_RECON),
        (r"(?:^|/)(?:actuator|server-status|telescope)(?:/|$|\?)", _CTX_RECON),
        (
            r"(?:CSCOE|dana-(?:na|cached)|sslvpn|RDWeb|/owa/|/ecp/"
            r"|global-protect|ssl-vpn/|svpn/|sonicui|/remote/login"
            r"|myvpn|vpntunnel|versa/login)",
            _CTX_RECON,
        ),
        (
            r"(?:^|/)(?:geoserver|confluence|nifi|ScadaBR|pandora_console"
            r"|centreon|kylin|decisioncenter|evox|MagicInfo|metasys"
            r"|officescan|helpdesk|ignite)(?:/|$|\?|\.|-)",
            _CTX_RECON,
        ),
        (r"(?:^|/)cgi-(?:bin|mod)/", _CTX_RECON),
        (r"(?:^|/)(?:HNAP1|IPCamDesc\.xml|SDK/webLanguage)(?:\?|$|/)", _CTX_RECON),
        (r"^/(?:scripts|language|languages|images|css|img)/", _CTX_RECON),
        (
            r"(?:^|/)(?:robots\.txt|sitemap\.xml|security\.txt|readme\.txt"
            r"|README\.md|CHANGELOG|pom\.xml|build\.gradle|appsettings\.json"
            r"|crossdomain\.xml)(?:\?|$|\.)",
            _CTX_RECON,
        ),
        (
            r"(?:^|/)(?:sap|ise|nidp|cslu|rustfs|developmentserver"
            r"|fog/management|lms/db|json/login_session|sms_mp"
            r"|plugin/webs_model|wsman|am_bin)(?:/|$|\?)",
            _CTX_RECON,
        ),
        (r"(?:nmaplowercheck|nice\s+ports|Trinity\.txt)", _CTX_RECON),
        (r"(?:^|/)\.(?:openclaw|clawdbot)(?:/|$)", _CTX_RECON),
        (r"^/(?:default|inicio|indice|localstart)(?:\.|/|$|\?)", _CTX_RECON),
        (
            r"(?:^|/)(?:\.streamlit|\.gpt-pilot|\.aider|\.cursor"
            r"|\.windsurf|\.copilot|\.devcontainer)(?:/|$)",
            _CTX_RECON,
        ),
        (
            r"(?:^|/)(?:docker-compose|Dockerfile|Makefile|Vagrantfile"
            r"|Jenkinsfile|Procfile)(?:\.ya?ml)?(?:\?|$)",
            _CTX_RECON,
        ),
        (
            r"(?:^|/)[\w./-]*(?:secrets?|credentials?)"
            r"\.(?:py|json|yml|yaml|toml|txt|env|xml|conf|cfg)(?:\?|$)",
            _CTX_RECON,
        ),
        (r"(?:^|/)autodiscover/", _CTX_RECON),
        (r"^/dns-query(?:\?|$)", _CTX_RECON),
        (r"(?:^|/)\.git/(?:refs|index|HEAD|objects|logs)(?:/|$)", _CTX_RECON),
    ]

    patterns: list[str] = [p[0] for p in _pattern_definitions]

    custom_patterns: set[str]
    compiled_patterns: list[tuple[re.Pattern, frozenset[str]]]
    compiled_custom_patterns: set[tuple[re.Pattern, frozenset[str]]]
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
                (re.compile(pattern, re.IGNORECASE | re.MULTILINE), contexts)
                for pattern, contexts in cls._pattern_definitions
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

    async def _preprocess_content(
        self, content: str, correlation_id: str | None
    ) -> str:
        """Preprocess content if preprocessor is available."""
        if not self._preprocessor:
            return content

        context_preprocessor = ContentPreprocessor(
            max_content_length=self._preprocessor.max_content_length,
            preserve_attack_patterns=self._preprocessor.preserve_attack_patterns,
            agent_handler=self.agent_handler,
            correlation_id=correlation_id,
        )
        return await context_preprocessor.preprocess(content)

    async def _check_regex_pattern(
        self,
        pattern: re.Pattern,
        content: str,
        ip_address: str,
        pattern_start: float,
    ) -> tuple[dict | None, bool]:
        """Check a single regex pattern with timeout protection."""
        timeout_occurred = False

        if self._compiler:
            # Use safe matcher with timeout when compiler is available
            safe_matcher = self._compiler.create_safe_matcher(pattern.pattern)
            match = safe_matcher(content)

            # Check if timeout occurred
            if match is None and time.time() - pattern_start >= 0.9 * 2.0:
                timeout_occurred = True
                import logging

                logging.getLogger("fastapi_guard.handlers.suspatterns").warning(
                    f"Pattern timeout: {pattern.pattern[:50]}..."
                )
            elif match:
                return {
                    "type": "regex",
                    "pattern": pattern.pattern,
                    "match": match.group(),
                    "position": match.start(),
                    "execution_time": time.time() - pattern_start,
                }, timeout_occurred
        else:
            # Fallback: Direct pattern matching with thread-based timeout
            match, timeout_occurred = await self._check_pattern_with_timeout(
                pattern, content, ip_address, pattern_start
            )
            if match:
                return {
                    "type": "regex",
                    "pattern": pattern.pattern,
                    "match": match.group(),
                    "position": match.start(),
                    "execution_time": time.time() - pattern_start,
                }, timeout_occurred

        return None, timeout_occurred

    async def _check_pattern_with_timeout(
        self, pattern: re.Pattern, content: str, ip_address: str, pattern_start: float
    ) -> tuple[re.Match | None, bool]:
        """Check pattern with thread-based timeout protection."""
        import concurrent.futures

        def _search(p: re.Pattern = pattern) -> re.Match | None:
            return p.search(content)

        executor_class = concurrent.futures.ThreadPoolExecutor
        with executor_class(max_workers=1) as executor:
            future = executor.submit(_search)
            try:
                match = future.result(timeout=2.0)  # Default timeout
                return match, False
            except concurrent.futures.TimeoutError:
                import logging

                logger = logging.getLogger("fastapi_guard.handlers.suspatterns")
                logger.warning(
                    f"Regex timeout exceeded for pattern: "
                    f"{pattern.pattern[:50]}... "
                    f"Potential ReDoS attack blocked. IP: {ip_address}"
                )
                future.cancel()
                return None, True
            except Exception as e:
                import logging

                logger = logging.getLogger("fastapi_guard.handlers.suspatterns")
                logger.error(
                    f"Error in regex search for pattern {pattern.pattern[:50]}...: {e}"
                )
                return None, False

    _KNOWN_CONTEXTS = frozenset(
        {"query_param", "header", "url_path", "request_body", "unknown"}
    )

    @staticmethod
    def _normalize_context(context: str) -> str:
        normalized = context.split(":", 1)[0]
        if normalized not in SusPatternsManager._KNOWN_CONTEXTS:
            return "unknown"
        return normalized

    async def _check_regex_patterns(
        self,
        content: str,
        ip_address: str,
        correlation_id: str | None,
        context: str = "unknown",
    ) -> tuple[list[dict], list[str], list[str]]:
        threats = []
        matched_patterns = []
        timeouts = []

        all_patterns = await self.get_all_compiled_patterns()
        normalized = self._normalize_context(context)
        skip_filter = normalized in ("unknown", "request_body")

        for pattern, contexts in all_patterns:
            if not skip_filter and normalized not in contexts:
                continue

            pattern_start = time.time()

            threat, timeout_occurred = await self._check_regex_pattern(
                pattern, content, ip_address, pattern_start
            )

            if timeout_occurred:
                timeouts.append(pattern.pattern)

            if threat:
                threats.append(threat)
                matched_patterns.append(pattern.pattern)

            if self._performance_monitor:
                await self._performance_monitor.record_metric(
                    pattern=pattern.pattern,
                    execution_time=time.time() - pattern_start,
                    content_length=len(content),
                    matched=bool(threat),
                    timeout=timeout_occurred,
                    agent_handler=self.agent_handler,
                    correlation_id=correlation_id,
                )

        return threats, matched_patterns, timeouts

    async def _check_semantic_threats(self, content: str) -> tuple[list[dict], float]:
        """Perform semantic analysis if analyzer is available."""
        if not self._semantic_analyzer:
            return [], 0.0

        semantic_analysis = self._semantic_analyzer.analyze(content)
        semantic_score = self._semantic_analyzer.get_threat_score(semantic_analysis)
        threats = []

        if semantic_score > self._semantic_threshold:
            # Find the most likely attack type
            attack_probs = semantic_analysis.get("attack_probabilities", {})

            for attack_type, probability in attack_probs.items():
                if probability >= self._semantic_threshold:
                    threats.append(
                        {
                            "type": "semantic",
                            "attack_type": attack_type,
                            "probability": probability,
                            "analysis": semantic_analysis,
                        }
                    )

            # Add general suspicious behavior if no specific attacks found
            if not threats and semantic_score >= self._semantic_threshold:
                threats.append(
                    {
                        "type": "semantic",
                        "attack_type": "suspicious",
                        "threat_score": semantic_score,
                        "analysis": semantic_analysis,
                    }
                )

        return threats, semantic_score

    async def _calculate_threat_score(
        self, regex_threats: list, semantic_threats: list
    ) -> float:
        """Calculate overall threat score from all detections."""
        if not (regex_threats or semantic_threats):
            return 0.0

        # Take the maximum threat score from all detections
        regex_score = 1.0 if regex_threats else 0.0
        semantic_scores = [
            t.get("probability", t.get("threat_score", 0.0)) for t in semantic_threats
        ]
        semantic_max = max(semantic_scores) if semantic_scores else 0.0
        return max(regex_score, semantic_max)

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
        execution_start = time.time()

        # Preprocess content
        processed_content = await self._preprocess_content(content, correlation_id)

        # Check regex patterns
        regex_threats, matched_patterns, timeouts = await self._check_regex_patterns(
            processed_content, ip_address, correlation_id, context
        )

        # Check semantic threats
        semantic_threats, semantic_score = await self._check_semantic_threats(
            processed_content
        )

        # Combine all threats
        threats = regex_threats + semantic_threats
        is_threat = len(threats) > 0

        # Calculate overall threat score
        threat_score = await self._calculate_threat_score(
            regex_threats, semantic_threats
        )

        # Calculate total execution time
        total_execution_time = time.time() - execution_start

        # Record overall detection metrics
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
            await self._send_threat_event(
                matched_patterns,
                semantic_threats,
                ip_address,
                context,
                content,
                threat_score,
                threats,
                regex_threats,
                timeouts,
                total_execution_time,
                correlation_id,
            )

        # Build comprehensive result
        return {
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

    async def _send_threat_event(
        self,
        matched_patterns: list,
        semantic_threats: list,
        ip_address: str,
        context: str,
        content: str,
        threat_score: float,
        threats: list,
        regex_threats: list,
        timeouts: list,
        execution_time: float,
        correlation_id: str | None,
    ) -> None:
        """Send threat detection event."""
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
            execution_time_ms=int(execution_time * 1000),
            correlation_id=correlation_id,
        )

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
        compiled_tuple = (compiled_pattern, _CTX_ALL)
        if custom:
            instance.compiled_custom_patterns.add(compiled_tuple)
            instance.custom_patterns.add(pattern)

            if instance.redis_handler:
                await instance.redis_handler.set_key(
                    "patterns", "custom", ",".join(instance.custom_patterns)
                )
        else:
            instance.compiled_patterns.append(compiled_tuple)
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

    async def _remove_custom_pattern(self, pattern: str) -> bool:
        """
        Remove pattern from custom patterns list.

        Returns:
            True if pattern was found and removed
        """
        if pattern not in self.custom_patterns:
            return False

        # Remove the pattern
        self.custom_patterns.discard(pattern)

        # Remove the compiled pattern by matching pattern string
        self.compiled_custom_patterns = {
            (p, ctx) for p, ctx in self.compiled_custom_patterns if p.pattern != pattern
        }

        # Update Redis if available
        if self.redis_handler:
            await self.redis_handler.set_key(
                "patterns", "custom", ",".join(self.custom_patterns)
            )

        return True

    async def _remove_default_pattern(self, pattern: str) -> bool:
        if pattern not in self.patterns:
            return False

        index = self.patterns.index(pattern)
        self.patterns.pop(index)

        if 0 <= index < len(self.compiled_patterns):
            self.compiled_patterns.pop(index)
            return True

        return False

    async def _clear_pattern_caches(self, pattern: str) -> None:
        """Clear caches and monitoring data for removed pattern."""
        if self._compiler:
            await self._compiler.clear_cache()
        if self._performance_monitor:
            await self._performance_monitor.remove_pattern_stats(pattern)

    async def _send_pattern_removal_event(
        self, pattern: str, custom: bool, total_patterns: int
    ) -> None:
        """Send pattern removal event to agent."""
        if not self.agent_handler:
            return

        details = f"{'Custom' if custom else 'Default'} pattern removed"
        await self._send_pattern_event(
            event_type="pattern_removed",
            ip_address="system",
            action_taken="pattern_removed",
            reason=f"{details} from detection system",
            pattern=pattern,
            pattern_type="custom" if custom else "default",
            total_patterns=total_patterns,
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

        # Remove pattern based on type
        if custom:
            pattern_removed = await instance._remove_custom_pattern(pattern)
        else:
            pattern_removed = await instance._remove_default_pattern(pattern)

        # Clear caches if pattern was removed
        if pattern_removed:
            await instance._clear_pattern_caches(pattern)

        # Send removal event if successful
        if pattern_removed:
            total_patterns = (
                len(instance.custom_patterns) if custom else len(instance.patterns)
            )
            await instance._send_pattern_removal_event(pattern, custom, total_patterns)

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
    async def get_default_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str]]]:
        instance = cls()
        return instance.compiled_patterns.copy()

    @classmethod
    async def get_custom_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str]]]:
        instance = cls()
        return list(instance.compiled_custom_patterns)

    @classmethod
    async def get_all_compiled_patterns(
        cls,
    ) -> list[tuple[re.Pattern, frozenset[str]]]:
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
