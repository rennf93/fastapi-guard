import re
from typing import Any


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

    custom_patterns: set[str] = set()

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

    compiled_patterns: list[re.Pattern]
    compiled_custom_patterns: set[re.Pattern]
    redis_handler: Any = None

    def __new__(cls: type["SusPatternsManager"]) -> "SusPatternsManager":
        """
        Ensure only one instance of SusPatternsManager
        is created (singleton pattern).

        Returns:
            SusPatternsManager: The single instance
            of the SusPatternsManager class.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.compiled_patterns = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in cls.patterns
            ]
            cls._instance.compiled_custom_patterns = set()
            cls._instance.redis_handler = None
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
                return True
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
                    return True

        return False

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


# Instance
sus_patterns_handler = SusPatternsManager()
