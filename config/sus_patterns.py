import re
from typing import Set, List


class SusPatterns:
    """
    A singleton class that manages suspicious
    patterns for security checks.

    This class maintains two sets of patterns:
    default patterns and custom patterns.
    It provides methods to add, remove,
    and retrieve patterns.
    """

    _instance = None

    custom_patterns: Set[str] = set()

    patterns: List[str] = [
        # XSS - Enhanced patterns
        r"<script[^>]*>[^<]*<\/script\s*>",  # Basic script tag
        r"javascript:\s*[^\s]+",  # javascript: protocol
        # Event handlers
        r"(?:on(?:error|load|click|mouseover|submit|mouse|unload|change|focus|"
        r"blur|drag))=[\"\']?[^\"\'>\s]+",
        # Malicious attributes
        r"(?:<[^>]*\s+(?:href|src|data|action)\s*=[\s\"\']*(?:javascript|"
        r"vbscript|data):)",
        # CSS expressions
        r"(?:<[^>]*\s+style\s*=[\s\"\']*[^>]*(?:expression|behavior|url)\s*\("
        r"[^)]*\))",
        r"(?:<object[^>]*>[\s\S]*?<\/object\s*>)",  # Suspicious objects
        r"(?:<embed[^>]*>[\s\S]*?<\/embed\s*>)",  # Suspicious embeds
        r"(?:<applet[^>]*>[\s\S]*?<\/applet\s*>)",  # Java applets

        # SQL Injection - Enhanced patterns
        # Logic-based
        r"(?i)('\s*(?:OR|AND)\s*[\(\s]*'?[\d\w]+\s*(?:=|LIKE|<|>|<=|>=)\s*"
        r"[\(\s]*'?[\d\w]+)",
        # UNION-based
        r"(?i)(UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL[,\s]*)+|\(\s*SELECT\s+"
        r"(?:@@|VERSION))",
        r"(?i)(?:INTO\s+(?:OUTFILE|DUMPFILE)\s+'[^']+')",  # File operations
        r"(?i)(?:LOAD_FILE\s*\([^)]+\))",  # File reading
        r"(?i)(?:BENCHMARK\s*\(\s*\d+\s*,)",  # Time-based
        r"(?i)(?:SLEEP\s*\(\s*\d+\s*\))",  # Time-based
        # Comment-based
        r"(?i)(?:\/\*![0-9]*\s*(?:OR|AND|UNION|SELECT|INSERT|DELETE|DROP|"
        r"CONCAT|CHAR|UPDATE)\b)",

        # Directory Traversal - Enhanced patterns
        r"(?:\.\./|\.\\/){2,}",  # Multiple traversal
        # Sensitive files
        r"(?:/etc/(?:passwd|shadow|group|hosts|motd|issue|mysql/my.cnf|ssh/"
        r"ssh_config)$)",
        r"(?:boot\.ini|win\.ini|system\.ini|config\.sys)\s*$",  # Windows files
        r"(?:\/proc\/self\/environ$)",  # Process information
        r"(?:\/var\/log\/[^\/]+$)",  # Log files

        # Command Injection - Enhanced patterns
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

        # File Inclusion - Enhanced patterns
        # Protocols
        r"(?:php|data|zip|rar|file|glob|expect|input|phpinfo|zlib|phar|ssh2|"
        r"rar|ogg|expect)://[^\s]+",
        # URLs
        r"(?:\/\/[0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*(:(0-9)*)*(?:\/?)(?:"
        r"[a-zA-Z0-9\-\.\?,'/\\\+&amp;%\$#_]*)?)",

        # LDAP Injection - Enhanced patterns
        r"\(\s*[|&]\s*\(\s*[^)]+=[*]",  # Wildcards
        r"(?:\*(?:[\s\d\w]+\s*=|=\s*[\d\w\s]+))",  # Attribute matching
        r"(?:\(\s*[&|]\s*)",  # Logic operations

        # XML Injection - Enhanced patterns
        r"<!(?:ENTITY|DOCTYPE)[^>]+SYSTEM[^>]+>",  # XXE
        r"(?:<!\[CDATA\[.*?\]\]>)",  # CDATA sections
        r"(?:<\?xml.*?\?>)",  # XML declarations

        # SSRF - Enhanced patterns
        # Local addresses
        r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|[::]|(?:169\.254|192\.168|10\.|"
        r"172\.(?:1[6-9]|2[0-9]|3[01]))\.)",
        r"(?:file|dict|gopher|jar|tftp)://[^\s]+",  # Dangerous protocols

        # NoSQL Injection - Enhanced patterns
        # MongoDB
        r"\{\s*\$(?:where|gt|lt|ne|eq|regex|in|nin|all|size|exists|type|mod|"
        r"options):",
        r"(?:\{\s*\$[a-zA-Z]+\s*:\s*(?:\{|\[))",  # Nested operators

        # File Upload - Enhanced patterns
        r"(?i)filename=[\"'].*?\.(?:php\d*|phar|phtml|exe|jsp|asp|aspx|sh|"
        r"bash|rb|py|pl|cgi|com|bat|cmd|vbs|vbe|js|ws|wsf|msi|hta)[\"\']",

        # Path Traversal - Enhanced patterns
        # Encoded traversal
        r"(?:%2e%2e|%252e%252e|%uff0e%uff0e|%c0%ae%c0%ae|%e0%40%ae|%c0%ae"
        r"%e0%80%ae|%25c0%25ae)/",

        # Template Injection - New category
        # Basic template injection
        r"\{\{\s*[^\}]*(?:system|exec|popen|eval|require|include)\s*\}\}",
        # Alternative syntax
        r"\{\%\s*[^\%]*(?:system|exec|popen|eval|require|include)\s*\%\}",

        # HTTP Response Splitting - New category
        r"[\r\n]\s*(?:HTTP\/[0-9.]+|Location:|Set-Cookie:)",
    ]

    def __new__(cls):
        """
        Ensure only one instance of SusPatterns
        is created (singleton pattern).

        Returns:
            SusPatterns: The single instance
            of the SusPatterns class.
        """
        if cls._instance is None:
            cls._instance = super(
                SusPatterns,
                cls
            ).__new__(cls)
            cls._instance.compiled_patterns = [
                re.compile(
                    pattern,
                    re.IGNORECASE | re.MULTILINE
                )
                for pattern in cls.patterns
            ]
            cls._instance.compiled_custom_patterns = set()
        return cls._instance

    @classmethod
    async def add_pattern(
        cls,
        pattern: str,
        custom: bool = False
    ) -> None:
        """
        Add a new pattern to either the custom or
        default patterns list.

        Args:
            pattern (str): The pattern to be added.
            custom (bool, optional): If True, add
            to custom patterns; otherwise, add to
            default patterns. Defaults to False.
        """
        compiled_pattern = re.compile(
            pattern,
            re.IGNORECASE | re.MULTILINE
        )
        if custom:
            cls._instance.compiled_custom_patterns.add(
                compiled_pattern
            )
            cls._instance.custom_patterns.add(
                pattern
            )
        else:
            cls._instance.compiled_patterns.append(
                compiled_pattern
            )
            cls._instance.patterns.append(
                pattern
            )

    @classmethod
    async def remove_pattern(
        cls,
        pattern: str,
        custom: bool = False
    ) -> None:
        """
        Remove a pattern from either the
        custom or default patterns list.

        Args:
            pattern (str): The pattern to be removed.
            custom (bool, optional): If True, remove
            from custom patterns; otherwise, remove
            from default patterns. Defaults to False.
        """
        compiled_pattern = re.compile(
            pattern,
            re.IGNORECASE | re.MULTILINE
        )
        if custom:
            cls._instance.compiled_custom_patterns.discard(
                compiled_pattern
            )
            cls._instance.custom_patterns.discard(
                pattern
            )
        else:
            cls._instance.compiled_patterns = [
                p
                for p in cls._instance.compiled_patterns
                if p.pattern != pattern
            ]
            cls._instance.patterns = [
                p
                for p in cls._instance.patterns
                if p != pattern
            ]

    @classmethod
    async def get_all_patterns(
        cls
    ) -> List[str]:
        """
        Retrieve all patterns, including
        both default and custom patterns.

        Returns:
            List[str]: A list containing
            all default and custom patterns.
        """
        return cls._instance.patterns + list(
            cls._instance.custom_patterns
        )

    @classmethod
    async def get_all_compiled_patterns(
        cls
    ) -> List[re.Pattern]:
        """
        Retrieve all compiled patterns,
        including both default and custom patterns.

        Returns:
            List[re.Pattern]: A list containing
            all default and custom compiled patterns.
        """
        return cls._instance.compiled_patterns + list(
            cls._instance.compiled_custom_patterns
        )
