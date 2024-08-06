from typing import Set, List



class SusPatterns:
    """
    A singleton class that manages suspicious patterns for security checks.

    This class maintains two sets of patterns: default patterns and custom patterns.
    It provides methods to add, remove, and retrieve patterns.
    """

    _instance = None

    custom_patterns: Set[str] = set()

    patterns: List[str] = [
        # XSS
        r"<script.*?>.*?</script.*?>",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"alert\(",
        r"document\.cookie",
        r"document\.write",
        r"window\.location",

        # SQL Injection
        r"SELECT\s+.*\s+FROM\s+.*",
        r"UNION\s+SELECT\s+.*",
        r"'.*?OR.*?=.*?'",
        r"'.*?AND.*?=.*?'",
        r"INSERT\s+INTO\s+.*",
        r"UPDATE\s+.*\s+SET\s+.*",
        r"DELETE\s+FROM\s+.*",
        r"DROP\s+TABLE\s+.*",
        r"CREATE\s+TABLE\s+.*",
        r"ALTER\s+TABLE\s+.*",
        r"EXEC\s+.*",
        r"CAST\s*\(.*\s+AS\s+.*\)",
        r"CONVERT\s*\(.*\s+USING\s+.*\)",

        # Directory Traversal
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/group",
        r"/proc/self/environ",
        r"/windows/win.ini",
        r"/boot.ini",

        # Command Injection
        r"\b(?:ls|cat|rm|mv|cp|chmod|chown|sudo|su)\b",
        r"\b(?:wget|curl|nc|ncat|telnet|ssh|ftp)\b",
        r"\b(?:ping|traceroute|nslookup|dig)\b",
        r"\b(?:ifconfig|ipconfig|netstat)\b",
        r"\b(?:uname|whoami|id|pwd)\b",

        # Sensitive File Access
        r"\b(?:passwd|shadow|group)\b",
        r"\b(?:\.env|\.git|\.svn|\.hg|\.DS_Store)\b",
        r"\b(?:phpinfo|setup\.php|config\.php|admin\.php)\b",
        r"\b(?:sitemap\.xml|robots\.txt|security\.txt)\b",

        # Common Admin Paths
        r"\b(?:solr|admin|cgi-bin|wp-admin|wp-login)\b",

        # Common Query Parameters
        r"\b(?:query|show|diagnostics|status|action)\b",
        r"\b(?:format=json|wt=json)\b",

        # HTTP Method Tampering
        r"OPTIONS",
        r"TRACE",
        r"CONNECT",

        # Path Traversal
        r"\.\./",
        r"\.\.\\",

        # File Inclusion
        r"file://",
        r"php://",
        r"data://",
        r"zip://",
        r"rar://",
        r"expect://",

        # LDAP Injection
        r"\(\|\(.*?\=\*\)\)",
        r"\(\&\(.*?\=\*\)\)",

        # XML Injection
        r"<!DOCTYPE\s+.*?>",
        r"<\?xml\s+.*?>",
        r"<!ENTITY\s+.*?>",

        # SSRF (Server-Side Request Forgery)
        r"http://localhost",
        r"http://127\.0\.0\.1",
        r"http://169\.254\.169\.254",
        r"http://metadata\.google\.internal",

        # Open Redirect
        r"//",
        r"/\.\./",
        r"/\.\.\\",

        # CRLF Injection
        r"%0d%0a",
        r"%0d",
        r"%0a",

        # Path Manipulation
        r"\.\./",
        r"\.\.\\",

        # Shell Injection
        r";",
        r"&",
        r"\|",
        r"`",
        r"\$\(.*?\)",
        r"\$\{.*?\}",

        # NoSQL Injection
        r"\{\s*['\"]?\$.*?['\"]?\s*:\s*.*?\s*\}",

        # JSON Injection
        r"\{\s*\"\$.*?\"\s*:\s*.*?\s*\}",

        # HTTP Header Injection
        r"\r\n",
        r"\n",

        # File Upload
        r"Content-Disposition: form-data; name=\".*?\"; filename=\".*?\.(php|exe|sh|bat)\"",

        # Other
        r"eval\(",
        r"base64_decode\(",
        r"system\(",
        r"shell_exec\(",
        r"exec\(",
        r"popen\(",
        r"proc_open\(",
    ]

    def __new__(cls):
        """
        Ensure only one instance of SusPatterns is created (singleton pattern).

        Returns:
            SusPatterns: The single instance of the SusPatterns class.
        """
        if cls._instance is None:
            cls._instance = super(SusPatterns, cls).__new__(cls)
        return cls._instance

    @classmethod
    async def add_pattern(cls, pattern: str, custom: bool = False) -> None:
        """
        Add a new pattern to either the custom or default patterns list.

        Args:
            pattern (str): The pattern to be added.
            custom (bool, optional): If True, add to custom patterns; otherwise, add to default patterns. Defaults to False.
        """
        if custom:
            if pattern not in cls.custom_patterns:
                cls.custom_patterns.add(pattern)
        else:
            if pattern not in cls.patterns:
                cls.patterns.append(pattern)

    @classmethod
    async def remove_pattern(cls, pattern: str, custom: bool = False) -> None:
        """
        Remove a pattern from either the custom or default patterns list.

        Args:
            pattern (str): The pattern to be removed.
            custom (bool, optional): If True, remove from custom patterns; otherwise, remove from default patterns. Defaults to False.
        """
        if custom:
            if pattern in cls.custom_patterns:
                cls.custom_patterns.discard(pattern)
        else:
            if pattern in cls.patterns:
                cls.patterns.remove(pattern)

    @classmethod
    async def get_all_patterns(cls) -> List[str]:
        """
        Retrieve all patterns, including both default and custom patterns.

        Returns:
            List[str]: A list containing all default and custom patterns.
        """
        return cls.patterns + list(cls.custom_patterns)