class SusPatterns:
    _instance = None

    custom_patterns = []

    patterns = [
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
        if cls._instance is None:
            cls._instance = super(SusPatterns, cls).__new__(cls)
        return cls._instance

    @classmethod
    def add_pattern(cls, pattern: str):
        if pattern not in cls.patterns:
            cls.patterns.append(pattern)

    @classmethod
    def remove_pattern(cls, pattern: str):
        if pattern in cls.patterns:
            cls.patterns.remove(pattern)
