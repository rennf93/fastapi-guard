# guard/detection_engine/semantic.py
import ast
import re
from collections import Counter
from typing import Any


class SemanticAnalyzer:
    """
    Bypass-resistant semantic analysis for attack detection.

    This class provides semantic analysis capabilities that can detect
    attacks regardless of padding or other evasion techniques that
    exploit bounded quantifier limitations.
    """

    def __init__(self) -> None:
        """Initialize the SemanticAnalyzer."""
        # Attack keywords grouped by category
        self.attack_keywords = {
            "xss": {
                "script",
                "javascript",
                "onerror",
                "onload",
                "onclick",
                "onmouseover",
                "alert",
                "eval",
                "document",
                "cookie",
                "window",
                "location",
            },
            "sql": {
                "select",
                "union",
                "insert",
                "update",
                "delete",
                "drop",
                "from",
                "where",
                "order",
                "group",
                "having",
                "concat",
                "substring",
                "database",
                "table",
                "column",
            },
            "command": {
                "exec",
                "system",
                "shell",
                "cmd",
                "bash",
                "powershell",
                "wget",
                "curl",
                "nc",
                "netcat",
                "chmod",
                "chown",
                "sudo",
                "passwd",
            },
            "path": {"etc", "passwd", "shadow", "hosts", "proc", "boot", "win", "ini"},
            "template": {
                "render",
                "template",
                "jinja",
                "mustache",
                "handlebars",
                "ejs",
                "pug",
                "twig",
            },
        }

        # Suspicious character patterns
        self.suspicious_chars = {
            "brackets": r"[<>{}()\[\]]",
            "quotes": r"['\"`]",
            "slashes": r"[/\\]",
            "special": r"[;&|$]",
            "wildcards": r"[*?]",
        }

        # Common attack structures
        self.attack_structures = {
            "tag_like": r"<[^>]+>",
            "function_call": r"\w+\s*\([^)]*\)",
            "command_chain": r"[;&|]{1,2}",
            "path_traversal": r"\.{2,}[/\\]",
            "url_pattern": r"[a-z]+://",
        }

    def extract_tokens(self, content: str) -> list[str]:
        """
        Extract meaningful tokens from content.

        Args:
            content: The content to tokenize

        Returns:
            List of tokens
        """
        # Limit content length
        MAX_CONTENT_LENGTH = 50000
        if len(content) > MAX_CONTENT_LENGTH:
            content = content[:MAX_CONTENT_LENGTH]

        # Remove excessive whitespace
        content = re.sub(r"\s+", " ", content)

        # Extract alphanumeric tokens with limit
        MAX_TOKENS = 1000
        tokens = re.findall(r"\b\w+\b", content.lower())[:MAX_TOKENS]

        # Also extract special patterns with timeout
        special_patterns = []
        import concurrent.futures

        for _, pattern in self.attack_structures.items():

            def _find_pattern(p: str, c: str) -> list[str]:
                return re.findall(p, c, re.IGNORECASE)[:10]  # Limit matches

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_find_pattern, pattern, content)
                try:
                    matches = future.result(timeout=0.1)  # 100ms timeout
                    special_patterns.extend(matches)
                except concurrent.futures.TimeoutError:
                    # Skip pattern if timeout
                    continue

            if len(special_patterns) >= 50:  # Limit special patterns
                break

        return (tokens + special_patterns)[:MAX_TOKENS]

    def calculate_entropy(self, content: str) -> float:
        """
        Calculate Shannon entropy of content.

        High entropy might indicate obfuscation or encoding.

        Args:
            content: The content to analyze

        Returns:
            Entropy value
        """
        if not content:
            return 0.0

        # Limit content length to prevent DoS
        MAX_ENTROPY_LENGTH = 10000
        if len(content) > MAX_ENTROPY_LENGTH:
            content = content[:MAX_ENTROPY_LENGTH]

        # Count character frequencies
        char_counts = Counter(content)
        length = len(content)

        # Calculate entropy
        import math

        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                # Use proper Shannon entropy formula
                entropy -= probability * math.log2(probability)

        return entropy

    def detect_encoding_layers(self, content: str) -> int:
        """
        Detect potential encoding layers.

        Args:
            content: The content to analyze

        Returns:
            Number of detected encoding layers
        """
        # Limit content length
        MAX_SCAN_LENGTH = 10000
        if len(content) > MAX_SCAN_LENGTH:
            content = content[:MAX_SCAN_LENGTH]

        layers = 0

        # Check for URL encoding
        if re.search(r"%[0-9a-fA-F]{2}", content):
            layers += 1

        # Check for base64
        if re.search(r"[A-Za-z0-9+/]{4,}={0,2}", content):
            layers += 1

        # Check for hex encoding
        if re.search(r"(?:0x)?[0-9a-fA-F]{4,}", content):
            layers += 1

        # Check for unicode encoding
        if re.search(r"\\u[0-9a-fA-F]{4}", content):
            layers += 1

        # Check for HTML entities
        if re.search(r"&[#\w]+;", content):
            layers += 1

        return layers

    def analyze_attack_probability(self, content: str) -> dict[str, float]:
        """
        Analyze the probability of different attack types.

        Args:
            content: The content to analyze

        Returns:
            Dictionary of attack type to probability scores
        """
        tokens = self.extract_tokens(content)
        token_set = set(tokens)
        probabilities = {}

        for attack_type, keywords in self.attack_keywords.items():
            # Count keyword matches
            matches = len(token_set.intersection(keywords))
            total_keywords = len(keywords)

            # Calculate base score
            if total_keywords > 0:
                score = matches / total_keywords
            else:
                score = 0.0

            # Boost score based on structural patterns
            if attack_type == "xss" and re.search(r"<[^>]+>", content):
                score += 0.3
            elif attack_type == "sql" and re.search(
                r"\b(?:union|select|from|where)\b", content, re.IGNORECASE
            ):
                score += 0.3
            elif attack_type == "command" and re.search(r"[;&|]", content):
                score += 0.3
            elif attack_type == "path" and re.search(r"\.{2,}[/\\]", content):
                score += 0.3

            # Cap at 1.0
            probabilities[attack_type] = min(score, 1.0)

        return probabilities

    def detect_obfuscation(self, content: str) -> bool:
        """
        Detect if content appears to be obfuscated.

        Args:
            content: The content to analyze

        Returns:
            True if obfuscation is detected
        """
        # High entropy indicates possible obfuscation
        if self.calculate_entropy(content) > 4.5:
            return True

        # Multiple encoding layers
        if self.detect_encoding_layers(content) > 2:
            return True

        # Excessive special characters
        special_char_ratio = len(re.findall(r"[^a-zA-Z0-9\s]", content)) / max(
            len(content), 1
        )
        if special_char_ratio > 0.4:
            return True

        # Long strings without spaces
        if re.search(r"\S{100,}", content):
            return True

        return False

    def extract_suspicious_patterns(self, content: str) -> list[dict[str, Any]]:
        """
        Extract specific suspicious patterns with context.

        Args:
            content: The content to analyze

        Returns:
            List of suspicious patterns with metadata
        """
        patterns = []

        # Check for each suspicious pattern
        for name, pattern in self.attack_structures.items():
            for match in re.finditer(pattern, content, re.IGNORECASE):
                context_start = max(0, match.start() - 20)
                context_end = min(len(content), match.end() + 20)
                patterns.append(
                    {
                        "type": name,
                        "pattern": match.group(),
                        "position": match.start(),
                        "context": content[context_start:context_end],
                    }
                )

        return patterns

    def analyze_code_injection_risk(self, content: str) -> float:
        """
        Analyze risk of code injection.

        Args:
            content: The content to analyze

        Returns:
            Risk score (0.0 to 1.0)
        """
        risk_score = 0.0

        # Check for code-like patterns
        if re.search(r"[\{\}].*[\{\}]", content):
            risk_score += 0.2

        # Check for function calls
        if re.search(r"\w+\s*\([^)]*\)", content):
            risk_score += 0.2

        # Check for variable references
        if re.search(r"[$@]\w+", content):
            risk_score += 0.1

        # Check for operators
        if re.search(r"[=+\-*/]{2,}", content):
            risk_score += 0.1

        # Try to parse as Python code (catches many injection attempts)
        # Limit AST parsing to prevent DoS
        MAX_AST_LENGTH = 1000
        try:
            if len(content) <= MAX_AST_LENGTH:
                # Use timeout for AST parsing
                import concurrent.futures

                def _parse_ast() -> bool:
                    try:
                        # Use mode='eval' to be extra safe - only allows expressions
                        tree = ast.parse(content, mode="eval")
                        # Check for dangerous nodes
                        for node in ast.walk(tree):
                            # Check for potentially dangerous AST nodes
                            if isinstance(
                                node,
                                ast.Import
                                | ast.ImportFrom
                                | ast.FunctionDef
                                | ast.AsyncFunctionDef
                                | ast.ClassDef,
                            ):
                                # These shouldn't appear in eval mode anyway
                                return True
                        return True
                    except SyntaxError:
                        # Not valid Python - this is normal
                        return False
                    except Exception:
                        # Other parsing errors
                        return False

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(_parse_ast)
                    try:
                        if future.result(timeout=0.1):  # 100ms timeout
                            risk_score += 0.3
                    except concurrent.futures.TimeoutError:
                        # Assume dangerous if parsing times out
                        risk_score += 0.2
        except Exception:  # pragma: no cover
            # AST parsing failed - this is expected for malformed code
            # There's already the risk score for timeout, so just continue
            pass

        # Check for common injection keywords
        injection_keywords = [
            "eval",
            "exec",
            "compile",
            "__import__",
            "globals",
            "locals",
        ]
        for keyword in injection_keywords:
            if re.search(rf"\b{keyword}\b", content, re.IGNORECASE):
                risk_score += 0.2
                break

        return min(risk_score, 1.0)

    def analyze(self, content: str) -> dict[str, Any]:
        """
        Perform comprehensive semantic analysis.

        Args:
            content: The content to analyze

        Returns:
            Analysis results dictionary
        """
        return {
            "attack_probabilities": self.analyze_attack_probability(content),
            "entropy": self.calculate_entropy(content),
            "encoding_layers": self.detect_encoding_layers(content),
            "is_obfuscated": self.detect_obfuscation(content),
            "suspicious_patterns": self.extract_suspicious_patterns(content),
            "code_injection_risk": self.analyze_code_injection_risk(content),
            "token_count": len(self.extract_tokens(content)),
        }

    def get_threat_score(self, analysis_results: dict[str, Any]) -> float:
        """
        Calculate overall threat score from analysis results.

        Args:
            analysis_results: Results from analyze() method

        Returns:
            Overall threat score (0.0 to 1.0)
        """
        score = 0.0

        # Weight attack probabilities
        attack_probs = analysis_results.get("attack_probabilities", {})
        if attack_probs:
            max_prob = max(attack_probs.values())
            score += max_prob * 0.3

        # Weight obfuscation
        if analysis_results.get("is_obfuscated", False):
            score += 0.2

        # Weight encoding layers
        encoding_layers = analysis_results.get("encoding_layers", 0)
        if encoding_layers > 0:
            score += min(encoding_layers * 0.1, 0.2)

        # Weight code injection risk
        injection_risk = analysis_results.get("code_injection_risk", 0.0)
        score += injection_risk * 0.2

        # Weight suspicious patterns
        patterns = analysis_results.get("suspicious_patterns", [])
        if patterns:
            score += min(len(patterns) * 0.05, 0.1)

        return float(min(score, 1.0))
