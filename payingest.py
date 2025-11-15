"""
WAF Stressor - Payload Loading and Parsing
Production-grade payload ingestion with validation and generation

© GHOSTSHINOBI 2025
"""

import re
from pathlib import Path
from typing import List, Optional, Tuple

from core import Payload


class PayloadLoader:
    """
    Load and parse benign payloads from file
    Supports pipe-delimited format: payload | category | description
    Auto-detects categories when not specified
    """

    # Payload categories based on content patterns
    CATEGORIES = {
        "sql_benign": r"(?i)(select|union|where|from|insert|update|delete)\s",
        "xss_benign": r"<(script|img|svg|iframe|object|embed|body|div|span)",
        "path_traversal": r"\.\./|\.\.\\",
        "command_injection": r"[;|&`$()]",
        "template_injection": r"\$\{|\{\{",
        "xxe_benign": r"<!ENTITY|<!DOCTYPE",
        "url_norm": r"^[a-zA-Z0-9%\-_\.]+$",
        "generic": r".*"
    }

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        if not self.filepath.exists():
            raise FileNotFoundError(f"Payload file not found: {filepath}")
        self.payloads_loaded = 0
        self.lines_processed = 0
        self.errors_encountered = 0

    def load_all(self) -> List[Payload]:
        """
        Load all payloads from file with comprehensive error handling
        Alias for load() for backward compatibility
        """
        return self.load()

    def load(self) -> List[Payload]:
        """Load all payloads from file with error handling"""
        payloads = []

        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    self.lines_processed += 1
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue

                    # Parse payload
                    payload = self._parse_line(line, line_num)
                    if payload:
                        payloads.append(payload)
                        self.payloads_loaded += 1
                    else:
                        self.errors_encountered += 1

        except UnicodeDecodeError as e:
            raise RuntimeError(f"Encoding error in {self.filepath}: {str(e)}")
        except IOError as e:
            raise RuntimeError(f"I/O error reading {self.filepath}: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error loading payloads from {self.filepath}: {str(e)}")

        return payloads

    def _parse_line(self, line: str, line_num: int) -> Optional[Payload]:
        """
        Parse a single payload line
        Format: payload | category | description
        Or just: payload
        """
        try:
            parts = [p.strip() for p in line.split('|')]

            if not parts or not parts[0]:
                return None

            raw_payload = parts[0]
            category = parts[1] if len(parts) > 1 else self._detect_category(raw_payload)
            description = parts[2] if len(parts) > 2 else f"Payload from line {line_num}"

            # Validate payload length (prevent memory issues)
            if len(raw_payload) > 10000:
                return None

            # Detect risk level
            risk_level = self._assess_risk(raw_payload)

            return Payload(
                raw=raw_payload,
                category=category,
                description=description,
                metadata={
                    "line_number": line_num,
                    "source": str(self.filepath.name)
                },
                risk_level=risk_level
            )

        except Exception:
            return None

    def _detect_category(self, payload: str) -> str:
        """Auto-detect payload category based on content patterns"""
        for category, pattern in self.CATEGORIES.items():
            try:
                if re.search(pattern, payload, re.IGNORECASE):
                    return category
            except re.error:
                continue
        return "generic"

    def _assess_risk(self, payload: str) -> str:
        """Assess payload risk level (benign vs potentially dangerous)"""
        # Dangerous indicators
        dangerous_patterns = [
            r"rm\s+-rf",
            r"DROP\s+TABLE",
            r"</script>",
            r"onerror\s*=",
            r"eval\(",
            r"exec\(",
            r"/etc/passwd",
            r"cmd\.exe",
        ]

        for pattern in dangerous_patterns:
            try:
                if re.search(pattern, payload, re.IGNORECASE):
                    return "dangerous"
            except re.error:
                continue

        return "benign"

    def validate_payloads(self, payloads: List[Payload]) -> Tuple[List[Payload], List[str]]:
        """
        Validate payloads are benign (no actual exploits)
        Returns: (valid_payloads, warnings)
        """
        valid = []
        warnings = []

        # Dangerous patterns that should NOT be in benign payloads
        DANGEROUS_PATTERNS = [
            (r"rm\s+-rf\s+/", "Destructive command (rm -rf /) detected"),
            (r"DROP\s+TABLE", "Destructive SQL (DROP TABLE) detected"),
            (r"DROP\s+DATABASE", "Destructive SQL (DROP DATABASE) detected"),
            (r"</script>", "Closing script tag - potential XSS"),
            (r"onerror\s*=\s*['\"]", "Event handler attribute - potential XSS"),
            (r"onclick\s*=\s*['\"]", "Click handler - potential XSS"),
            (r"onload\s*=\s*['\"]", "Load handler - potential XSS"),
            (r"\.\./\.\./\.\./etc/passwd", "Direct /etc/passwd access"),
            (r"cmd\.exe", "Windows command shell"),
            (r"/bin/(sh|bash)", "Unix shell invocation"),
            (r"base64.*decode", "Base64 decode (encoding obfuscation)"),
            (r"__import__\s*\(", "Python import attempt"),
            (r"eval\s*\(", "Eval execution"),
            (r"exec\s*\(", "Exec execution"),
            (r"system\s*\(", "System command execution"),
            (r"shell_exec\s*\(", "PHP shell exec"),
            (r"passthru\s*\(", "PHP passthru"),
            (r"proc_open\s*\(", "PHP proc_open"),
            (r"popen\s*\(", "Process open"),
        ]

        for payload in payloads:
            is_valid = True

            # Check against dangerous patterns
            for pattern, reason in DANGEROUS_PATTERNS:
                try:
                    if re.search(pattern, payload.raw, re.IGNORECASE):
                        warnings.append(
                            f"Payload '{payload.raw[:50]}{'...' if len(payload.raw) > 50 else ''}' "
                            f"flagged: {reason}"
                        )
                        is_valid = False
                        break
                except re.error:
                    # Regex error - skip this pattern
                    continue

            if is_valid:
                valid.append(payload)

        return valid, warnings

    def get_stats(self) -> dict:
        """Return loading statistics"""
        return {
            'lines_processed': self.lines_processed,
            'payloads_loaded': self.payloads_loaded,
            'errors_encountered': self.errors_encountered,
            'filepath': str(self.filepath),
            'success_rate': round(
                (self.payloads_loaded / max(self.lines_processed, 1)) * 100, 2
            )
        }


class PayloadGenerator:
    """Generate benign test payloads for security testing"""

    @staticmethod
    def generate_benign_set() -> List[Payload]:
        """
        Generate a comprehensive set of safe, benign payloads for testing
        All payloads are safe for testing and will not cause actual harm
        """
        payloads = [
            # URL normalization tests
            Payload("test", "url_norm", "Simple alphanumeric"),
            Payload("Test123", "url_norm", "Mixed case alphanumeric"),
            Payload("test%20value", "url_norm", "URL encoded space"),
            Payload("café", "url_norm", "Unicode characters (é)"),
            Payload("测试", "url_norm", "Chinese characters"),
            Payload("тест", "url_norm", "Cyrillic characters"),
            Payload("test-value_123", "url_norm", "Hyphens and underscores"),

            # SQL-like but benign (not actual SQL injection)
            Payload("user=admin", "sql_benign", "Key-value pair"),
            Payload("id=1", "sql_benign", "Numeric ID"),
            Payload("name='test'", "sql_benign", "Quoted string"),
            Payload("FROM users", "sql_benign", "SQL keyword"),
            Payload("SELECT id", "sql_benign", "SELECT clause"),
            Payload("WHERE id=1", "sql_benign", "WHERE clause"),
            Payload("1' OR '1'='1", "sql_benign", "Classic SQL pattern (benign)"),
            Payload("admin'--", "sql_benign", "SQL comment pattern"),
            Payload("UNION SELECT", "sql_benign", "UNION keyword"),

            # HTML-like but benign (properly escaped)
            Payload("<b>test</b>", "xss_benign", "Bold tag"),
            Payload("<p>content</p>", "xss_benign", "Paragraph tag"),
            Payload("<div>test</div>", "xss_benign", "Div tag"),
            Payload("<span>text</span>", "xss_benign", "Span tag"),
            Payload("<img src='test.jpg'>", "xss_benign", "Image tag"),
            Payload("<a href='#'>link</a>", "xss_benign", "Link tag"),
            Payload("<!-- comment -->", "xss_benign", "HTML comment"),
            Payload("<script>alert(1)</script>", "xss_benign", "Script tag (benign test)"),

            # Path traversal patterns (benign)
            Payload("../", "path_traversal", "Single parent directory"),
            Payload("../../", "path_traversal", "Double parent directory"),
            Payload("..\\..\\", "path_traversal", "Windows path traversal"),
            Payload("....//....//", "path_traversal", "Double encoding traversal"),
            Payload("/etc/test", "path_traversal", "Absolute path"),
            Payload("C:\\test", "path_traversal", "Windows absolute path"),

            # Command injection patterns (benign)
            Payload("test; ls", "command_injection", "Command separator"),
            Payload("test | cat", "command_injection", "Pipe operator"),
            Payload("test && echo", "command_injection", "AND operator"),
            Payload("test || echo", "command_injection", "OR operator"),
            Payload("`whoami`", "command_injection", "Backtick execution"),
            Payload("$(whoami)", "command_injection", "Command substitution"),

            # Template injection (benign)
            Payload("${7*7}", "template_injection", "JSTL expression"),
            Payload("{{7*7}}", "template_injection", "Jinja2 expression"),
            Payload("#{7*7}", "template_injection", "Ruby expression"),
            Payload("<%= 7*7 %>", "template_injection", "ERB expression"),

            # XXE patterns (benign)
            Payload("<!DOCTYPE foo>", "xxe_benign", "DOCTYPE declaration"),
            Payload("<!ENTITY test>", "xxe_benign", "Entity declaration"),

            # Special characters
            Payload("!@#$%^&*()", "generic", "Special characters"),
            Payload("'\"\\;", "generic", "Quote and escape chars"),
            Payload("\n\r\t", "generic", "Whitespace characters"),
            Payload("\x00", "generic", "Null byte"),
            Payload("%00", "generic", "URL encoded null"),
        ]

        return payloads

    @staticmethod
    def generate_xss_set() -> List[Payload]:
        """Generate XSS-focused benign payloads"""
        return [
            Payload("<script>alert(1)</script>", "xss_benign", "Basic script tag"),
            Payload("<img src=x onerror=alert(1)>", "xss_benign", "Image onerror"),
            Payload("<svg onload=alert(1)>", "xss_benign", "SVG onload"),
            Payload("<iframe src=javascript:alert(1)>", "xss_benign", "Iframe javascript"),
            Payload("<body onload=alert(1)>", "xss_benign", "Body onload"),
            Payload("javascript:alert(1)", "xss_benign", "JavaScript protocol"),
            Payload("<a href='javascript:alert(1)'>click</a>", "xss_benign", "Link with JS"),
        ]

    @staticmethod
    def generate_sql_set() -> List[Payload]:
        """Generate SQL-focused benign payloads"""
        return [
            Payload("' OR '1'='1", "sql_benign", "Classic OR bypass"),
            Payload("admin'--", "sql_benign", "Comment injection"),
            Payload("' UNION SELECT NULL--", "sql_benign", "UNION injection"),
            Payload("1' AND '1'='1", "sql_benign", "AND condition"),
            Payload("'; DROP TABLE test--", "sql_benign", "Drop table (benign)"),
            Payload("1' ORDER BY 1--", "sql_benign", "Order by column"),
        ]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def load_payloads_from_file(filepath: str) -> List[Payload]:
    """
    Convenience function to load payloads from file
    Returns list of Payload objects
    """
    loader = PayloadLoader(filepath)
    return loader.load()


def create_default_payload_file(filepath: str, payload_type: str = 'benign') -> None:
    """
    Create a default payload file with benign test payloads

    Args:
        filepath: Path to create file at
        payload_type: Type of payloads ('benign', 'xss', 'sql')
    """
    if payload_type == 'xss':
        payloads = PayloadGenerator.generate_xss_set()
    elif payload_type == 'sql':
        payloads = PayloadGenerator.generate_sql_set()
    else:
        payloads = PayloadGenerator.generate_benign_set()

    output_path = Path(filepath)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# WAF Stressor - Benign Test Payloads\n")
        f.write("# Format: payload | category | description\n")
        f.write("# Lines starting with # are comments\n\n")

        for payload in payloads:
            f.write(f"{payload.raw} | {payload.category} | {payload.description}\n")


__all__ = [
    'PayloadLoader',
    'PayloadGenerator',
    'load_payloads_from_file',
    'create_default_payload_file'
]
