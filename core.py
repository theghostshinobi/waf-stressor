"""
WAF Stressor Core Module - Production-Ready Implementation
Data structures, enums, and configuration management
Complete with all dependencies required by engine, analysis, httpclientexec, urlops, reposys

© GHOSTSHINOBI 2025
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Set
from enum import Enum
import time
import hashlib


# ============================================================================
# ENUMS
# ============================================================================

class TestProfile(Enum):
    """Testing profiles with predefined configurations"""
    LIGHT = "light"
    DEEP = "deep"

    def get_config(self) -> Dict[str, Any]:
        """Get profile-specific configuration"""
        configs = {
            TestProfile.LIGHT: {
                "timeout": 10.0,
                "max_retries": 2,
                "requests_per_second": 1.0,
                "payload_limit": 50,
                "budget": 50,
            },
            TestProfile.DEEP: {
                "timeout": 30.0,
                "max_retries": 3,
                "requests_per_second": 0.5,
                "payload_limit": 200,
                "budget": 200,
            },
        }
        return configs[self]


class HTTPMethod(Enum):
    """HTTP methods for testing"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    # WebDAV methods
    PROPFIND = "PROPFIND"
    PROPPATCH = "PROPPATCH"
    MKCOL = "MKCOL"
    COPY = "COPY"
    MOVE = "MOVE"
    LOCK = "LOCK"
    UNLOCK = "UNLOCK"


class VariantType(Enum):
    """URL variant manipulation types"""
    BASELINE = "baseline"
    TRAILING_SLASH = "trailing_slash"
    CASE_VARIATION = "case_variation"
    DOUBLE_ENCODING = "double_encoding"
    PATH_PARAMETER = "path_parameter"
    FRAGMENT = "fragment"
    UNICODE_NORMALIZATION = "unicode_normalization"
    NULL_BYTE = "null_byte"
    DOT_SEGMENT = "dot_segment"
    BACKSLASH = "backslash"
    MIXED_ENCODING = "mixed_encoding"
    OVERLONG_UTF8 = "overlong_utf8"
    QUERY_PARAM = "query_param"
    HEADER_INJECTION = "header_injection"
    METHOD_OVERRIDE = "method_override"


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(Enum):
    """Types of vulnerabilities"""
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    COMMAND_INJECTION = "command_injection"
    TEMPLATE_INJECTION = "template_injection"
    UNKNOWN = "unknown"


# ============================================================================
# CONFIGURATION DATACLASSES
# ============================================================================

@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_second: float = 0.5
    burst_size: int = 5
    retry_delay: float = 1.0
    max_concurrent: int = 5
    max_retries: int = 3
    backoff_on_429: bool = True
    exponential_backoff_base: float = 2.0


@dataclass
class TestConfig:
    """Main test configuration"""
    target_url: str
    payload_file: str = "xss-payloads.txt"
    profile: TestProfile = TestProfile.LIGHT
    budget: int = 50
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    timeout: float = 10.0
    verify_tls: bool = False
    verify_ssl: bool = False  # Alias for backward compatibility
    custom_headers: Dict[str, str] = field(default_factory=dict)
    max_retries: int = 2
    follow_redirects: bool = True
    user_agent: str = "WAF-Stressor/1.0 (Security Testing)"
    max_redirects: int = 10

    def __post_init__(self):
        """Post-initialization validation and setup"""
        # Ensure URL has protocol
        if not self.target_url.startswith(('http://', 'https://')):
            self.target_url = f"https://{self.target_url}"

        # Sync TLS/SSL verification flags
        if self.verify_tls != self.verify_ssl:
            self.verify_ssl = self.verify_tls

        # Get profile config and apply defaults
        if hasattr(self.profile, 'get_config'):
            profile_config = self.profile.get_config()
            self.timeout = profile_config.get('timeout', self.timeout)
            self.max_retries = profile_config.get('max_retries', self.max_retries)
            if self.budget <= 0:
                self.budget = profile_config.get('budget', 50)


# ============================================================================
# PAYLOAD DATACLASS
# ============================================================================

@dataclass
class Payload:
    """Represents a test payload"""
    raw: str
    category: str = "generic"
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = "benign"

    def __hash__(self):
        return hash((self.raw, self.category))

    def __eq__(self, other):
        if not isinstance(other, Payload):
            return False
        return self.raw == other.raw and self.category == other.category


# ============================================================================
# HTTP REQUEST/RESPONSE DATACLASSES
# ============================================================================

@dataclass
class RequestConfig:
    """Configuration for a single HTTP request"""
    url: str
    method: HTTPMethod = HTTPMethod.GET
    headers: Dict[str, str] = field(default_factory=dict)
    payload: Optional[Payload] = None
    timeout: float = 10.0
    verify_tls: bool = False
    follow_redirects: bool = True
    max_redirects: int = 10
    body: Optional[str] = None
    json_data: Optional[Dict[str, Any]] = None


@dataclass
class ResponseSignature:
    """HTTP response signature for comparison and analysis"""
    status_code: int
    headers: Dict[str, str]
    body_hash: str
    body_length: int
    elapsed_time: float
    redirect_chain: List[str] = field(default_factory=list)
    server_header: Optional[str] = None
    content_type: Optional[str] = None

    @staticmethod
    def from_response(response, start_time: float) -> 'ResponseSignature':
        """Create signature from httpx.Response object"""
        headers_dict = dict(response.headers)
        body_hash = hashlib.sha256(response.content).hexdigest()

        redirect_chain = []
        if hasattr(response, 'history') and response.history:
            redirect_chain = [str(r.url) for r in response.history]

        return ResponseSignature(
            status_code=response.status_code,
            headers=headers_dict,
            body_hash=body_hash,
            body_length=len(response.content),
            elapsed_time=time.time() - start_time,
            redirect_chain=redirect_chain,
            server_header=headers_dict.get('server'),
            content_type=headers_dict.get('content-type')
        )

    def __eq__(self, other):
        if not isinstance(other, ResponseSignature):
            return False
        return (
            self.status_code == other.status_code and
            self.body_hash == other.body_hash
        )


# ============================================================================
# URL VARIANT DATACLASS
# ============================================================================

@dataclass
class URLVariant:
    """Represents a URL manipulation variant"""
    url: str
    variant_type: VariantType
    base_url: str
    description: str = ""
    payload: Optional[Payload] = None
    method: HTTPMethod = HTTPMethod.GET
    headers: Dict[str, str] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.url)

    def __eq__(self, other):
        if not isinstance(other, URLVariant):
            return False
        return self.url == other.url


# ============================================================================
# TEST RESULT DATACLASSES
# ============================================================================

@dataclass
class BaselineSnapshot:
    """Baseline behavior snapshot for comparison"""
    normal_signature: ResponseSignature
    blocked_signature: Optional[ResponseSignature] = None
    waf_detected: bool = False
    waf_fingerprint: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class TestResult:
    """Result of a single test execution"""
    url: str
    variant: URLVariant
    request_config: RequestConfig
    response_signature: ResponseSignature
    blocked: bool = False
    waf_detected: bool = False
    waf_name: Optional[str] = None
    anomaly_detected: bool = False
    timestamp: float = field(default_factory=time.time)
    error: Optional[str] = None

    @property
    def success(self) -> bool:
        """Test succeeded if no error occurred"""
        return self.error is None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'url': self.url,
            'variant_type': self.variant.variant_type.value,
            'method': self.request_config.method.value,
            'status_code': self.response_signature.status_code,
            'elapsed_time': self.response_signature.elapsed_time,
            'blocked': self.blocked,
            'waf_detected': self.waf_detected,
            'waf_name': self.waf_name,
            'anomaly_detected': self.anomaly_detected,
            'error': self.error,
            'timestamp': self.timestamp
        }


# ============================================================================
# METRICS DATACLASS
# ============================================================================

@dataclass
class TestMetrics:
    """Aggregated test metrics"""
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    error_requests: int = 0
    unique_status_codes: Set[int] = field(default_factory=set)
    avg_response_time: float = 0.0
    min_response_time: float = 0.0
    max_response_time: float = 0.0

    # WAF bypass metrics
    normalization_factor: float = 0.0  # NF
    mutation_potency: float = 0.0  # MP
    payload_penetration: float = 0.0  # PP
    consistency_coefficient: float = 0.0  # CC
    status_code_variance: float = 0.0  # SC
    uniformity_index: float = 0.0  # UI

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_requests': self.total_requests,
            'blocked_requests': self.blocked_requests,
            'allowed_requests': self.allowed_requests,
            'error_requests': self.error_requests,
            'unique_status_codes': list(self.unique_status_codes),
            'avg_response_time': self.avg_response_time,
            'min_response_time': self.min_response_time,
            'max_response_time': self.max_response_time,
            'normalization_factor': self.normalization_factor,
            'mutation_potency': self.mutation_potency,
            'payload_penetration': self.payload_penetration,
            'consistency_coefficient': self.consistency_coefficient,
            'status_code_variance': self.status_code_variance,
            'uniformity_index': self.uniformity_index
        }


# ============================================================================
# FINDINGS DATACLASS
# ============================================================================

@dataclass
class Finding:
    """Single vulnerability finding"""
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    payload: str
    response: str
    response_code: int
    elapsed_time: float
    url: str
    detected_waf: bool = False
    variant_type: Optional[VariantType] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'type': self.vulnerability_type.value,
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'payload': self.payload,
            'response': self.response[:500],  # Truncate for storage
            'response_code': self.response_code,
            'elapsed_time': self.elapsed_time,
            'url': self.url,
            'detected_waf': self.detected_waf,
            'variant_type': self.variant_type.value if self.variant_type else None
        }


# ============================================================================
# SCAN REPORT DATACLASS
# ============================================================================

@dataclass
class ScanReport:
    """Complete scan report"""
    target_url: str
    profile: TestProfile
    start_time: float
    end_time: Optional[float] = None
    results: List[TestResult] = field(default_factory=list)
    baseline: Optional[BaselineSnapshot] = None
    metrics: Optional[TestMetrics] = None
    findings: List[Finding] = field(default_factory=list)
    waf_fingerprint: Optional[str] = None

    @property
    def elapsed_time(self) -> float:
        """Total scan duration"""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    @property
    def total_requests(self) -> int:
        """Total number of requests made"""
        return len(self.results)

    @property
    def success_rate(self) -> float:
        """Percentage of successful requests"""
        if not self.results:
            return 0.0
        successful = sum(1 for r in self.results if r.success)
        return (successful / len(self.results)) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'target_url': self.target_url,
            'profile': self.profile.value,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'elapsed_time': self.elapsed_time,
            'total_requests': self.total_requests,
            'success_rate': self.success_rate,
            'results': [r.to_dict() for r in self.results],
            'metrics': self.metrics.to_dict() if self.metrics else {},
            'findings': [f.to_dict() for f in self.findings],
            'waf_fingerprint': self.waf_fingerprint
        }


# ============================================================================
# LEGACY SUPPORT CLASSES
# ============================================================================

class ScanResult:
    """Complete scan result for a target (legacy support)"""
    def __init__(self, target: str, profile: TestProfile):
        self.target = target
        self.profile = profile
        self.findings: List[Finding] = []
        self.requests_made = 0
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.waf_detected = False
        self.waf_fingerprint: Optional[str] = None
        self.metrics: Dict[str, Any] = {}

    def add_finding(self, finding: Finding):
        """Add a vulnerability finding"""
        self.findings.append(finding)

    def finish(self):
        """Mark scan as finished"""
        self.end_time = time.time()

    @property
    def elapsed_time(self) -> float:
        """Get total elapsed time"""
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def critical_findings(self) -> List[Finding]:
        """Get critical findings"""
        return [f for f in self.findings if f.severity == SeverityLevel.CRITICAL]

    @property
    def high_findings(self) -> List[Finding]:
        """Get high severity findings"""
        return [f for f in self.findings if f.severity == SeverityLevel.HIGH]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'target': self.target,
            'profile': self.profile.value,
            'findings': [f.to_dict() for f in self.findings],
            'total_findings': len(self.findings),
            'critical': len(self.critical_findings),
            'high': len(self.high_findings),
            'requests_made': self.requests_made,
            'elapsed_time': self.elapsed_time,
            'waf_detected': self.waf_detected,
            'waf_fingerprint': self.waf_fingerprint,
            'metrics': self.metrics,
        }


class BatchConfig:
    """Batch scanning configuration"""
    def __init__(self, targets: List[str], payloads_file: str,
                 output_dir: str, profile: TestProfile):
        self.targets = targets
        self.payloads_file = payloads_file
        self.output_dir = output_dir
        self.profile = profile
        self.results: List[ScanResult] = []

    def add_result(self, result: ScanResult):
        """Add scan result"""
        self.results.append(result)

    @property
    def total_findings(self) -> int:
        """Total findings across all targets"""
        return sum(len(r.findings) for r in self.results)

    @property
    def critical_findings(self) -> int:
        """Critical findings across all targets"""
        return sum(len(r.critical_findings) for r in self.results)


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Enums
    'TestProfile',
    'HTTPMethod',
    'VariantType',
    'SeverityLevel',
    'VulnerabilityType',

    # Configuration
    'RateLimitConfig',
    'TestConfig',

    # Payload
    'Payload',

    # Request/Response
    'RequestConfig',
    'ResponseSignature',
    'URLVariant',

    # Results
    'BaselineSnapshot',
    'TestResult',
    'TestMetrics',
    'Finding',
    'ScanReport',

    # Legacy
    'ScanResult',
    'BatchConfig',
]
