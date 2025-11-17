"""
WAF Stressor - URL Variant Generation
Production-ready URL manipulation for comprehensive WAF testing

© GHOSTSHINOBI 2025
"""

import urllib.parse
import unicodedata
import re
from typing import List, Dict, Any, Optional, Set

from core import URLVariant, VariantType, Payload, TestProfile, HTTPMethod


class URLVariantGenerator:
    """
    Production-grade URL variant generator
    Generates comprehensive URL manipulation techniques for WAF bypass detection
    Fully deduplicated and profile-aware
    """

    def __init__(self, base_url: str, profile: TestProfile = TestProfile.LIGHT):
        self.base_url = base_url.rstrip('/')
        self.parsed = urllib.parse.urlparse(base_url)
        self.profile = profile
        self.variant_count = 0

    def generate_all_variants(self, payload: Optional[Payload] = None) -> List[URLVariant]:
        """
        Generate all URL variants based on profile with complete deduplication
        Returns unique variants only
        """
        variants = []
        seen_urls: Set[str] = set()

        # Always include baseline
        baseline = URLVariant(
            url=self.base_url,
            variant_type=VariantType.BASELINE,
            base_url=self.base_url,
            description="Baseline URL",
            payload=payload
        )
        variants.append(baseline)
        seen_urls.add(self.base_url)

        # Core variants (always tested)
        variant_generators = [
            self.trailing_slash_variants,
            self.case_variants,
            self.dot_segment_variants,
            self.double_slash_variants,
        ]

        # Deep scan additional variants
        if self.profile == TestProfile.DEEP:
            variant_generators.extend([
                self.matrix_param_variants,
                self.encoding_variants,
                self.unicode_variants,
                self.fragment_variants,
            ])

        # Generate all variants with deduplication
        for generator in variant_generators:
            for variant in generator(payload):
                if variant.url not in seen_urls:
                    variants.append(variant)
                    seen_urls.add(variant.url)

        # Query parameter variants (if payload present)
        if payload:
            for variant in self.query_variants(payload):
                if variant.url not in seen_urls:
                    variants.append(variant)
                    seen_urls.add(variant.url)

        self.variant_count = len(variants)
        return variants

    def trailing_slash_variants(self, payload: Optional[Payload] = None) -> List[URLVariant]:
        """Generate trailing slash variations"""
        variants = []

        # With trailing slash
        url_with_slash = self.base_url + '/'
        if payload:
            url_with_slash += f"?q={urllib.parse.quote(payload.raw)}"

        variants.append(URLVariant(
            url=url_with_slash,
            variant_type=VariantType.TRAILING_SLASH,
            base_url=self.base_url,
            description="URL with trailing slash",
            payload=payload
        ))

        # Without trailing slash (if base has one)
        if self.base_url.endswith('/'):
            url_without = self.base_url.rstrip('/')
            if payload:
                url_without += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url_without,
                variant_type=VariantType.TRAILING_SLASH,
                base_url=self.base_url,
                description="URL without trailing slash",
                payload=payload
            ))

        return variants

    def case_variants(self, payload: Optional[Payload] = None) -> List[URLVariant]:
        """Generate case sensitivity variants"""
        variants = []
        path = self.parsed.path or '/'

        if len(path) <= 1:
            return variants

        # Uppercase path
        url_upper = self._rebuild_url(path=path.upper())
        if payload:
            url_upper += f"?q={urllib.parse.quote(payload.raw)}"

        variants.append(URLVariant(
            url=url_upper,
            variant_type=VariantType.CASE_VARIATION,
            base_url=self.base_url,
            description="Uppercase path",
            payload=payload
        ))

        # Lowercase path
        url_lower = self._rebuild_url(path=path.lower())
        if payload:
            url_lower += f"?q={urllib.parse.quote(payload.raw)}"

        variants.append(URLVariant(
            url=url_lower,
            variant_type=VariantType.CASE_VARIATION,
            base_url=self.base_url,
            description="Lowercase path",
            payload=payload
        ))

        # Mixed case (alternating)
        if len(path) > 2:
            mixed_path = ''.join(
                c.upper() if i % 2 == 0 else c.lower()
                for i, c in enumerate(path)
            )
            url_mixed = self._rebuild_url(path=mixed_path)
            if payload:
                url_mixed += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url_mixed,
                variant_type=VariantType.CASE_VARIATION,
                base_url=self.base_url,
                description="Mixed case path (alternating)",
                payload=payload
            ))

        return variants

    def dot_segment_variants(self, payload: Optional[Payload] = None) -> List[URLVariant]:
        """Generate dot segment variants (. and ..)"""
        variants = []
        path = self.parsed.path or '/'

        if '/' not in path or path == '/':
            return variants

        path_parts = [p for p in path.split('/') if p]

        if len(path_parts) >= 1:
            # Add /./ (current directory - should normalize away)
            if len(path_parts) > 1:
                new_path = '/' + '/'.join(path_parts[:-1]) + '/./' + path_parts[-1]
            else:
                new_path = '/./' + path_parts[0]

            url = self._rebuild_url(path=new_path)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.DOT_SEGMENT,
                base_url=self.base_url,
                description="Path with /./ segment",
                payload=payload
            ))

        if len(path_parts) >= 2:
            # Add /../ (parent directory - neutral cancellation)
            new_path = '/' + '/'.join(path_parts[:-1]) + '/../' + path_parts[-1] + '/' + path_parts[-1]
            url = self._rebuild_url(path=new_path)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.DOT_SEGMENT,
                base_url=self.base_url,
                description="Path with /../ segment",
                payload=payload
            ))

            # Multiple dots
            new_path = '/' + './'.join(path_parts)
            url = self._rebuild_url(path=new_path)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.DOT_SEGMENT,
                base_url=self.base_url,
                description="Path with multiple ./ segments",
                payload=payload
            ))

        return variants

    def double_slash_variants(self, payload: Optional[Payload] = None) -> List[URLVariant]:
        """Generate double slash variants"""
        variants = []
        path = self.parsed.path or '/'

        if '/' not in path or path == '/':
            return variants

        # Replace single slashes with double
        new_path = path.replace('/', '//', 1)  # Only first occurrence
        url = self._rebuild_url(path=new_path)
        if payload:
            url += f"?q={urllib.parse.quote(payload.raw)}"

        variants.append(URLVariant(
            url=url,
            variant_type=VariantType.BACKSLASH,
            base_url=self.base_url,
            description="Path with double slash",
            payload=payload
        ))

        # Triple slash (deep profile only)
        if self.profile == TestProfile.DEEP:
            new_path = path.replace('/', '///', 1)
            url = self._rebuild_url(path=new_path)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.BACKSLASH,
                base_url=self.base_url,
                description="Path with triple slashes",
                payload=payload
            ))

        return variants

    def matrix_param_variants(self, payload: Optional[Payload] = None) -> List[URLVariant]:
        """Generate matrix parameter variants (RFC 3986)"""
        variants = []
        path = self.parsed.path or '/'

        # Standard session ID patterns
        session_ids = ['jsessionid=TEST123', 'phpsessid=abc123', 'sid=xyz789']

        for sid in session_ids:
            new_path = path + ';' + sid
            url = self._rebuild_url(path=new_path)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.PATH_PARAMETER,
                base_url=self.base_url,
                description=f"Path with matrix parameter ({sid.split('=')[0]})",
                payload=payload
            ))

        # Multiple matrix params
        new_path = path + ';param1=val1;param2=val2'
        url = self._rebuild_url(path=new_path)
        if payload:
            url += f"?q={urllib.parse.quote(payload.raw)}"

        variants.append(URLVariant(
            url=url,
            variant_type=VariantType.PATH_PARAMETER,
            base_url=self.base_url,
            description="Path with multiple matrix parameters",
            payload=payload
        ))

        return variants

    def encoding_variants(self, payload: Optional[Payload] = None) -> List[URLVariant]:
        """Generate percent-encoding variants"""
        variants = []
        path = self.parsed.path or '/'

        if not path or path == '/':
            return variants

        # Standard percent encoding
        encoded_path = urllib.parse.quote(path, safe='/')
        if encoded_path != path:
            url = self._rebuild_url(path=encoded_path)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.DOUBLE_ENCODING,
                base_url=self.base_url,
                description="Percent-encoded path",
                payload=payload
            ))

        # Double encoding
        double_encoded = urllib.parse.quote(encoded_path, safe='')
        if double_encoded != encoded_path:
            url = self._rebuild_url(path=double_encoded)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.DOUBLE_ENCODING,
                base_url=self.base_url,
                description="Double percent-encoded path",
                payload=payload
            ))

        # Encoding with uppercase hex
        if '%' in encoded_path:
            upper_hex = re.sub(r'%([0-9a-f]{2})', lambda m: f'%{m.group(1).upper()}', encoded_path)
            url = self._rebuild_url(path=upper_hex)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.MIXED_ENCODING,
                base_url=self.base_url,
                description="Uppercase hex percent-encoding",
                payload=payload
            ))

        return variants

    def unicode_variants(self, payload: Optional[Payload] = None) -> List[URLVariant]:
        """Generate Unicode normalization variants"""
        variants = []
        path = self.parsed.path or '/'

        # NFC normalization (composed)
        nfc_path = unicodedata.normalize('NFC', path)
        if nfc_path != path:
            url = self._rebuild_url(path=nfc_path)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.UNICODE_NORMALIZATION,
                base_url=self.base_url,
                description="Unicode NFC normalized",
                payload=payload
            ))

        # NFD normalization (decomposed)
        nfd_path = unicodedata.normalize('NFD', path)
        if nfd_path != path:
            url = self._rebuild_url(path=nfd_path)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.UNICODE_NORMALIZATION,
                base_url=self.base_url,
                description="Unicode NFD normalized",
                payload=payload
            ))

        # NFKC (compatibility composed)
        nfkc_path = unicodedata.normalize('NFKC', path)
        if nfkc_path != path and nfkc_path != nfc_path:
            url = self._rebuild_url(path=nfkc_path)
            if payload:
                url += f"?q={urllib.parse.quote(payload.raw)}"

            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.UNICODE_NORMALIZATION,
                base_url=self.base_url,
                description="Unicode NFKC normalized",
                payload=payload
            ))

        return variants

    def query_variants(self, payload: Payload) -> List[URLVariant]:
        """Generate query parameter variants with payload"""
        variants = []

        # Simple query with payload
        url = f"{self.base_url}?q={urllib.parse.quote(payload.raw)}"
        variants.append(URLVariant(
            url=url,
            variant_type=VariantType.QUERY_PARAM,
            base_url=self.base_url,
            description="Payload in query parameter",
            payload=payload
        ))

        # Multiple parameters (order variation)
        url = f"{self.base_url}?a=1&q={urllib.parse.quote(payload.raw)}&b=2"
        variants.append(URLVariant(
            url=url,
            variant_type=VariantType.QUERY_PARAM,
            base_url=self.base_url,
            description="Payload with surrounding parameters",
            payload=payload
        ))

        # Reverse order
        url = f"{self.base_url}?b=2&q={urllib.parse.quote(payload.raw)}&a=1"
        variants.append(URLVariant(
            url=url,
            variant_type=VariantType.QUERY_PARAM,
            base_url=self.base_url,
            description="Reversed parameter order",
            payload=payload
        ))

        # Duplicate parameters
        url = f"{self.base_url}?q={urllib.parse.quote(payload.raw)}&q=test"
        variants.append(URLVariant(
            url=url,
            variant_type=VariantType.QUERY_PARAM,
            base_url=self.base_url,
            description="Duplicate query parameters",
            payload=payload
        ))

        # Empty parameter
        url = f"{self.base_url}?q={urllib.parse.quote(payload.raw)}&empty="
        variants.append(URLVariant(
            url=url,
            variant_type=VariantType.QUERY_PARAM,
            base_url=self.base_url,
            description="Query with empty parameter",
            payload=payload
        ))

        # Payload in different common parameter names
        if self.profile == TestProfile.DEEP:
            for param_name in ['search', 'id', 'page', 'filter', 'data']:
                url = f"{self.base_url}?{param_name}={urllib.parse.quote(payload.raw)}"
                variants.append(URLVariant(
                    url=url,
                    variant_type=VariantType.QUERY_PARAM,
                    base_url=self.base_url,
                    description=f"Payload in '{param_name}' parameter",
                    payload=payload
                ))

        return variants

    def fragment_variants(self, payload: Optional[Payload] = None) -> List[URLVariant]:
        """Generate fragment identifier variants (client-side only, test server handling)"""
        variants = []

        if payload:
            # Fragment with payload (should be ignored by server)
            url = f"{self.base_url}#{urllib.parse.quote(payload.raw)}"
            variants.append(URLVariant(
                url=url,
                variant_type=VariantType.FRAGMENT,
                base_url=self.base_url,
                description="Payload in URL fragment",
                payload=payload
            ))

        return variants

    def _rebuild_url(self, path: Optional[str] = None, query: Optional[str] = None) -> str:
        """
        Rebuild URL with modified components
        Properly handles all URL parts with safe defaults
        """
        scheme = self.parsed.scheme or 'https'
        netloc = self.parsed.netloc
        new_path = path if path is not None else (self.parsed.path or '/')
        new_params = self.parsed.params
        new_query = query if query is not None else self.parsed.query
        new_fragment = ''  # Never include fragment in rebuilt URLs

        # Ensure path starts with /
        if new_path and not new_path.startswith('/'):
            new_path = '/' + new_path

        return urllib.parse.urlunparse((
            scheme,
            netloc,
            new_path,
            new_params,
            new_query,
            new_fragment
        ))

    def get_variant_stats(self) -> Dict[str, Any]:
        """Return statistics about generated variants"""
        return {
            'total_variants': self.variant_count,
            'profile': self.profile.value,
            'base_url': self.base_url,
            'parsed_components': {
                'scheme': self.parsed.scheme,
                'netloc': self.parsed.netloc,
                'path': self.parsed.path,
                'query': self.parsed.query
            }
        }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def normalize_url(url: str) -> str:
    """
    Normalize URL to canonical form for comparison
    Handles scheme, netloc, path, and query normalization
    """
    try:
        parsed = urllib.parse.urlparse(url)

        # Lowercase scheme and netloc
        scheme = parsed.scheme.lower() if parsed.scheme else 'https'
        netloc = parsed.netloc.lower()

        # Remove default ports
        if ':' in netloc:
            host, port = netloc.rsplit(':', 1)
            if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
                netloc = host

        # Normalize path
        path = parsed.path or '/'
        path = urllib.parse.unquote(path)
        path = urllib.parse.quote(path, safe='/')

        # Remove trailing slash (except for root)
        if path != '/' and path.endswith('/'):
            path = path.rstrip('/')

        # Sort query parameters for consistent comparison
        query = parsed.query
        if query:
            params = sorted(urllib.parse.parse_qsl(query))
            query = urllib.parse.urlencode(params)

        return urllib.parse.urlunparse((
            scheme,
            netloc,
            path,
            parsed.params,
            query,
            ''  # No fragment
        ))

    except Exception:
        return url


def extract_host_from_url(url: str) -> str:
    """Extract clean hostname from URL (without port)"""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(':')[0]
    except Exception:
        return ''


def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin (scheme + netloc)"""
    try:
        p1 = urllib.parse.urlparse(url1)
        p2 = urllib.parse.urlparse(url2)
        return (
            p1.scheme == p2.scheme and
            p1.netloc.lower() == p2.netloc.lower()
        )
    except Exception:
        return False


def extract_path_components(url: str) -> List[str]:
    """Extract path components from URL"""
    try:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or '/'
        return [p for p in path.split('/') if p]
    except Exception:
        return []


def build_url_with_query(base_url: str, params: Dict[str, str]) -> str:
    """Build URL with query parameters"""
    if not params:
        return base_url

    separator = '&' if '?' in base_url else '?'
    query_string = urllib.parse.urlencode(params)
    return f"{base_url}{separator}{query_string}"


__all__ = [
    'URLVariantGenerator',
    'normalize_url',
    'extract_host_from_url',
    'is_same_origin',
    'extract_path_components',
    'build_url_with_query'
]
