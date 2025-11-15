"""
WAF Stressor - HTTP Client and Request Execution
Production-ready HTTP client with comprehensive error handling and rate limiting

© GHOSTSHINOBI 2025
"""

import httpx
import hashlib
import time
import json
from typing import Optional, Dict, Any
from urllib.parse import urlencode

from core import RequestConfig, HTTPMethod, TestConfig


class SecureHTTPClient:
    """
    Production-grade HTTP client with:
    - Rate limiting with exponential backoff
    - Budget enforcement
    - Retry logic with 429 handling
    - Full HTTP method support (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS)
    - WebDAV method support (PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, TRACE)
    - TLS verification control
    - Connection pooling and keepalive
    - Comprehensive error handling
    """

    # WebDAV and extended HTTP methods
    WEBDAV_METHODS = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'TRACE']

    def __init__(self, config: TestConfig):
        self.config = config
        self.client = self._create_client()
        self.request_count = 0
        self.last_request_time = 0.0
        self.retry_count = 0
        self.blocked_count = 0
        self.error_count = 0

    def _create_client(self) -> httpx.Client:
        """Create HTTP client with security defaults and connection pooling"""
        return httpx.Client(
            timeout=httpx.Timeout(
                connect=5.0,
                read=self.config.timeout,
                write=self.config.timeout,
                pool=10.0
            ),
            verify=self.config.verify_tls,
            follow_redirects=self.config.follow_redirects,
            max_redirects=self.config.max_redirects,
            headers={
                'User-Agent': self.config.user_agent,
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                **self.config.custom_headers
            },
            limits=httpx.Limits(
                max_connections=10,
                max_keepalive_connections=5,
                keepalive_expiry=30.0
            ),
            http2=False  # HTTP/1.1 for better compatibility with WAF testing
        )

    def execute_request(self, request: RequestConfig) -> httpx.Response:
        """
        Execute HTTP request with full error handling and retry logic
        Returns httpx.Response object directly for engine processing
        """
        # Rate limiting
        self._apply_rate_limit()

        # Budget check (only if budget > 0)
        if self.config.budget > 0 and self.request_count >= self.config.budget:
            raise RuntimeError(f"Budget exceeded: {self.config.budget} requests")

        # Retry logic with exponential backoff
        max_retries = self.config.rate_limit.max_retries
        retry_delay = self.config.rate_limit.retry_delay
        backoff_base = self.config.rate_limit.exponential_backoff_base

        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                # Execute request
                response = self._dispatch_request(request)

                # Increment counter on successful dispatch
                self.request_count += 1

                # Handle 429 Too Many Requests with backoff
                if response.status_code == 429 and self.config.rate_limit.backoff_on_429:
                    if attempt < max_retries:
                        retry_after = float(response.headers.get('Retry-After', retry_delay))
                        time.sleep(retry_after)
                        retry_delay *= backoff_base
                        self.retry_count += 1
                        continue

                # Track blocked responses
                if response.status_code in {403, 406, 418, 429, 503, 520, 521, 522, 523, 524, 525}:
                    self.blocked_count += 1

                return response

            except httpx.TimeoutException as e:
                last_exception = e
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    retry_delay *= backoff_base
                    self.retry_count += 1
                else:
                    self.error_count += 1
                    raise

            except httpx.ConnectError as e:
                last_exception = e
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    retry_delay *= backoff_base
                    self.retry_count += 1
                else:
                    self.error_count += 1
                    raise

            except httpx.HTTPStatusError as e:
                # HTTP errors with valid response (4xx, 5xx)
                self.request_count += 1
                return e.response

            except httpx.HTTPError as e:
                last_exception = e
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    retry_delay *= backoff_base
                    self.retry_count += 1
                else:
                    self.error_count += 1
                    raise

        # Fallback after all retries exhausted
        self.error_count += 1
        if last_exception:
            raise last_exception
        raise RuntimeError("Max retries exceeded with unknown error")

    def _dispatch_request(self, request: RequestConfig) -> httpx.Response:
        """
        Dispatch request based on HTTP method
        Handles all standard methods + WebDAV extensions
        """
        method = request.method.value.upper()

        # Prepare common params
        params = {
            'url': request.url,
            'headers': self._prepare_headers(request),
            'timeout': request.timeout,
        }

        # Handle body for methods that support it
        body_methods = {'POST', 'PUT', 'PATCH'}
        if method in body_methods or method in self.WEBDAV_METHODS:
            if request.body:
                params['content'] = request.body.encode('utf-8')
            elif request.json_data:
                params['json'] = request.json_data

        # Method-specific handling
        if method == 'GET':
            return self.client.get(**params)
        elif method == 'HEAD':
            return self.client.head(**params)
        elif method == 'OPTIONS':
            return self.client.options(**params)
        elif method == 'POST':
            return self.client.post(**params)
        elif method == 'PUT':
            return self.client.put(**params)
        elif method == 'PATCH':
            return self.client.patch(**params)
        elif method == 'DELETE':
            return self.client.delete(**params)
        elif method in self.WEBDAV_METHODS:
            # WebDAV methods via generic request()
            return self.client.request(method=method, **params)
        else:
            # Fallback for any custom methods
            return self.client.request(method=method, **params)

    def _prepare_headers(self, request: RequestConfig) -> Dict[str, str]:
        """Prepare and merge request headers with proper case handling"""
        headers = dict(self.client.headers)

        # Merge request-specific headers (case-insensitive replacement)
        if request.headers:
            for key, value in request.headers.items():
                # Remove any existing case-insensitive versions
                for existing_key in list(headers.keys()):
                    if existing_key.lower() == key.lower():
                        del headers[existing_key]
                headers[key] = value

        # Auto-set Content-Type if body present and not set
        has_content_type = any(k.lower() == 'content-type' for k in headers.keys())
        if request.body and not has_content_type:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        elif request.json_data and not has_content_type:
            headers['Content-Type'] = 'application/json'

        # Set Content-Length for body requests
        if request.body:
            headers['Content-Length'] = str(len(request.body.encode('utf-8')))

        return headers

    def _apply_rate_limit(self) -> None:
        """
        Apply token bucket rate limiting
        Enforces requests_per_second with sub-second precision
        """
        if self.last_request_time > 0:
            elapsed = time.time() - self.last_request_time
            min_interval = 1.0 / self.config.rate_limit.requests_per_second

            # Enforce rate limit
            if elapsed < min_interval:
                sleep_time = min_interval - elapsed
                time.sleep(sleep_time)

        self.last_request_time = time.time()

    def get_stats(self) -> Dict[str, Any]:
        """Return client statistics for monitoring"""
        return {
            'total_requests': self.request_count,
            'blocked_requests': self.blocked_count,
            'error_requests': self.error_count,
            'retry_count': self.retry_count,
            'success_rate': round(
                (self.request_count - self.error_count) / max(self.request_count, 1) * 100, 2
            ),
            'budget_remaining': max(0, self.config.budget - self.request_count) if self.config.budget > 0 else 'unlimited'
        }

    def close(self) -> None:
        """Close HTTP client and cleanup resources"""
        try:
            self.client.close()
        except Exception:
            pass

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - always cleanup"""
        self.close()
        return False  # Don't suppress exceptions


# ============================================================================
# REQUEST BUILDER UTILITIES
# ============================================================================

class RequestBuilder:
    """
    Fluent request builder for all HTTP methods
    Provides convenient factory methods for common request types
    """

    @staticmethod
    def build_get_request(
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None
    ) -> RequestConfig:
        """Build GET request with optional query parameters"""
        if params:
            separator = '&' if '?' in url else '?'
            url = f"{url}{separator}{urlencode(params)}"

        return RequestConfig(
            url=url,
            method=HTTPMethod.GET,
            headers=headers or {}
        )

    @staticmethod
    def build_head_request(url: str, headers: Optional[Dict[str, str]] = None) -> RequestConfig:
        """Build HEAD request (metadata only, no body)"""
        return RequestConfig(
            url=url,
            method=HTTPMethod.HEAD,
            headers=headers or {}
        )

    @staticmethod
    def build_options_request(url: str, headers: Optional[Dict[str, str]] = None) -> RequestConfig:
        """Build OPTIONS request (discover allowed methods)"""
        return RequestConfig(
            url=url,
            method=HTTPMethod.OPTIONS,
            headers=headers or {}
        )

    @staticmethod
    def build_post_request(
        url: str,
        body: Optional[str] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> RequestConfig:
        """Build POST request with form or JSON body"""
        req_headers = headers or {}

        if json_data:
            req_headers['Content-Type'] = 'application/json'
            return RequestConfig(
                url=url,
                method=HTTPMethod.POST,
                headers=req_headers,
                json_data=json_data
            )

        if body and 'Content-Type' not in req_headers:
            req_headers['Content-Type'] = 'application/x-www-form-urlencoded'

        return RequestConfig(
            url=url,
            method=HTTPMethod.POST,
            headers=req_headers,
            body=body
        )

    @staticmethod
    def build_put_request(
        url: str,
        body: Optional[str] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> RequestConfig:
        """Build PUT request for resource update"""
        req_headers = headers or {}

        if json_data:
            req_headers['Content-Type'] = 'application/json'
            return RequestConfig(
                url=url,
                method=HTTPMethod.PUT,
                headers=req_headers,
                json_data=json_data
            )

        if body and 'Content-Type' not in req_headers:
            req_headers['Content-Type'] = 'application/json'

        return RequestConfig(
            url=url,
            method=HTTPMethod.PUT,
            headers=req_headers,
            body=body
        )

    @staticmethod
    def build_patch_request(
        url: str,
        body: Optional[str] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> RequestConfig:
        """Build PATCH request for partial update"""
        req_headers = headers or {}

        if json_data:
            req_headers['Content-Type'] = 'application/json'
            return RequestConfig(
                url=url,
                method=HTTPMethod.PATCH,
                headers=req_headers,
                json_data=json_data
            )

        if body and 'Content-Type' not in req_headers:
            req_headers['Content-Type'] = 'application/json'

        return RequestConfig(
            url=url,
            method=HTTPMethod.PATCH,
            headers=req_headers,
            body=body
        )

    @staticmethod
    def build_delete_request(url: str, headers: Optional[Dict[str, str]] = None) -> RequestConfig:
        """Build DELETE request"""
        return RequestConfig(
            url=url,
            method=HTTPMethod.DELETE,
            headers=headers or {}
        )

    @staticmethod
    def build_json_request(
        url: str,
        method: HTTPMethod = HTTPMethod.POST,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> RequestConfig:
        """Build JSON request for any method"""
        req_headers = headers or {}
        req_headers['Content-Type'] = 'application/json'
        req_headers['Accept'] = 'application/json'

        return RequestConfig(
            url=url,
            method=method,
            headers=req_headers,
            json_data=json_data
        )

    @staticmethod
    def build_form_request(
        url: str,
        form_data: Dict[str, str],
        method: HTTPMethod = HTTPMethod.POST,
        headers: Optional[Dict[str, str]] = None
    ) -> RequestConfig:
        """Build form-encoded request"""
        req_headers = headers or {}
        req_headers['Content-Type'] = 'application/x-www-form-urlencoded'

        body = urlencode(form_data)

        return RequestConfig(
            url=url,
            method=method,
            headers=req_headers,
            body=body
        )


__all__ = ['SecureHTTPClient', 'RequestBuilder']
