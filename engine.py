"""
WAF Stressor - Test Execution Engine
Production-grade orchestrator that coordinates all testing components

© GHOSTSHINOBI 2025
"""

import time
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime
from pathlib import Path

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.console import Console
from rich.table import Table

from core import (
    TestConfig, TestProfile, TestResult, RequestConfig, URLVariant,
    BaselineSnapshot, Payload, HTTPMethod, ResponseSignature, TestMetrics,
    VariantType, ScanReport, Finding, SeverityLevel, VulnerabilityType
)

from httpclientexec import SecureHTTPClient
from urlops import URLVariantGenerator
from payingest import PayloadLoader
from analysis import WAFDetector, MetricsCalculator, FindingsAnalyzer


class TestEngine:
    """
    Complete test execution engine
    Orchestrates: payload loading → variant generation → HTTP execution → WAF detection → analysis
    """

    def __init__(self, config: TestConfig):
        self.config = config
        self.http_client = SecureHTTPClient(config)
        self.waf_detector = WAFDetector()
        self.variant_generator = URLVariantGenerator(config.target_url, config.profile)
        self.console = Console()

        # State tracking
        self.baseline: Optional[BaselineSnapshot] = None
        self.results: List[TestResult] = []
        self.total_requests_made = 0
        self.start_time = time.time()
        self.end_time: Optional[float] = None

    def scan(self, config: Optional[TestConfig] = None) -> ScanReport:
        """
        Main entry point for scanning
        Loads payloads, executes full scan pipeline, returns report
        """
        # Use provided config or instance config
        if config:
            self.config = config
            self.http_client = SecureHTTPClient(config)
            self.variant_generator = URLVariantGenerator(config.target_url, config.profile)

        self.console.print(f"\n[bold cyan]🚀 WAF Stressor Engine Starting[/bold cyan]")
        self.console.print(f"[yellow]Target:[/yellow] {self.config.target_url}")
        self.console.print(f"[yellow]Profile:[/yellow] {self.config.profile.value.upper()}")
        self.console.print(f"[yellow]Budget:[/yellow] {self.config.budget} requests\n")

        # Load payloads
        payloads = self._load_payloads()

        # Run full scan
        report = self.run_full_scan(payloads)

        return report

    def _load_payloads(self) -> List[Payload]:
        """Load payloads from file with budget enforcement"""
        self.console.print("[bold yellow]📂 Loading payloads...[/bold yellow]")

        try:
            payload_path = Path(self.config.payload_file)

            if not payload_path.exists():
                self.console.print(f"[yellow]⚠️  Payload file not found, using default payloads[/yellow]")
                return self._get_default_payloads()

            loader = PayloadLoader(str(payload_path))
            all_payloads = loader.load_all()

            # Apply budget limit
            if self.config.budget > 0:
                limited_payloads = all_payloads[:self.config.budget]
                self.console.print(f"[green]✓ Loaded {len(limited_payloads)} payloads (budget limited)[/green]\n")
                return limited_payloads

            self.console.print(f"[green]✓ Loaded {len(all_payloads)} payloads[/green]\n")
            return all_payloads

        except Exception as e:
            self.console.print(f"[red]❌ Error loading payloads: {e}[/red]")
            self.console.print(f"[yellow]Using default payloads[/yellow]")
            return self._get_default_payloads()

    def _get_default_payloads(self) -> List[Payload]:
        """Get minimal default payloads for testing"""
        return [
            Payload("<script>alert(1)</script>", "xss_benign", "Basic XSS test"),
            Payload("' OR '1'='1", "sql_benign", "Basic SQL test"),
            Payload("../../../etc/passwd", "path_traversal", "Path traversal test"),
            Payload("${7*7}", "template_injection", "Template injection test"),
            Payload("<img src=x onerror=alert(1)>", "xss_benign", "Image XSS test"),
        ]

    def run_full_scan(self, payloads: List[Payload]) -> ScanReport:
        """
        Execute complete security scan with all payloads
        Returns comprehensive scan report
        """
        self.start_time = time.time()

        try:
            # Step 1: Capture baseline
            self._capture_baseline()

            # Step 2: Test URL variants without payloads
            self._test_url_variants_baseline()

            # Step 3: Test with payloads on variants
            self._test_with_payloads(payloads)

            # Step 4: Test HTTP methods
            self._test_http_methods()

            # Finalize scan
            self.end_time = time.time()

            # Calculate metrics
            metrics = MetricsCalculator.calculate_all_metrics(self.results)

            # WAF fingerprinting
            waf_fingerprint = self.waf_detector.fingerprint_waf(self.results)

            # Generate findings
            findings = FindingsAnalyzer.generate_findings(self.results)

            self.console.print(f"\n[bold green]✅ Scan complete![/bold green]")
            self.console.print(f"[cyan]Total requests: {self.total_requests_made}[/cyan]")
            self.console.print(f"[cyan]Total results: {len(self.results)}[/cyan]")

            if waf_fingerprint:
                self.console.print(f"[red]🛡️  WAF Detected: {waf_fingerprint}[/red]\n")

            # Create report
            report = ScanReport(
                target_url=self.config.target_url,
                profile=self.config.profile,
                start_time=self.start_time,
                end_time=self.end_time,
                results=self.results,
                baseline=self.baseline,
                metrics=metrics,
                waf_fingerprint=waf_fingerprint,
                findings=findings
            )

            return report

        except Exception as e:
            self.console.print(f"[red bold]❌ Scan failed: {str(e)}[/red bold]")
            raise

    def _capture_baseline(self) -> None:
        """Capture baseline behavior without payloads"""
        self.console.print("[bold yellow]📸 Capturing baseline...[/bold yellow]")

        if self._check_budget():
            return

        try:
            # Normal request
            normal_request = RequestConfig(
                url=self.config.target_url,
                method=HTTPMethod.GET,
                timeout=self.config.timeout,
                verify_tls=self.config.verify_tls,
                follow_redirects=self.config.follow_redirects
            )

            start_time = time.time()
            response = self.http_client.execute_request(normal_request)
            normal_signature = ResponseSignature.from_response(response, start_time)
            self.total_requests_made += 1

            # Test with obvious attack pattern to detect blocking
            blocked_url = f"{self.config.target_url}{'&' if '?' in self.config.target_url else '?'}test=<script>alert(1)</script>"

            blocked_request = RequestConfig(
                url=blocked_url,
                method=HTTPMethod.GET,
                timeout=self.config.timeout,
                verify_tls=self.config.verify_tls,
                follow_redirects=self.config.follow_redirects
            )

            start_time = time.time()
            blocked_response = self.http_client.execute_request(blocked_request)
            blocked_signature = ResponseSignature.from_response(blocked_response, start_time)
            self.total_requests_made += 1

            # Detect WAF from baseline
            waf_detected = self.waf_detector.detect_waf_response(blocked_signature)
            waf_name = None
            if waf_detected:
                fingerprint = self.waf_detector.fingerprint_waf([])
                waf_name = fingerprint if isinstance(fingerprint, str) else None

            # Store baseline
            self.baseline = BaselineSnapshot(
                normal_signature=normal_signature,
                blocked_signature=blocked_signature,
                waf_detected=waf_detected,
                waf_fingerprint=waf_name
            )

            self.console.print(f"[green]✓ Baseline captured (normal: {normal_signature.status_code}, blocked: {blocked_signature.status_code})[/green]")

            if waf_detected:
                self.console.print(f"[red]⚠️  WAF detected in baseline: {waf_name or 'Unknown'}[/red]")

        except Exception as e:
            self.console.print(f"[red]❌ Baseline capture failed: {e}[/red]")
            # Create minimal baseline
            self.baseline = None

    def _test_url_variants_baseline(self) -> None:
        """Test URL normalization variants without payloads"""
        self.console.print("\n[bold yellow]🔀 Testing URL variants (baseline)...[/bold yellow]")

        variants = self.variant_generator.generate_all_variants()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:

            task = progress.add_task(
                "[cyan]Testing variants...",
                total=min(len(variants), self.config.budget - self.total_requests_made)
            )

            for variant in variants:
                if self._check_budget():
                    break

                try:
                    result = self._execute_variant(variant)
                    if result:
                        self.results.append(result)
                    progress.advance(task)

                except Exception as e:
                    self.console.print(f"[red]Error testing variant {variant.variant_type.value}: {e}[/red]")
                    continue

        self.console.print(f"[green]✓ Tested {len([r for r in self.results if not r.request_config.payload])} URL variants[/green]")

    def _test_with_payloads(self, payloads: List[Payload]) -> None:
        """Test variants combined with payloads"""
        self.console.print("\n[bold yellow]💣 Testing with payloads...[/bold yellow]")

        # Generate variant types to test
        variant_types = [VariantType.BASELINE, VariantType.QUERY_PARAM, VariantType.DOUBLE_ENCODING]

        total_tests = min(
            len(payloads) * len(variant_types),
            self.config.budget - self.total_requests_made
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:

            task = progress.add_task("[cyan]Testing payloads...", total=total_tests)

            for payload in payloads:
                if self._check_budget():
                    break

                for variant_type in variant_types:
                    if self._check_budget():
                        break

                    try:
                        # Generate variant with payload
                        variants = self.variant_generator.generate_all_variants(payload)
                        matching_variant = next(
                            (v for v in variants if v.variant_type == variant_type),
                            None
                        )

                        if matching_variant:
                            result = self._execute_variant(matching_variant)
                            if result:
                                self.results.append(result)
                            progress.advance(task)

                    except Exception as e:
                        self.console.print(f"[red]Error testing payload: {e}[/red]")
                        continue

        payload_results = len([r for r in self.results if r.request_config.payload])
        self.console.print(f"[green]✓ Tested {payload_results} payload variants[/green]")

    def _test_http_methods(self) -> None:
        """Test different HTTP methods"""
        self.console.print("\n[bold yellow]🔧 Testing HTTP methods...[/bold yellow]")

        methods_to_test = [
            HTTPMethod.GET,
            HTTPMethod.POST,
            HTTPMethod.PUT,
            HTTPMethod.DELETE,
            HTTPMethod.OPTIONS,
            HTTPMethod.HEAD
        ]

        tested = 0
        for method in methods_to_test:
            if self._check_budget():
                break

            try:
                request = RequestConfig(
                    url=self.config.target_url,
                    method=method,
                    timeout=self.config.timeout,
                    verify_tls=self.config.verify_tls,
                    follow_redirects=self.config.follow_redirects
                )

                start_time = time.time()
                response = self.http_client.execute_request(request)
                signature = ResponseSignature.from_response(response, start_time)
                self.total_requests_made += 1

                # Create URLVariant for method test
                variant = URLVariant(
                    url=self.config.target_url,
                    variant_type=VariantType.METHOD_OVERRIDE,
                    base_url=self.config.target_url,
                    description=f"HTTP {method.value} test",
                    method=method
                )

                # Detect blocking/WAF
                blocked = self._is_blocked(signature)
                waf_detected = self.waf_detector.detect_waf_response(signature)

                result = TestResult(
                    url=self.config.target_url,
                    variant=variant,
                    request_config=request,
                    response_signature=signature,
                    blocked=blocked,
                    waf_detected=waf_detected
                )

                self.results.append(result)
                tested += 1

            except Exception as e:
                self.console.print(f"[red]Error testing {method.value}: {e}[/red]")
                continue

        self.console.print(f"[green]✓ Tested {tested} HTTP methods[/green]")

    def _execute_variant(self, variant: URLVariant) -> Optional[TestResult]:
        """Execute a single variant test and return result"""
        try:
            # Build request config
            request = RequestConfig(
                url=variant.url,
                method=variant.method,
                headers=variant.headers,
                payload=variant.payload,
                timeout=self.config.timeout,
                verify_tls=self.config.verify_tls,
                follow_redirects=self.config.follow_redirects
            )

            # Execute request
            start_time = time.time()
            response = self.http_client.execute_request(request)
            signature = ResponseSignature.from_response(response, start_time)
            self.total_requests_made += 1

            # Analyze response
            blocked = self._is_blocked(signature)
            waf_detected = self.waf_detector.detect_waf_response(signature)
            anomaly = self._detect_anomaly(signature)

            # Create result
            result = TestResult(
                url=variant.url,
                variant=variant,
                request_config=request,
                response_signature=signature,
                blocked=blocked,
                waf_detected=waf_detected,
                anomaly_detected=anomaly
            )

            return result

        except Exception as e:
            # Create error result
            error_result = TestResult(
                url=variant.url,
                variant=variant,
                request_config=RequestConfig(url=variant.url, method=variant.method),
                response_signature=ResponseSignature(
                    status_code=0,
                    headers={},
                    body_hash="",
                    body_length=0,
                    elapsed_time=0.0
                ),
                error=str(e)
            )
            return error_result

    def _is_blocked(self, signature: ResponseSignature) -> bool:
        """Determine if request was blocked by WAF"""
        blocking_codes = {403, 406, 418, 429, 503, 520, 521, 522, 523, 524}

        # Direct blocking codes
        if signature.status_code in blocking_codes:
            return True

        # If we have baseline, check DIFFERENCE from normal behavior
        if self.baseline and self.baseline.normal_signature:
            # Blocked if status code is DIFFERENT from normal
            if signature.status_code != self.baseline.normal_signature.status_code:
                return True

            # Blocked if body hash is DIFFERENT from normal (same status, different content)
            if signature.body_hash != self.baseline.normal_signature.body_hash:
                # But only if status suggests blocking
                if signature.status_code in blocking_codes:
                    return True

        return False

    def _detect_anomaly(self, signature: ResponseSignature) -> bool:
        """Detect response anomaly compared to baseline"""
        if not self.baseline or not self.baseline.normal_signature:
            return False

        normal = self.baseline.normal_signature

        # Check for significant differences
        if abs(signature.status_code - normal.status_code) > 0:
            return True

        if abs(signature.body_length - normal.body_length) > normal.body_length * 0.5:
            return True

        if signature.elapsed_time > normal.elapsed_time * 3:
            return True

        return False

    def _check_budget(self) -> bool:
        """Check if budget limit reached"""
        if self.config.budget <= 0:
            return False

        if self.total_requests_made >= self.config.budget:
            self.console.print(f"[yellow]⚠️  Budget limit reached ({self.config.budget} requests)[/yellow]")
            return True

        return False


# ============================================================================
# FACTORY FUNCTION
# ============================================================================

def create_engine(profile: TestProfile, target_url: str = "", **kwargs) -> TestEngine:
    """
    Factory function to create TestEngine with profile
    Maintains backward compatibility
    """
    config = TestConfig(
        target_url=target_url or "https://example.com",
        profile=profile,
        **kwargs
    )
    return TestEngine(config)


__all__ = ['TestEngine', 'create_engine']
