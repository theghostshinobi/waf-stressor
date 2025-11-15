#!/usr/bin/env python3

"""
WAF Stressor - Production CLI Entry Point
Simple, robust command-line wrapper for single-target scanning

© GHOSTSHINOBI 2025
"""

import sys
import json
import argparse
from pathlib import Path
from typing import Optional
from datetime import datetime

from core import TestConfig, TestProfile, RateLimitConfig, ScanReport
from engine import TestEngine


def parse_arguments() -> argparse.Namespace:
    """Parse and validate command-line arguments"""
    parser = argparse.ArgumentParser(
        description='WAF Stressor - Web Application Firewall Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run.py https://httpbin.org/get
  python3 run.py https://example.com --profile deep --budget 100
  python3 run.py https://api.target.com --rate 0.5 --timeout 15
  python3 run.py https://secure.site --no-verify-tls --user-agent "CustomBot/1.0"
        """
    )

    # Required arguments
    parser.add_argument(
        'target_url',
        help='Target URL to test (e.g., https://example.com/api)'
    )

    # Optional arguments
    parser.add_argument(
        '--profile', '-p',
        choices=['light', 'deep'],
        default='light',
        help='Testing profile (default: light)'
    )

    parser.add_argument(
        '--budget', '-b',
        type=int,
        default=0,
        help='Maximum number of requests (0 = profile default)'
    )

    parser.add_argument(
        '--payload-file', '-f',
        default='xss-payloads.txt',
        help='Path to payload file (default: xss-payloads.txt)'
    )

    parser.add_argument(
        '--rate', '-r',
        type=float,
        default=1.0,
        help='Requests per second (default: 1.0)'
    )

    parser.add_argument(
        '--timeout', '-t',
        type=float,
        default=0.0,
        help='Request timeout in seconds (0 = profile default)'
    )

    parser.add_argument(
        '--no-verify-tls',
        action='store_true',
        help='Disable TLS certificate verification'
    )

    parser.add_argument(
        '--user-agent', '-u',
        default='WAF-Stressor/1.0 (Security Testing)',
        help='Custom User-Agent header'
    )

    parser.add_argument(
        '--output-dir', '-o',
        default='scan_results',
        help='Output directory for reports (default: scan_results)'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Minimal output (errors only)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output with debug information'
    )

    return parser.parse_args()


def create_config_from_args(args: argparse.Namespace) -> TestConfig:
    """Create TestConfig from parsed arguments"""
    profile_enum = TestProfile.DEEP if args.profile.lower() == 'deep' else TestProfile.LIGHT

    # Create rate limit config
    rate_limit = RateLimitConfig(
        requests_per_second=args.rate,
        max_retries=3,
        backoff_on_429=True
    )

    # Create main config
    config = TestConfig(
        target_url=args.target_url,
        payload_file=args.payload_file,
        profile=profile_enum,
        budget=args.budget if args.budget > 0 else 0,
        rate_limit=rate_limit,
        timeout=args.timeout if args.timeout > 0 else 0.0,
        verify_tls=not args.no_verify_tls,
        user_agent=args.user_agent,
        follow_redirects=True,
        max_redirects=10
    )

    return config


def print_banner(quiet: bool = False):
    """Print application banner"""
    if quiet:
        return

    banner = """
╔══════════════════════════════════════════════════════════════╗
║              WAF STRESSOR - Security Testing Tool            ║
║                     © GHOSTSHINOBI 2025                      ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_scan_summary(report: ScanReport, quiet: bool = False):
    """Print scan summary results"""
    if quiet:
        return

    print(f"\n{'=' * 60}")
    print(f"✅ SCAN COMPLETE")
    print(f"{'=' * 60}")
    print(f"📊 Target:          {report.target_url}")
    print(f"🎯 Profile:         {report.profile.value.upper()}")
    print(f"📈 Total Requests:  {report.total_requests}")
    print(f"⏱️  Elapsed Time:    {report.elapsed_time:.2f}s")
    print(f"✔️  Success Rate:    {report.success_rate:.1f}%")

    if report.metrics:
        print(f"\n{'─' * 60}")
        print(f"📊 METRICS")
        print(f"{'─' * 60}")
        print(f"   Blocked:         {report.metrics.blocked_requests}")
        print(f"   Allowed:         {report.metrics.allowed_requests}")
        print(f"   Errors:          {report.metrics.error_requests}")
        print(f"   Avg Response:    {report.metrics.avg_response_time:.3f}s")
        print(f"   Min Response:    {report.metrics.min_response_time:.3f}s")
        print(f"   Max Response:    {report.metrics.max_response_time:.3f}s")

    if report.waf_fingerprint:
        print(f"\n{'─' * 60}")
        print(f"🛡️  WAF DETECTED: {report.waf_fingerprint}")
        print(f"{'─' * 60}")

    if report.findings:
        print(f"\n{'─' * 60}")
        print(f"🚨 FINDINGS: {len(report.findings)}")
        print(f"{'─' * 60}")

        for idx, finding in enumerate(report.findings[:10], 1):
            print(f"\n{idx}. {finding.title}")
            print(f"   Severity:     {finding.severity.value.upper()}")
            print(f"   Type:         {finding.vulnerability_type.value}")
            print(f"   URL:          {finding.url}")
            print(f"   Response:     {finding.response_code}")
            print(f"   Payload:      {finding.payload[:80]}...")

        if len(report.findings) > 10:
            print(f"\n   ... and {len(report.findings) - 10} more findings")
    else:
        print(f"\n✅ No vulnerabilities detected")


def save_report(report: ScanReport, output_dir: str, quiet: bool = False) -> Path:
    """Save scan report to JSON file"""
    results_dir = Path(output_dir)
    results_dir.mkdir(exist_ok=True, parents=True)

    # Generate sanitized filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    sanitized_url = report.target_url.replace('://', '_').replace('/', '_').replace('?', '_')
    filename = f"{sanitized_url}_{timestamp}.json"

    report_file = results_dir / filename

    # Write report
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

    if not quiet:
        print(f"\n📁 Report saved: {report_file}")

    return report_file


def main():
    """Main entry point"""
    try:
        # Parse arguments
        args = parse_arguments()

        # Print banner
        print_banner(args.quiet)

        # Create configuration
        config = create_config_from_args(args)

        if not args.quiet:
            print(f"🎯 Target:   {config.target_url}")
            print(f"📋 Profile:  {config.profile.value}")
            print(f"💰 Budget:   {config.budget or 'Profile default'}")
            print(f"⚡ Rate:     {config.rate_limit.requests_per_second} req/s")
            print(f"🔒 TLS:      {'Verified' if config.verify_tls else 'Not verified'}")
            print(f"\n🚀 Starting scan...\n")

        # Create engine and run scan
        engine = TestEngine(config)
        report = engine.scan(config)

        # Print summary
        print_scan_summary(report, args.quiet)

        # Save report
        report_path = save_report(report, args.output_dir, args.quiet)

        # Exit with appropriate code
        if report.findings:
            critical_count = sum(1 for f in report.findings if f.severity.value == 'critical')
            if critical_count > 0:
                sys.exit(2)  # Critical findings found
            sys.exit(1)  # Findings found

        sys.exit(0)  # No findings

    except FileNotFoundError as e:
        print(f"❌ Error: File not found - {e}", file=sys.stderr)
        sys.exit(3)

    except ValueError as e:
        print(f"❌ Error: Invalid value - {e}", file=sys.stderr)
        sys.exit(4)

    except KeyboardInterrupt:
        print(f"\n⚠️  Scan interrupted by user", file=sys.stderr)
        sys.exit(130)

    except Exception as e:
        print(f"❌ Fatal error: {e}", file=sys.stderr)
        if args.verbose if 'args' in locals() else False:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
