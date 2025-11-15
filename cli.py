#!/usr/bin/env python3

"""
WAF Stressor - Advanced Batch CLI Runner
Production-grade batch scanner with comprehensive error handling

© GHOSTSHINOBI 2025
"""

import time
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import argparse

from core import TestConfig, TestProfile, RateLimitConfig
from engine import TestEngine
from reposys import ReportGenerator


class GorillaRunner:
    """
    Production-grade batch runner for WAF Stressor
    Handles multiple targets with comprehensive error handling and reporting
    Direct engine execution (no subprocess)
    """

    def __init__(
        self,
        target_file: str,
        payload_file: str,
        output_dir: str = "results",
        profile: str = "light",
        budget: int = 50,
        rate: float = 0.5,
        delay: int = 10,
        report_format: str = "md",
        timeout: int = 300,
        tls_verify: bool = False,
        verbose: bool = False,
        continue_on_error: bool = True
    ):
        self.target_file = Path(target_file)
        self.payload_file = Path(payload_file)
        self.output_dir = Path(output_dir)
        self.profile = profile
        self.budget = budget
        self.rate = rate
        self.delay = delay
        self.report_format = report_format
        self.timeout = timeout
        self.tls_verify = tls_verify
        self.verbose = verbose
        self.continue_on_error = continue_on_error

        # Statistics
        self.total_targets = 0
        self.successful_scans = 0
        self.failed_scans = 0
        self.skipped_scans = 0
        self.start_time = None
        self.results_log = []

        # Validate inputs
        self._validate_inputs()

    def _validate_inputs(self):
        """Validate all input files and parameters"""
        if not self.target_file.exists():
            raise FileNotFoundError(f"Target file not found: {self.target_file}")

        if not self.payload_file.exists():
            raise FileNotFoundError(f"Payload file not found: {self.payload_file}")

        if self.profile not in ['light', 'deep']:
            raise ValueError(f"Invalid profile: {self.profile}. Must be 'light' or 'deep'")

        if self.budget < 1:
            raise ValueError(f"Budget must be positive: {self.budget}")

        if self.rate <= 0:
            raise ValueError(f"Rate must be positive: {self.rate}")

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        print(f"✓ Output directory: {self.output_dir}")

    def load_targets(self) -> List[str]:
        """Load and validate targets from file"""
        targets = []
        with open(self.target_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                targets.append(line)

        self.total_targets = len(targets)
        return targets

    def sanitize_filename(self, target: str) -> str:
        """Create safe filename from target"""
        safe = target.replace('https://', '').replace('http://', '')
        safe = safe.replace('/', '_').replace(':', '_').replace('.', '_')
        safe = safe.replace('?', '_').replace('&', '_').replace('=', '_')
        return safe[:50]

    def run_scan(self, target: str, index: int) -> Dict[str, Any]:
        """Execute single scan for target using TestEngine directly"""
        safe_name = self.sanitize_filename(target)
        output_file = self.output_dir / f"{safe_name}_report"

        result = {
            'target': target,
            'index': index,
            'start_time': datetime.now().isoformat(),
            'status': 'unknown',
            'duration_seconds': 0,
            'error_message': None,
            'output_file': str(output_file.with_suffix(f'.{self.report_format}'))
        }

        print(f"\n{'=' * 70}")
        print(f"🎯 Target {index}/{self.total_targets}: {target}")
        print(f"{'=' * 70}")
        print(f"   Output: {result['output_file']}")
        print(f"   Budget: {self.budget} requests")
        print(f"   Rate: {self.rate} req/s\n")

        scan_start = time.time()

        try:
            # Create config
            profile_enum = TestProfile.DEEP if self.profile == 'deep' else TestProfile.LIGHT
            config = TestConfig(
                target_url=target,
                payload_file=str(self.payload_file),
                profile=profile_enum,
                budget=self.budget,
                rate_limit=RateLimitConfig(requests_per_second=self.rate),
                verify_tls=self.tls_verify,
                timeout=self.timeout
            )

            # Run scan
            engine = TestEngine(config)
            report = engine.scan(config)

            # Generate report
            generator = ReportGenerator(report=report)
            generator.generate_report(self.report_format, str(output_file))

            duration = time.time() - scan_start
            result['duration_seconds'] = round(duration, 2)
            result['status'] = 'success'
            result['total_requests'] = report.total_requests
            result['findings'] = len(report.findings)
            result['waf_detected'] = report.waf_fingerprint is not None

            self.successful_scans += 1
            print(f"✅ Scan completed: {target} ({duration:.1f}s)")
            print(f"   Requests: {report.total_requests}")
            print(f"   Findings: {len(report.findings)}")

        except KeyboardInterrupt:
            result['status'] = 'interrupted'
            result['error_message'] = 'User interrupted'
            self.failed_scans += 1
            print(f"⚠️ Scan interrupted: {target}")
            raise  # Re-raise to stop batch

        except Exception as e:
            duration = time.time() - scan_start
            result['duration_seconds'] = round(duration, 2)
            result['status'] = 'error'
            result['error_message'] = str(e)
            self.failed_scans += 1
            print(f"❌ Scan failed: {target}")
            print(f"   Error: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()

        result['end_time'] = datetime.now().isoformat()
        return result

    def run_batch(self) -> None:
        """Execute batch scan on all targets"""
        print("\n" + "=" * 70)
        print("🦍 WAF Stressor - Advanced Batch Runner")
        print("=" * 70)

        # Load targets
        print(f"\n📁 Loading targets from: {self.target_file}")
        targets = self.load_targets()

        if not targets:
            print("❌ No valid targets found in file")
            sys.exit(1)

        print(f"✓ Loaded {len(targets)} targets")
        print(f"\n⚙️ Configuration:")
        print(f"   Payload file: {self.payload_file}")
        print(f"   Profile: {self.profile}")
        print(f"   Budget per target: {self.budget}")
        print(f"   Rate: {self.rate} req/s")
        print(f"   Delay between targets: {self.delay}s")
        print(f"   Output format: {self.report_format}")
        print(f"   TLS verify: {self.tls_verify}")

        estimated_time = (self.budget / self.rate + self.delay) * len(targets)
        print(f"\n⏱️ Estimated total time: {estimated_time / 60:.1f} minutes")

        # Confirm start
        try:
            input("\n▶️  Press ENTER to start batch scan (or Ctrl+C to abort)...")
        except KeyboardInterrupt:
            print("\n⚠️ Aborted by user")
            sys.exit(0)

        self.start_time = time.time()

        # Scan each target
        for i, target in enumerate(targets, 1):
            result = self.run_scan(target, i)
            self.results_log.append(result)

            # Check if should continue
            if result['status'] == 'interrupted':
                print("\n⚠️ Batch interrupted by user")
                break

            if result['status'] in ['error', 'failed'] and not self.continue_on_error:
                print(f"\n⚠️ Stopping batch due to error (continue_on_error=False)")
                break

            # Delay before next target
            if i < len(targets):
                print(f"\n⏱️ Waiting {self.delay}s before next target...")
                try:
                    time.sleep(self.delay)
                except KeyboardInterrupt:
                    print("\n⚠️ Batch interrupted by user")
                    break

        # Generate summary
        self._print_summary()
        self._save_batch_report()

    def _print_summary(self) -> None:
        """Print final summary"""
        if not self.start_time:
            return

        total_duration = time.time() - self.start_time

        print("\n" + "=" * 70)
        print("📊 BATCH SCAN SUMMARY")
        print("=" * 70)
        print(f"\n⏱️  Total Duration: {total_duration / 60:.1f} minutes")
        print(f"\n📈 Results:")
        print(f"   Total targets: {self.total_targets}")
        print(f"   ✅ Successful: {self.successful_scans}")
        print(f"   ❌ Failed: {self.failed_scans}")

        success_rate = (self.successful_scans / max(self.total_targets, 1)) * 100
        print(f"\n   Success rate: {success_rate:.1f}%")

        print(f"\n📁 Reports saved in: {self.output_dir.absolute()}/")
        print(f"📄 Batch log: {self.output_dir}/batch_log.json")

        # Show failed targets if any
        if self.failed_scans > 0:
            print(f"\n⚠️  Failed targets:")
            for result in self.results_log:
                if result['status'] in ['failed', 'error', 'timeout']:
                    print(f"   - {result['target']}: {result['error_message']}")

        print("\n" + "=" * 70 + "\n")

    def _save_batch_report(self) -> None:
        """Save comprehensive batch report to JSON"""
        report = {
            'batch_info': {
                'start_time': datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
                'end_time': datetime.now().isoformat(),
                'duration_seconds': round(time.time() - self.start_time, 2) if self.start_time else 0,
                'target_file': str(self.target_file),
                'payload_file': str(self.payload_file),
                'output_directory': str(self.output_dir)
            },
            'configuration': {
                'profile': self.profile,
                'budget_per_target': self.budget,
                'rate': self.rate,
                'delay': self.delay,
                'format': self.report_format,
                'timeout': self.timeout,
                'tls_verify': self.tls_verify
            },
            'statistics': {
                'total_targets': self.total_targets,
                'successful_scans': self.successful_scans,
                'failed_scans': self.failed_scans,
                'success_rate': round((self.successful_scans / max(self.total_targets, 1)) * 100, 2)
            },
            'detailed_results': self.results_log
        }

        log_file = self.output_dir / 'batch_log.json'
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"✓ Batch log saved: {log_file}")


def main() -> None:
    """CLI entry point for advanced batch runner"""
    parser = argparse.ArgumentParser(
        description="🦍 WAF Stressor - Advanced Batch Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py -t targets.txt -f xss-payloads.txt
  python cli.py -t targets.txt -f payloads.txt --profile deep --budget 100
  python cli.py -t targets.txt -f payloads.txt -o results/my_scan --format md
        """
    )

    # Required arguments
    parser.add_argument('-t', '--targets', required=True, help='File with target URLs (one per line)')
    parser.add_argument('-f', '--payloads', required=True, help='Payload file (.txt)')

    # Optional arguments
    parser.add_argument('-o', '--output', default='results', help='Output directory (default: results)')
    parser.add_argument('-p', '--profile', default='light', choices=['light', 'deep'],
                        help='Scan profile (default: light)')
    parser.add_argument('-b', '--budget', type=int, default=50, help='Budget per target (default: 50)')
    parser.add_argument('-r', '--rate', type=float, default=0.5, help='Requests per second (default: 0.5)')
    parser.add_argument('-d', '--delay', type=int, default=10, help='Delay between targets in seconds (default: 10)')
    parser.add_argument('--format', default='md', choices=['json', 'md', 'csv', 'sarif', 'html'],
                        help='Report format (default: md)')
    parser.add_argument('--timeout', type=int, default=300, help='Timeout per scan in seconds (default: 300)')
    parser.add_argument('--tls-verify', action='store_true', help='Enable TLS certificate verification')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--stop-on-error', action='store_true', help='Stop batch on first error')

    args = parser.parse_args()

    try:
        runner = GorillaRunner(
            target_file=args.targets,
            payload_file=args.payloads,
            output_dir=args.output,
            profile=args.profile,
            budget=args.budget,
            rate=args.rate,
            delay=args.delay,
            report_format=args.format,
            timeout=args.timeout,
            tls_verify=args.tls_verify,
            verbose=args.verbose,
            continue_on_error=not args.stop_on_error
        )

        runner.run_batch()

        # Exit with appropriate code
        if runner.failed_scans == 0:
            sys.exit(0)  # All successful
        elif runner.successful_scans > 0:
            sys.exit(2)  # Partial success
        else:
            sys.exit(1)  # All failed

    except KeyboardInterrupt:
        print("\n\n⚠️ Batch scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
