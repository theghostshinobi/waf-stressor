#!/usr/bin/env python3

"""
WAF Stressor Engine - Simple Batch Runner
Lightweight batch scanning for multiple targets

© GHOSTSHINOBI 2025
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime
import json
import time

from core import TestConfig, TestProfile, RateLimitConfig
from engine import TestEngine
from reposys import ReportGenerator


def main():
    """Simple batch scanner entry point"""
    parser = argparse.ArgumentParser(
        description='WAF Stressor - Lightweight Batch Scanning Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python waf-stressor-engine.py -t targets.txt -f payloads.txt
  python waf-stressor-engine.py -t targets.txt -f payloads.txt --profile deep
  python waf-stressor-engine.py -t targets.txt -f payloads.txt -o scan_results
        """
    )

    parser.add_argument('-t', '--targets', required=True, help='File with target URLs (one per line)')
    parser.add_argument('-f', '--payloads', default='xss-payloads.txt', help='Payload file (default: xss-payloads.txt)')
    parser.add_argument('-o', '--output', default='results', help='Output directory (default: results)')
    parser.add_argument('-p', '--profile', choices=['light', 'deep'], default='light',
                        help='Scan profile (default: light)')
    parser.add_argument('-b', '--budget', type=int, default=50, help='Request budget per target (default: 50)')
    parser.add_argument('-r', '--rate', type=float, default=0.5, help='Requests per second (default: 0.5)')
    parser.add_argument('--format', default='json', choices=['json', 'md', 'csv', 'sarif', 'html'],
                        help='Report format (default: json)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Load targets
    targets_file = Path(args.targets)
    if not targets_file.exists():
        print(f"❌ Error: Targets file not found: {targets_file}")
        sys.exit(1)

    with open(targets_file, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not targets:
        print(f"❌ Error: No valid targets found in {targets_file}")
        sys.exit(1)

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True, parents=True)

    # Print configuration
    print("\n" + "=" * 70)
    print("🛡️ WAF Stressor Engine - Batch Scanner")
    print("=" * 70)
    print(f"\n✓ Loading {len(targets)} targets...")
    print(f"✓ Payloads: {args.payloads}")
    print(f"✓ Profile: {args.profile.upper()}")
    print(f"✓ Budget per target: {args.budget}")
    print(f"✓ Rate: {args.rate} req/s")
    print(f"✓ Output: {output_dir}/")
    print(f"✓ Format: {args.format}")
    print()

    # Run scans
    profile = TestProfile.DEEP if args.profile == 'deep' else TestProfile.LIGHT
    batch_results = []
    start_time = time.time()

    for i, target in enumerate(targets, 1):
        print(f"\n[{i}/{len(targets)}] 🎯 Scanning: {target}")
        print("-" * 70)

        try:
            # Create config
            config = TestConfig(
                target_url=target,
                payload_file=args.payloads,
                profile=profile,
                budget=args.budget,
                rate_limit=RateLimitConfig(requests_per_second=args.rate),
                verify_tls=False
            )

            # Run scan
            engine = TestEngine(config)
            report = engine.scan(config)

            # Generate report
            safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_').replace('.', '_')
            report_path = output_dir / f"{safe_target}_report"

            generator = ReportGenerator(report=report)
            output_file = generator.generate_report(args.format, str(report_path))

            batch_results.append({
                'target': target,
                'status': 'success',
                'findings': len(report.findings),
                'total_requests': report.total_requests,
                'success_rate': report.success_rate,
                'waf_detected': report.waf_fingerprint is not None,
                'waf_vendor': report.waf_fingerprint,
                'output_file': str(output_file)
            })

            print(f"✅ Completed: {target}")
            print(f"   Requests: {report.total_requests}")
            print(f"   Findings: {len(report.findings)}")
            if report.waf_fingerprint:
                print(f"   WAF: {report.waf_fingerprint.upper()}")
            print(f"   Report: {output_file}")

        except KeyboardInterrupt:
            print(f"\n⚠️ Scan interrupted by user")
            batch_results.append({
                'target': target,
                'status': 'interrupted',
                'error': 'User interrupted'
            })
            break

        except FileNotFoundError as e:
            error_msg = str(e)
            batch_results.append({
                'target': target,
                'status': 'failed',
                'error': error_msg
            })
            print(f"❌ Failed: {target}")
            print(f"   Error: {error_msg}")

        except Exception as e:
            error_msg = str(e)
            batch_results.append({
                'target': target,
                'status': 'failed',
                'error': error_msg
            })
            print(f"❌ Failed: {target}")
            print(f"   Error: {error_msg}")
            if args.verbose:
                import traceback
                traceback.print_exc()

        # Small delay between targets
        if i < len(targets):
            time.sleep(2)

    # Print summary
    total_duration = time.time() - start_time
    successful = sum(1 for r in batch_results if r['status'] == 'success')
    failed = sum(1 for r in batch_results if r['status'] == 'failed')

    print("\n" + "=" * 70)
    print("📊 BATCH SUMMARY")
    print("=" * 70)
    print(f"\n⏱️  Duration: {total_duration / 60:.1f} minutes")
    print(f"📈 Results:")
    print(f"   Total targets: {len(targets)}")
    print(f"   ✅ Successful: {successful}")
    print(f"   ❌ Failed: {failed}")
    print(f"   Success rate: {(successful / len(targets) * 100):.1f}%")

    # Show WAF detections
    waf_detections = [r for r in batch_results if r.get('waf_detected')]
    if waf_detections:
        print(f"\n🛡️  WAF Detections:")
        for r in waf_detections:
            print(f"   {r['target']}: {r.get('waf_vendor', 'Unknown').upper()}")

    # Show findings summary
    total_findings = sum(r.get('findings', 0) for r in batch_results if r['status'] == 'success')
    if total_findings > 0:
        print(f"\n🔍 Total Findings: {total_findings}")

    print(f"\n📁 Reports saved in: {output_dir.absolute()}/")

    # Save batch summary
    summary_file = output_dir / 'batch_summary.json'
    summary = {
        'scan_info': {
            'start_time': datetime.fromtimestamp(start_time).isoformat(),
            'end_time': datetime.now().isoformat(),
            'duration_seconds': round(total_duration, 2),
            'profile': args.profile,
            'budget_per_target': args.budget
        },
        'statistics': {
            'total_targets': len(targets),
            'successful': successful,
            'failed': failed,
            'success_rate': round((successful / len(targets)) * 100, 2),
            'total_findings': total_findings
        },
        'results': batch_results
    }

    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"📄 Summary: {summary_file}")
    print("=" * 70 + "\n")

    # Exit code
    if failed == 0:
        sys.exit(0)
    elif successful > 0:
        sys.exit(2)  # Partial success
    else:
        sys.exit(1)  # All failed


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Batch scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)
