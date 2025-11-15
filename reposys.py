"""
WAF Stressor - Report Generation System
Production-ready multi-format reporting suite

© GHOSTSHINOBI 2025
"""

import json
import csv
import statistics
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core import ScanReport, TestResult, TestMetrics, Finding
from analysis import WAFDetector


class ReportGenerator:
    """
    Production-grade multi-format report generator
    Accepts ScanReport or creates one from components
    Supports JSON, Markdown, CSV, SARIF, HTML formats
    """

    def __init__(
        self,
        report: Optional[ScanReport] = None,
        results: Optional[List[TestResult]] = None,
        config=None,
        metrics: Optional[TestMetrics] = None,
        findings: Optional[List[Finding]] = None,
        waf_fingerprint: Optional[str] = None
    ):
        """
        Initialize with ScanReport or individual components
        Flexible initialization for backward compatibility
        """
        if report:
            # Use ScanReport directly (preferred)
            self.report = report
            self.results = report.results
            self.config = config  # Optional override
            self.metrics = report.metrics
            self.findings = report.findings
            self.waf_fingerprint = report.waf_fingerprint
            self.target_url = report.target_url
            self.profile = report.profile
        elif results:
            # Build from components (legacy support)
            self.results = results
            self.config = config
            self.metrics = metrics or TestMetrics()
            self.findings = findings or []
            self.waf_fingerprint = waf_fingerprint
            self.target_url = config.target_url if config else "unknown"
            self.profile = config.profile if config else None
            self.report = None
        else:
            raise ValueError("Either 'report' or 'results' must be provided")

        # Calculate additional stats
        self.stats = self._calculate_additional_stats()

    def generate_report(self, format: str, output_path: str) -> Path:
        """Generate report in specified format and return output path"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        format_handlers = {
            'json': self._generate_json,
            'md': self._generate_markdown,
            'markdown': self._generate_markdown,
            'csv': self._generate_csv,
            'sarif': self._generate_sarif,
            'html': self._generate_html,
        }

        handler = format_handlers.get(format.lower())
        if not handler:
            raise ValueError(
                f"Unsupported format: {format}. "
                f"Supported: {list(format_handlers.keys())}"
            )

        return handler(output_path)

    def generate_all_formats(self, base_path: str) -> Dict[str, Path]:
        """Generate all report formats and return paths"""
        base_path = Path(base_path).with_suffix('')

        formats = {
            'json': self._generate_json(base_path),
            'markdown': self._generate_markdown(base_path),
            'csv': self._generate_csv(base_path),
            'sarif': self._generate_sarif(base_path),
            'html': self._generate_html(base_path),
        }

        return formats

    def _calculate_additional_stats(self) -> Dict[str, Any]:
        """Calculate additional statistics for reporting"""
        stats = {
            'variant_distribution': defaultdict(int),
            'status_distribution': defaultdict(int),
            'method_distribution': defaultdict(int),
            'payload_categories': defaultdict(int),
            'avg_response_times': {},
            'error_types': defaultdict(int),
            'response_times': []
        }

        response_times_by_type = defaultdict(list)

        for result in self.results:
            # Count distributions
            stats['variant_distribution'][result.variant.variant_type.value] += 1
            stats['status_distribution'][result.response_signature.status_code] += 1
            stats['method_distribution'][result.request_config.method.value] += 1

            if result.variant.payload:
                stats['payload_categories'][result.variant.payload.category] += 1

            # Response times (convert seconds to ms)
            elapsed_ms = result.response_signature.elapsed_time * 1000
            if elapsed_ms > 0:
                stats['response_times'].append(elapsed_ms)
                vtype = result.variant.variant_type.value
                response_times_by_type[vtype].append(elapsed_ms)

            # Errors
            if result.error:
                stats['error_types'][result.error] += 1

        # Calculate average response times
        for vtype, times in response_times_by_type.items():
            stats['avg_response_times'][vtype] = round(statistics.mean(times), 2) if times else 0.0

        return dict(stats)

    def _generate_json(self, output_path: Path) -> Path:
        """Generate comprehensive JSON report"""
        report = {
            'waf_stressor_version': '1.0.0',
            'report_format': 'json',
            'generated_at': datetime.now().isoformat(),
            'scan_info': {
                'target': self.target_url,
                'profile': self.profile.value if self.profile else 'unknown',
                'budget': self.config.budget if self.config else 0,
                'rate_limit': self.config.rate_limit.requests_per_second if self.config else 0,
                'total_requests': len(self.results),
            },
            'executive_summary': {
                'total_tests': self.metrics.total_requests,
                'allowed': self.metrics.allowed_requests,
                'blocked': self.metrics.blocked_requests,
                'errors': self.metrics.error_requests,
                'unique_status_codes': list(self.metrics.unique_status_codes),
            },
            'metrics': self.metrics.to_dict(),
            'waf_fingerprint': self.waf_fingerprint,
            'findings': [f.to_dict() for f in self.findings],
            'statistics': self.stats,
            'detailed_results': []
        }

        # Add detailed results
        for result in self.results:
            report['detailed_results'].append({
                'url': result.url,
                'variant_type': result.variant.variant_type.value,
                'method': result.request_config.method.value,
                'status_code': result.response_signature.status_code,
                'body_length': result.response_signature.body_length,
                'body_hash': result.response_signature.body_hash,
                'elapsed_time_ms': round(result.response_signature.elapsed_time * 1000, 2),
                'blocked': result.blocked,
                'waf_detected': result.waf_detected,
                'waf_name': result.waf_name,
                'anomaly_detected': result.anomaly_detected,
                'payload': result.variant.payload.raw if result.variant.payload else None,
                'payload_category': result.variant.payload.category if result.variant.payload else None,
                'timestamp': result.timestamp,
                'error': result.error
            })

        output_file = output_path.with_suffix('.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return output_file

    def _generate_markdown(self, output_path: Path) -> Path:
        """Generate comprehensive Markdown report"""
        md = []

        # Header
        md.append("# 🛡️ WAF Stressor Security Test Report\n\n")
        md.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        md.append(f"**Target**: `{self.target_url}`\n\n")
        if self.profile:
            md.append(f"**Profile**: {self.profile.value.upper()}\n\n")
        md.append("---\n\n")

        # Executive Summary
        md.append("## 📊 Executive Summary\n\n")
        md.append(f"- **Total Tests**: {self.metrics.total_requests}\n")
        md.append(f"- **Allowed**: {self.metrics.allowed_requests}\n")
        md.append(f"- **Blocked**: {self.metrics.blocked_requests}\n")
        md.append(f"- **Errors**: {self.metrics.error_requests}\n")
        md.append(f"- **Unique Status Codes**: {len(self.metrics.unique_status_codes)}\n\n")

        # WAF Detection
        md.append("## 🛡️ WAF Detection\n\n")
        if self.waf_fingerprint:
            md.append(f"✅ **WAF Detected**: {self.waf_fingerprint.upper()}\n\n")
        else:
            md.append("❌ **No WAF detected** (or very permissive configuration)\n\n")

        # Quality Metrics
        md.append("## 📈 Quality Metrics\n\n")
        md.append("| Metric | Score | Description |\n")
        md.append("|--------|-------|-------------|\n")
        md.append(f"| **Uniformity Index (UI)** | {self.metrics.uniformity_index:.3f} | Consistency of behavior |\n")
        md.append(f"| **Normalization Factor (NF)** | {self.metrics.normalization_factor:.3f} | URL normalization quality |\n")
        md.append(f"| **Mutation Potency (MP)** | {self.metrics.mutation_potency:.3f} | HTTP method consistency |\n")
        md.append(f"| **Payload Penetration (PP)** | {self.metrics.payload_penetration:.3f} | Payload delivery success |\n")
        md.append(f"| **Consistency Coefficient (CC)** | {self.metrics.consistency_coefficient:.3f} | Caching behavior |\n")
        md.append(f"| **Status Code Variance (SC)** | {self.metrics.status_code_variance:.3f} | Response variance |\n\n")

        # Findings
        if self.findings:
            md.append("## 🔍 Security Findings\n\n")
            for i, finding in enumerate(self.findings, 1):
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🔵',
                    'info': '⚪'
                }.get(finding.severity.value, '⚪')

                md.append(f"### {severity_emoji} Finding #{i}: {finding.title}\n\n")
                md.append(f"**Severity**: `{finding.severity.value.upper()}`\n\n")
                md.append(f"**Type**: {finding.vulnerability_type.value}\n\n")
                md.append(f"**Description**: {finding.description}\n\n")
                md.append(f"**URL**: `{finding.url}`\n\n")
                if finding.payload and finding.payload != "N/A":
                    md.append(f"**Payload**: `{finding.payload}`\n\n")
                md.append("---\n\n")
        else:
            md.append("## 🔍 Security Findings\n\n")
            md.append("✅ **No significant security issues found**\n\n")

        # Statistics
        md.append("## 📊 Test Statistics\n\n")

        # Response Time Stats
        if self.stats['response_times']:
            avg_time = statistics.mean(self.stats['response_times'])
            min_time = min(self.stats['response_times'])
            max_time = max(self.stats['response_times'])
            md.append(f"**Response Times**:\n")
            md.append(f"- Average: {avg_time:.2f}ms\n")
            md.append(f"- Min: {min_time:.2f}ms\n")
            md.append(f"- Max: {max_time:.2f}ms\n\n")

        # Status Code Distribution
        md.append("### Status Code Distribution\n\n")
        md.append("| Status | Count | Percentage |\n")
        md.append("|--------|-------|------------|\n")
        for status, count in sorted(self.stats['status_distribution'].items()):
            percentage = (count / len(self.results)) * 100 if self.results else 0
            md.append(f"| {status} | {count} | {percentage:.1f}% |\n")
        md.append("\n")

        # Footer
        md.append("---\n\n")
        md.append("*Generated by WAF Stressor v1.0.0 - Ethical WAF Testing Tool*\n")

        output_file = output_path.with_suffix('.md')
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(''.join(md))

        return output_file

    def _generate_csv(self, output_path: Path) -> Path:
        """Generate detailed CSV report"""
        output_file = output_path.with_suffix('.csv')

        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                'Timestamp',
                'URL',
                'Variant Type',
                'Method',
                'Status',
                'Body Length',
                'Body Hash',
                'Elapsed Time (ms)',
                'Blocked',
                'WAF Detected',
                'WAF Name',
                'Anomaly',
                'Payload',
                'Payload Category',
                'Error'
            ])

            # Data rows
            for r in self.results:
                writer.writerow([
                    r.timestamp,
                    r.url,
                    r.variant.variant_type.value,
                    r.request_config.method.value,
                    r.response_signature.status_code,
                    r.response_signature.body_length,
                    r.response_signature.body_hash,
                    f"{r.response_signature.elapsed_time * 1000:.2f}",
                    'Yes' if r.blocked else 'No',
                    'Yes' if r.waf_detected else 'No',
                    r.waf_name or '',
                    'Yes' if r.anomaly_detected else 'No',
                    r.variant.payload.raw[:100] if r.variant.payload else '',
                    r.variant.payload.category if r.variant.payload else '',
                    r.error or ''
                ])

        return output_file

    def _generate_sarif(self, output_path: Path) -> Path:
        """Generate SARIF 2.1.0 format report for CI/CD integration"""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "WAF Stressor",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/ghostshinobi/waf-stressor",
                        "shortDescription": {"text": "Ethical WAF Testing Tool"},
                        "rules": self._generate_sarif_rules()
                    }
                },
                "results": [],
                "properties": {
                    "metrics": {
                        "uniformity_index": self.metrics.uniformity_index,
                        "normalization_factor": self.metrics.normalization_factor,
                        "mutation_potency": self.metrics.mutation_potency,
                        "payload_penetration": self.metrics.payload_penetration
                    }
                }
            }]
        }

        # Convert findings to SARIF results
        severity_map = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'none'
        }

        for finding in self.findings:
            sarif_result = {
                "ruleId": finding.vulnerability_type.value,
                "level": severity_map.get(finding.severity.value, 'note'),
                "message": {"text": finding.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.url}
                    }
                }]
            }

            sarif['runs'][0]['results'].append(sarif_result)

        output_file = output_path.with_suffix('.sarif')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)

        return output_file

    def _generate_sarif_rules(self) -> List[Dict[str, Any]]:
        """Generate SARIF rules definitions"""
        return [
            {
                "id": "unknown",
                "shortDescription": {"text": "Security Finding"},
                "defaultConfiguration": {"level": "warning"}
            },
            {
                "id": "xss",
                "shortDescription": {"text": "Cross-Site Scripting"},
                "defaultConfiguration": {"level": "error"}
            },
            {
                "id": "sql_injection",
                "shortDescription": {"text": "SQL Injection"},
                "defaultConfiguration": {"level": "error"}
            },
            {
                "id": "path_traversal",
                "shortDescription": {"text": "Path Traversal"},
                "defaultConfiguration": {"level": "error"}
            }
        ]

    def _generate_html(self, output_path: Path) -> Path:
        """Generate interactive HTML report"""
        waf_status = "✅ DETECTED" if self.waf_fingerprint else "❌ NOT DETECTED"
        waf_vendor = (self.waf_fingerprint or 'Unknown').upper()

        findings_html = ""
        for finding in self.findings:
            severity = finding.severity.value
            severity_class = severity.lower()
            findings_html += f"""
            <div class="finding {severity_class}">
                <h3>{finding.title}</h3>
                <p><strong>Severity:</strong> {severity.upper()}</p>
                <p><strong>Type:</strong> {finding.vulnerability_type.value}</p>
                <p><strong>Description:</strong> {finding.description}</p>
                <p><strong>URL:</strong> <code>{finding.url}</code></p>
                {f'<p><strong>Payload:</strong> <code>{finding.payload[:200]}</code></p>' if finding.payload and finding.payload != "N/A" else ''}
            </div>
            """

        # Build stats tables
        status_rows = ""
        for status, count in sorted(self.stats['status_distribution'].items()):
            pct = (count / len(self.results)) * 100 if self.results else 0
            status_rows += f"<tr><td>{status}</td><td>{count}</td><td>{pct:.1f}%</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Stressor Report - {self.target_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; margin-bottom: 20px; }}
        h2 {{ color: #555; margin-top: 30px; margin-bottom: 15px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .card {{ background: #f8f9fa; padding: 20px; border-radius: 5px; border-left: 4px solid #007bff; }}
        .card h3 {{ color: #666; font-size: 14px; margin-bottom: 5px; }}
        .card p {{ font-size: 24px; font-weight: bold; color: #333; }}
        .metrics table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .metrics th, .metrics td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        .metrics th {{ background: #007bff; color: white; }}
        .finding {{ padding: 20px; margin: 15px 0; border-radius: 5px; border-left: 4px solid #ffc107; background: #fff8e1; }}
        .finding.critical {{ border-left-color: #dc3545; background: #f8d7da; }}
        .finding.high {{ border-left-color: #fd7e14; background: #fff3cd; }}
        .finding.medium {{ border-left-color: #ffc107; background: #fff8e1; }}
        .finding.low {{ border-left-color: #17a2b8; background: #d1ecf1; }}
        .finding h3 {{ color: #333; margin-bottom: 10px; }}
        .waf-badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; background: #28a745; color: white; font-weight: bold; }}
        .waf-badge.not-detected {{ background: #dc3545; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }}
        footer {{ margin-top: 40px; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ WAF Stressor Security Test Report</h1>
        <p><strong>Target:</strong> <code>{self.target_url}</code></p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>WAF Status:</strong> <span class="waf-badge {'not-detected' if not self.waf_fingerprint else ''}">{waf_status} {waf_vendor if self.waf_fingerprint else ''}</span></p>

        <h2>📊 Executive Summary</h2>
        <div class="summary">
            <div class="card">
                <h3>Total Tests</h3>
                <p>{self.metrics.total_requests}</p>
            </div>
            <div class="card">
                <h3>Allowed</h3>
                <p>{self.metrics.allowed_requests}</p>
            </div>
            <div class="card">
                <h3>Blocked</h3>
                <p>{self.metrics.blocked_requests}</p>
            </div>
            <div class="card">
                <h3>Errors</h3>
                <p>{self.metrics.error_requests}</p>
            </div>
        </div>

        <h2>📈 Quality Metrics</h2>
        <div class="metrics">
            <table>
                <tr><th>Metric</th><th>Score</th><th>Description</th></tr>
                <tr><td>Uniformity Index (UI)</td><td>{self.metrics.uniformity_index:.3f}</td><td>Consistency of behavior</td></tr>
                <tr><td>Normalization Factor (NF)</td><td>{self.metrics.normalization_factor:.3f}</td><td>URL normalization quality</td></tr>
                <tr><td>Mutation Potency (MP)</td><td>{self.metrics.mutation_potency:.3f}</td><td>HTTP method consistency</td></tr>
                <tr><td>Payload Penetration (PP)</td><td>{self.metrics.payload_penetration:.3f}</td><td>Payload delivery success</td></tr>
                <tr><td>Consistency Coefficient (CC)</td><td>{self.metrics.consistency_coefficient:.3f}</td><td>Caching behavior</td></tr>
                <tr><td>Status Code Variance (SC)</td><td>{self.metrics.status_code_variance:.3f}</td><td>Response variance</td></tr>
            </table>
        </div>

        <h2>🔍 Security Findings</h2>
        {findings_html if findings_html else '<p>✅ No significant security issues found</p>'}

        <h2>📊 Status Code Distribution</h2>
        <div class="metrics">
            <table>
                <tr><th>Status Code</th><th>Count</th><th>Percentage</th></tr>
                {status_rows}
            </table>
        </div>

        <footer>
            <p>Generated by WAF Stressor v1.0.0 - Ethical WAF Testing Tool</p>
        </footer>
    </div>
</body>
</html>"""

        output_file = output_path.with_suffix('.html')
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_file


__all__ = ['ReportGenerator']
