```markdown
# 🛡️ WAF Stressor

**Advanced Web Application Firewall Testing Framework for Security Researchers**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-theghostshinobi%2Fwaf--stressor-black)](https://github.com/theghostshinobi/waf-stressor)

WAF Stressor is a production-grade penetration testing tool designed for ethical security research and bug bounty hunting. It employs advanced URL normalization techniques, payload mutation strategies, and multi-signal WAF fingerprinting to identify security gaps in Web Application Firewall implementations.

---

## ✨ Features

- **🔍 WAF Detection & Fingerprinting**: Automatically identifies 15+ WAF vendors (Cloudflare, Akamai, AWS WAF, Imperva, F5, ModSecurity, and more)
- **🎯 URL Normalization Testing**: 15+ URL manipulation techniques to test WAF bypass vectors
- **💣 Payload Mutation Engine**: Advanced payload delivery with encoding, obfuscation, and variant generation
- **📊 Advanced Metrics**: 6 quality metrics including Uniformity Index, Normalization Factor, and Payload Penetration
- **🚨 Automated Finding Generation**: Identifies bypass vectors, inconsistent blocking, and normalization issues
- **📁 Multi-Format Reports**: JSON, Markdown, HTML, CSV, and SARIF (GitHub Code Scanning compatible)
- **⚡ Rate Limiting & Budget Control**: Production-ready with exponential backoff and 429 handling
- **🔄 Batch Scanning**: Test multiple targets with progress tracking and error recovery

---

## 📦 Installation

### Requirements

- Python 3.8 or higher
- pip (Python package manager)

### Quick Install

```
git clone https://github.com/theghostshinobi/waf-stressor.git
cd waf-stressor
pip install -r requirements.txt
```

### Dependencies

```
httpx>=0.25.0
rich>=13.0.0
```

Install manually:

```
pip install httpx rich
```

---

## 🚀 Quick Start

### Basic Single-Target Scan

```
python run.py https://example.com --budget 50
```

### With Custom Payloads

```
python run.py https://example.com \
  --payload-file xss-payloads.txt \
  --profile light \
  --budget 50
```

### Deep Scan with Rate Limiting

```
python run.py https://example.com \
  --payload-file xss-payloads.txt \
  --profile deep \
  --budget 100 \
  --rate 0.5 \
  --no-verify-tls
```

---

## 📖 Usage Examples

### 1. Quick Vulnerability Assessment

```
python run.py https://target.com \
  --profile light \
  --budget 30
```

**Recommended for**: Initial reconnaissance, fast testing

### 2. Comprehensive WAF Analysis

```
python run.py https://target.com \
  --payload-file xss-payloads.txt \
  --profile deep \
  --budget 200 \
  --rate 1.0 \
  --output-dir target_scan
```

**Recommended for**: In-depth security assessments, bypass hunting

### 3. Cloudflare-Protected Target

```
python run.py https://cloudflare-protected-site.com \
  --payload-file xss-payloads.txt \
  --budget 50 \
  --rate 0.5 \
  --no-verify-tls
```

**Recommended for**: Testing against known WAF deployments

### 4. Batch Multi-Target Scanning

Create `targets.txt`:
```
https://target1.com/api
https://target2.com/login
https://target3.com/search
```

Run batch scan:
```
python waf-stressor-engine.py \
  -t targets.txt \
  -f xss-payloads.txt \
  --budget 30 \
  --rate 1.0 \
  --format json
```

**Recommended for**: Testing multiple endpoints, bug bounty programs

### 5. Advanced Batch with Custom Configuration

```
python cli.py \
  -t targets.txt \
  -f payloads.txt \
  --profile deep \
  --budget 100 \
  --rate 0.5 \
  --delay 10 \
  --format md \
  --verbose
```

**Recommended for**: Large-scale assessments, stealthy scanning

---

## 🎛️ Command-Line Options

### `run.py` - Single Target Scanner

```
python run.py <target-url> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--profile` | Scan profile: `light` or `deep` | `light` |
| `--budget` | Maximum number of HTTP requests | `50` |
| `--rate` | Requests per second | `1.0` |
| `--payload-file` | Path to payload file | `payloads.txt` |
| `--output-dir` | Output directory for reports | `scan_results` |
| `--no-verify-tls` | Disable TLS certificate verification | `False` |
| `--timeout` | Request timeout in seconds | `30` |
| `--max-redirects` | Maximum redirect follow count | `5` |

### `waf-stressor-engine.py` - Batch Scanner

```
python waf-stressor-engine.py -t <targets-file> -f <payloads-file> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --targets` | File with target URLs (one per line) | Required |
| `-f, --payloads` | Payload file path | `xss-payloads.txt` |
| `-o, --output` | Output directory | `results` |
| `-p, --profile` | Scan profile: `light` or `deep` | `light` |
| `-b, --budget` | Request budget per target | `50` |
| `-r, --rate` | Requests per second | `0.5` |
| `--format` | Report format: `json`, `md`, `csv`, `sarif`, `html` | `json` |
| `-v, --verbose` | Enable verbose output | `False` |

### `cli.py` - Advanced Batch Runner

```
python cli.py -t <targets-file> -f <payloads-file> [options]
```

Additional options:
| Option | Description | Default |
|--------|-------------|---------|
| `-d, --delay` | Delay between targets (seconds) | `10` |
| `--timeout` | Per-scan timeout (seconds) | `300` |
| `--tls-verify` | Enable TLS certificate verification | `False` |
| `--stop-on-error` | Stop batch on first error | `False` |

---

## 📊 Understanding the Output

### Scan Summary

```
============================================================
✅ SCAN COMPLETE
============================================================
📊 Target:          https://example.com
🎯 Profile:         LIGHT
📈 Total Requests:  48
⏱️  Elapsed Time:    49.35s
✔️  Success Rate:    100.0%

────────────────────────────────────────────────────────────
📊 METRICS
────────────────────────────────────────────────────────────
   Blocked:         13
   Allowed:         15
   Errors:          0
   Avg Response:    1002.57ms
   Min Response:    859.80ms
   Max Response:    1128.02ms

────────────────────────────────────────────────────────────
🛡️  WAF DETECTED: cloudflare
────────────────────────────────────────────────────────────
```

### Quality Metrics Explained

| Metric | Range | Description |
|--------|-------|-------------|
| **Uniformity Index (UI)** | 0.0 - 1.0 | Consistency of WAF behavior. High = consistent blocking |
| **Normalization Factor (NF)** | 0.0 - 1.0 | URL canonicalization quality. Low = potential bypass vectors |
| **Mutation Potency (MP)** | 0.0 - 1.0 | HTTP method consistency. Low = method-based bypass opportunities |
| **Payload Penetration (PP)** | 0.0 - 1.0 | Payload delivery success rate. High = weak filtering |
| **Consistency Coefficient (CC)** | 0.0 - 1.0 | Caching behavior consistency |
| **Status Code Variance (SC)** | 0.0 - 1.0 | Response diversity. High = inconsistent blocking |

### Finding Severity Levels

- **🔴 CRITICAL**: Confirmed WAF bypass vectors
- **🟠 HIGH**: Inconsistent blocking behavior
- **🟡 MEDIUM**: URL normalization weaknesses
- **🔵 LOW**: Timing anomalies, informational issues
- **⚪ INFO**: General observations

---

## 📁 Report Formats

### JSON Report

```
cat scan_results/*.json | jq '.metrics'
```

Structured data including all test results, metrics, and findings.

### Markdown Report

```
cat scan_results/*.md
```

Human-readable report with tables, metrics, and findings.

### HTML Report

```
open scan_results/*.html
```

Interactive report with styled metrics and color-coded severity levels.

### SARIF Report

```
cat scan_results/*.sarif
```

GitHub Code Scanning compatible format for CI/CD integration.

---

## 🎯 Use Cases

### Bug Bounty Hunting

```
python run.py https://target.hackerone.com/api/endpoint \
  --payload-file xss-payloads.txt \
  --budget 100 \
  --rate 0.3 \
  --no-verify-tls \
  --output-dir bounty_results
```

### Penetration Testing

```
python cli.py \
  -t client-targets.txt \
  -f comprehensive-payloads.txt \
  --profile deep \
  --budget 200 \
  --format md \
  --verbose
```

### WAF Effectiveness Assessment

```
python run.py https://waf-protected-app.com \
  --profile deep \
  --budget 150 \
  --rate 1.0
```

### CI/CD Security Testing

```
python waf-stressor-engine.py \
  -t production-endpoints.txt \
  -f security-payloads.txt \
  --budget 50 \
  --format sarif \
  -o sarif-reports
```

---

## 🔬 Payload Files

### Format

Pipe-delimited text file:
```
payload | category | description
```

### Example: `xss-payloads.txt`

```
<script>alert(1)</script> | xss_benign | Basic XSS test
<img src=x onerror=alert(1)> | xss_benign | Image XSS
<svg onload=alert(1)> | xss_benign | SVG XSS
' OR '1'='1 | sql_benign | SQL injection pattern
../../../etc/passwd | path_traversal | Path traversal test
```

### Creating Custom Payloads

```
cat > my-payloads.txt << 'EOF'
<script>alert(document.domain)</script> | xss_benign | Domain-based XSS
${7*7} | template_injection | SSTI test
';DROP TABLE users-- | sql_benign | SQL drop test
EOF
```

---

## 🛠️ Advanced Configuration

### Virtual Environment Setup

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Rate Limiting Configuration

For heavily protected targets:
```
python run.py https://target.com \
  --rate 0.2 \
  --budget 20 \
  --delay 5
```

### Custom Headers

Edit `core.py` to add custom headers:
```
config = TestConfig(
    target_url="https://example.com",
    custom_headers={
        'User-Agent': 'Custom-Agent/1.0',
        'X-Custom-Header': 'value'
    }
)
```

---

## 📈 Performance Tips

### Optimal Budget Settings

- **Quick scan**: `--budget 20-30`
- **Standard scan**: `--budget 50-100`
- **Deep scan**: `--budget 150-300`

### Rate Limiting Recommendations

- **Aggressive WAF**: `--rate 0.2-0.5`
- **Standard protection**: `--rate 0.5-1.0`
- **Minimal protection**: `--rate 1.0-2.0`

### Profile Selection

- **LIGHT**: 6-10 URL variants, ~30 requests
- **DEEP**: 20-30 URL variants, ~150+ requests

---

## 🔍 Analyzing Results

### Extract WAF Fingerprint

```
cat scan_results/*.json | jq '.waf_fingerprint'
```

### View All Findings

```
cat scan_results/*.json | jq '.findings[] | {severity, title, payload}'
```

### Calculate Block Rate

```
cat scan_results/*.json | jq '(.metrics.blocked_requests / .metrics.total_requests * 100)'
```

### List Successful Payloads

```
cat scan_results/*.json | jq '.results[] | select(.blocked==false and .request_config.payload != null) | .request_config.payload.raw'
```

---

## ⚠️ Legal & Ethical Use

**This tool is designed exclusively for authorized security testing.**

- ✅ Only test systems you own or have explicit written permission to test
- ✅ Respect bug bounty program scope and rules
- ✅ Follow responsible disclosure practices
- ✅ Comply with all applicable laws and regulations

**Unauthorized testing may be illegal in your jurisdiction.**

---

## 📝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🔗 Links

- **GitHub**: [https://github.com/theghostshinobi/waf-stressor](https://github.com/theghostshinobi/waf-stressor)
- **Issues**: [https://github.com/theghostshinobi/waf-stressor/issues](https://github.com/theghostshinobi/waf-stressor/issues)
- **Author**: [@theghostshinobi](https://github.com/theghostshinobi)

---

## 🙏 Acknowledgments

Built for the security research and bug bounty community.

**Happy hunting! 🎯**
```
