
````markdown
# 🛡️ WAF Stressor  

WAF Stressor is a production-grade assessment engine designed for ethical security research, penetration testing, and bug bounty operations.  
It provides advanced URL normalization fuzzing, payload mutation, and multi-signal WAF fingerprinting to identify bypass vectors and inconsistent filtering behaviors.

---

# 📘 Table of Contents

- [✨ Features]
- [📦 Installation]
- [🚀 Quick Start]
- [📖 Usage Examples]
- [🎛️ Command-Line Options]
- [📊 Understanding Output]
- [📁 Report Formats]
- [🎯 Use Cases]
- [🔬 Payload Files]
- [🛠️ Advanced Configuration]
- [📈 Performance Tips]
- [🔍 Result Analysis]
- [⚠️ Legal & Ethical Use]
- [📝 Contributing]
- [📄 License]
- [🔗 Links]
- [🙏 Acknowledgments]

---

# ✨ Features



- 🔍 **WAF Detection & Fingerprinting**  
  Detects 15+ major WAF vendors (Cloudflare, Akamai, AWS, Imperva, F5, ModSecurity, etc.)

- 🎯 **URL Normalization Testing**  
  15+ URL mangling techniques to detect bypass vectors

- 💣 **Payload Mutation Engine**  
  Encodings, obfuscation layers, variant generation

- 📊 **Advanced Metrics**  
  Includes UI, NF, MP, PP, CC, SC

- 🚨 **Automated Finding Generation**  
  Bypass identification, inconsistencies, normalization flaws

- 📁 **Multi-Format Reports**  
  JSON, Markdown, HTML, CSV, SARIF (CI/CD compatible)

- ⚡ **Rate Limiting & Backoff**  
  429-aware with exponential backoff

- 🔄 **Batch Scanning**  
  Multi-target support, error recovery, progress tracking


---

# 📦 Installation

## Requirements
- Python **3.8+**
- pip

## Quick Install
```bash
git clone https://github.com/theghostshinobi/waf-stressor.git
cd waf-stressor
````

## Manual Dependencies

```bash
pip install httpx rich
```

---

# 🚀 Quick Start

### Single Target

```bash
python run.py https://example.com --budget 50
```

### With Custom Payloads

```bash
python run.py https://example.com \
  --payload-file xss-payloads.txt \
  --profile light \
  --budget 50
```

### Deep Scan + Rate Limiting

```bash
python run.py https://example.com \
  --payload-file xss-payloads.txt \
  --profile deep \
  --budget 100 \
  --rate 0.5 \
  --no-verify-tls
```


---

# 📖 Usage Examples

### 1) Quick Assessment

```bash
python run.py https://target.com --profile light --budget 30
```

### 2) Comprehensive WAF Analysis

```bash
python run.py https://target.com \
  --payload-file xss-payloads.txt \
  --profile deep \
  --budget 200 \
  --rate 1.0 \
  --output-dir target_scan
```

### 3) Cloudflare Targets

```bash
python run.py https://cloudflare-protected.com \
  --payload-file xss-payloads.txt \
  --budget 50 \
  --rate 0.5 \
  --no-verify-tls
```

### 4) Batch Scanning

```bash
python waf-stressor-engine.py \
  -t targets.txt \
  -f xss-payloads.txt \
  --budget 30 \
  --rate 1.0 \
  --format json
```

### 5) Advanced Batch

```bash
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

---

# 🎛️ Command-Line Options

<details>
<summary><strong>Show Single Target (run.py)</strong></summary>

| Option            | Description        | Default      |
| ----------------- | ------------------ | ------------ |
| `--profile`       | light / deep       | light        |
| `--budget`        | Max requests       | 50           |
| `--rate`          | Requests/sec       | 1.0          |
| `--payload-file`  | Payload file       | payloads.txt |
| `--output-dir`    | Results dir        | scan_results |
| `--no-verify-tls` | Disable TLS checks | False        |
| `--timeout`       | Request timeout    | 30           |
| `--max-redirects` | Redirect limit     | 5            |

</details>

| Option     | Description                | Default          |
| ---------- | -------------------------- | ---------------- |
| `-t`       | Targets file               | Required         |
| `-f`       | Payload file               | xss-payloads.txt |
| `-o`       | Output dir                 | results          |
| `-p`       | Profile                    | light            |
| `-b`       | Budget                     | 50               |
| `-r`       | Rate                       | 0.5              |
| `--format` | json, md, csv, sarif, html | json             |
| `-v`       | Verbose                    | False            |


| Option            | Description           | Default |
| ----------------- | --------------------- | ------- |
| `-d`              | Delay between targets | 10      |
| `--timeout`       | Scan timeout          | 300     |
| `--tls-verify`    | Enable TLS verify     | False   |
| `--stop-on-error` | Halt on errors        | False   |

---

# 📊 Understanding Output

```
============================================================
✅ SCAN COMPLETE

Target: https://example.com
Profile: LIGHT
Total Requests: 48
Elapsed: 49.35s
Success Rate: 100%

WAF DETECTED: cloudflare
```

### Metrics Explained

| Metric | Meaning                 |
| ------ | ----------------------- |
| **UI** | Uniformity Index        |
| **NF** | Normalization Factor    |
| **MP** | Mutation Potency        |
| **PP** | Payload Penetration     |
| **CC** | Consistency Coefficient |
| **SC** | Status Code Variance    |


---

# 📁 Report Formats

* **JSON** — structured data
* **Markdown** — human readable
* **HTML** — color-coded UI
* **CSV** — quick parsing
* **SARIF** — GitHub/CI integration
---

# 🎯 Use Cases

### Bug Bounty

```bash
python run.py https://target.hackerone.com/api \
  --payload-file xss-payloads.txt \
  --budget 100 \
  --rate 0.3 \
  --no-verify-tls \
  --output-dir bounty_results
```

### Pentesting

```bash
python cli.py -t client-targets.txt -f payloads.txt --profile deep --budget 200 --format md --verbose
```

### WAF Effectiveness

### CI/CD SARIF Integration


---

# 🔬 Payload Files


Format:

```
payload | category | description
```

Example:

```
<script>alert(1)</script> | xss_benign | Basic XSS test
' OR '1'='1             | sql_benign | SQL injection probe
../../../etc/passwd     | path_traversal | Traversal test
```



---

# 🛠️ Advanced Configuration

<details>
<summary><strong>Show Advanced Configuration</strong></summary>

### Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Rate Limiting

```bash
python run.py https://target.com --rate 0.2 --budget 20 --delay 5
```

### Custom Headers

```python
config = TestConfig(
  target_url="https://example.com",
  custom_headers={
    'User-Agent': 'Custom-Agent/1.0',
    'X-Custom-Header': 'value'
  }
)
```


---

# 📈 Performance Tips

* **Quick scans:** budget **20–30**
* **Standard scans:** **50–100**
* **Deep scans:** **150–300**
* Aggressive WAF → rate: **0.2–0.5**


---

# 🔍 Result Analysis

```bash
jq '.waf_fingerprint'
jq '.findings[]'
jq '(.metrics.blocked_requests / .metrics.total_requests * 100)'
jq '.results[] | select(.blocked==false)'
```


---

# ⚠️ Legal & Ethical Use

**Only test systems you own or have explicit authorization for.**
Unauthorized testing may be illegal.

---

# 📝 Contributing

Fork → Branch → PR (with full description).

---

# 📄 License

MIT License.

---

# 🔗 Links

* **Repository**
  [https://github.com/theghostshinobi/waf-stressor](https://github.com/theghostshinobi/waf-stressor)
* **Issues**
  [https://github.com/theghostshinobi/waf-stressor/issues](https://github.com/theghostshinobi/waf-stressor/issues)

---

# 🙏 Acknowledgments

Built for security researchers, red teams, and bug bounty professionals.
**Happy hunting! 🎯**


