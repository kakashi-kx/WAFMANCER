

```markdown



<p align="center">
  <a href="https://github.com/kakashi-kx/wafmancer"><img src="https://img.shields.io/badge/version-2.0.0-purple?style=for-the-badge"></a>
  <a href="#"><img src="https://img.shields.io/badge/python-3.10+-blue?style=for-the-badge&logo=python"></a>
  <a href="#"><img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge"></a>
  <a href="#"><img src="https://img.shields.io/badge/status-active-success?style=for-the-badge"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/WAF-Cloudflare-red?style=flat-square">
  <img src="https://img.shields.io/badge/WAF-AWS_WAF-orange?style=flat-square">
  <img src="https://img.shields.io/badge/WAF-Akamai-blue?style=flat-square">
  <img src="https://img.shields.io/badge/WAF-Sucuri-green?style=flat-square">
  <img src="https://img.shields.io/badge/WAF-ModSecurity-gray?style=flat-square">
</p>

# <p align="center">WAFMANCER v2.0</p>

<h4 align="center">Next-Generation WAF Evasion Research Framework</h4>

<p align="center">
  <b>Response Oracle Technology</b> 🟣 | <b>Neural Exploit Synthesis</b> 🧠 | <b>Trust Corruptor</b> 🔥
</p>

<p align="center">
  <i>"Not a tool. A research weapon."</i>
</p>

<p align="center">
  <b>crafted by :: <a href="https://github.com/kakashi-kx">kakashi-kx</a></b>
</p>

---

## 📖 TABLE OF CONTENTS

- [What is WAFMANCER?](#-what-is-wafmancer)
- [Why WAFMANCER is Different](#-why-wafmancer-is-different)
- [Features](#-features)
- [Modules](#-modules)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Attack Chain](#-attack-chain)
- [WAFs Tested](#-wafs-tested)
- [Configuration](#-configuration)
- [Project Structure](#-project-structure)
- [Bug Bounty Usage](#-bug-bounty-usage)
- [Screenshots](#-screenshots)
- [Research & Publications](#-research--publications)
- [Contributing](#-contributing)
- [Disclaimer](#-disclaimer)
- [License](#-license)
- [Credits](#-credits)

---

## 🧠 WHAT IS WAFMANCER?

WAFMANCER is a **research-grade WAF evasion framework** that introduces three novel attack concepts never before implemented in a single tool:

1. **Response Oracle Technology** — Maps the complete decision boundary of a WAF through systematic probing
2. **Neural Exploit Synthesis** — AI-powered payload generation that synthesizes never-before-seen attack vectors
3. **Trust Corruptor** — Exploits WAF reputation scoring by building trust before delivering payloads

Unlike traditional fuzzers that simply throw payloads at a target, WAFMANCER **understands** the WAF it's attacking and adapts its strategy accordingly.

---

## 🔥 WHY WAFMANCER IS DIFFERENT

| Feature | Traditional Tools | WAFMANCER |
|---------|------------------|-----------|
| Payload Generation | Pre-built wordlists | **AI-synthesized novel payloads** |
| WAF Interaction | Blind fuzzing | **Decision boundary mapping** |
| Delivery Strategy | Single request | **Trust-based multi-request timing** |
| WAF Awareness | None | **Fingerprinting + tactical profiles** |
| Output | Pass/Fail | **Full tactical intel + PoC + data exfiltration** |
| Reputation Exploitation | No concept | **Trust decay curve mapping** |
| ML Evasion | Basic encoding | **Multi-vector chaining + ML blindspot targeting** |

---

## ⚡ FEATURES

### Core Capabilities
- 🔮 **Response Oracle** — Maps WAF decision boundaries with 50+ mutation templates
- 🧬 **Smart Mutation Engine** — WAF-specific payloads (Cloudflare, AWS, Akamai, ModSecurity, Sucuri)
- 🎯 **WAF Fingerprinter** — Passive detection via header/cookie/response analysis
- 🧠 **Neural Exploit Synthesis** — AI-powered payload generation with 5-layer obfuscation chains
- 🔥 **Trust Corruptor** — Exploits WAF reputation scoring for timed payload delivery
- 💰 **Bug Bounty Mode** — Automated multi-target scanning with rate limiting
- 📊 **Research Database** — SQLite-backed findings with full history
- 📄 **Export Engine** — Publication-ready Markdown/JSON reports
- 🐍 **PoC Generator** — Auto-generated Python exploit scripts
- 🎨 **Cyberpunk Terminal** — Unique signature theme with tactical intel display

### Attack Techniques
- HTTP Request Smuggling (CL.TE, TE.CL, TE.TE variants)
- Header Injection & Manipulation
- Path Traversal & URL Obfuscation
- Unicode/HTML Entity/URL/Hex Encoding Bypasses
- Protocol-Level Attacks (HTTP/2, pipelining)
- Method Tampering
- Content-Type Confusion
- Cache Deception & Poisoning
- ML Blindspot Exploitation
- Reputation Score Manipulation

---

## 📦 MODULES

| Module | Command | Description |
|--------|---------|-------------|
| 🟣 Response Oracle | `wafmancer oracle` | Maps WAF decision boundaries |
| 🧠 Neural Exploit | `wafmancer neural` | AI-powered payload synthesis |
| 🔥 Trust Corruptor | `wafmancer corrupt` | Trust-based delivery + data exfiltration |
| 💰 Bug Bounty | `wafmancer bounty` | Automated multi-target scanning |
| 📊 History | `wafmancer history` | View research session history |
| 📈 Stats | `wafmancer stats` | Research statistics dashboard |
| 📄 Export | `wafmancer export` | Publication-ready reports |
| ℹ️ Info | `wafmancer info` | Configuration display |
| 📋 Modules | `wafmancer modules` | List all available modules |

---

## 🔧 INSTALLATION

### Prerequisites
- Python 3.10+
- pip
- git

### Setup

```bash
# Clone the repository
git clone https://github.com/CSAT-DEVELOPER/wafmancer.git
cd wafmancer

# Create virtual environment (recommended for Kali Linux)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install 'httpx[http2]' rich pyyaml structlog click

# Install WAFMANCER in development mode
pip install -e .
```

### Kali Linux Note
Kali uses PEP 668 externally-managed environments. Always use a virtual environment:
```bash
sudo apt install python3-venv -y
python3 -m venv venv
source venv/bin/activate
```

---

## 🚀 QUICK START

```bash
# 1. Run a basic scan
python -m wafmancer oracle -t https://example.com --probes 15

# 2. Generate AI-synthesized payloads
python -m wafmancer neural -p "<script>alert(1)</script>"

# 3. Deliver payload with trust manipulation
python -m wafmancer corrupt -t https://example.com -p "<script>alert(1)</script>"

# 4. View your research history
python -m wafmancer history

# 5. Check statistics
python -m wafmancer stats

# 6. Export findings
python -m wafmancer export
```

---

## 📝 USAGE EXAMPLES

### Oracle — Map WAF Decision Boundaries

```bash
# Basic scan
python -m wafmancer oracle -t https://example.com --probes 15

# Against Cloudflare with more probes
python -m wafmancer oracle -t https://www.cloudflare.com --probes 30

# Save report
python -m wafmancer oracle -t https://example.com -o report.md
```

### Neural — AI Payload Synthesis

```bash
# XSS payload synthesis
python -m wafmancer neural -p "<script>alert(1)</script>"

# SQLi targeting Cloudflare
python -m wafmancer neural -p "' OR 1=1 --" --waf Cloudflare

# Path traversal targeting AWS WAF
python -m wafmancer neural -p "../../../etc/passwd" --waf "AWS WAF"

# Command injection with ModSecurity profile
python -m wafmancer neural -p "; cat /etc/shadow" --waf ModSecurity
```

### Trust Corruptor — Trust-Based Delivery with Data Exfiltration

```bash
# Path traversal with data extraction
python -m wafmancer corrupt -t https://example.com -p "../../../etc/passwd"

# SQL injection bypass with Cloudflare profile
python -m wafmancer corrupt -t https://example.com -p "' OR 1=1 --" --waf Cloudflare

# Skip neural synthesis (use raw payload)
python -m wafmancer corrupt -t https://example.com -p "../../../etc/passwd" --no-synthesize

# Slow mode for aggressive WAFs
python -m wafmancer corrupt -t https://example.com -p "<script>alert(1)</script>" --requests 10
```

### Bounty Mode — Automated Multi-Target Scanning

```bash
# Create target list
cat > targets.txt << 'EOF'
https://api.example.com
https://app.example.com
https://admin.example.com
EOF

# Run bounty scan (bounty-compliant rate limiting)
python -m wafmancer bounty -f targets.txt --probes 15 --concurrency 1 --delay 5

# Export results
python -m wafmancer export
```

---

## 🔄 ATTACK CHAIN

```
┌─────────────────────────────────────────────────────────────────────┐
│                      WAFMANCER ATTACK CHAIN                          │
└─────────────────────────────────────────────────────────────────────┘

  STEP 1: ORACLE PROBES
  ├── Sends 50+ mutations at the target
  ├── Maps WAF decision boundary
  └── Output: "These payloads got blocked, these got through"

  STEP 2: FINGERPRINT
  ├── Identifies WAF vendor (Cloudflare, AWS, Akamai, etc.)
  └── Output: "Cloudflare detected — confidence 67%"

  STEP 3: NEURAL EXPLOIT SYNTHESIS
  ├── Takes BLOCKED payloads from Step 1
  ├── Synthesizes novel payloads via 5-layer obfuscation chains
  ├── Targets WAF-specific ML blindspots
  └── Output: "Here are NEW payloads that bypass ML detection"

  STEP 4: TRUST CORRUPTOR
  ├── Takes BYPASSED payloads from Step 3
  ├── Builds trust with benign browser-like requests
  ├── Maps trust decay curve
  ├── Injects payload at peak trust window
  └── Output: "DATA EXFILTRATED — 391,764 bytes"

  STEP 5: RESEARCH DATABASE
  ├── Saves all findings with full metadata
  ├── Generates PoC scripts
  └── Output: Publication-ready reports
```

---

## 🛡️ WAFS TESTED

| WAF Vendor | Detection | Bypass Rate | Difficulty |
|-----------|-----------|-------------|------------|
| **Cloudflare** | ✅ Fingerprinted | 37.5% | Medium |
| **AWS WAF** | ✅ Fingerprinted | — | Low-Medium |
| **Akamai Kona** | ✅ Fingerprinted | 0% (aggressive stream resets) | Hard |
| **Sucuri WAF** | ✅ Fingerprinted | 30% | Medium-High |
| **ModSecurity** | ✅ Fingerprinted | High | Low |
| **Fortinet** | Supported | — | — |
| **Citrix NetScaler** | Supported | — | — |
| **Imperva/Incapsula** | Supported | — | — |

---

## ⚙️ CONFIGURATION

Edit `config.yaml` to customize WAFMANCER:

```yaml
oracle:
  max_probes: 50          # Maximum probes per scan
  concurrency: 1           # 1 = bounty-compliant
  probe_delay: 0.6         # 600ms between probes

bounty:
  concurrency: 1           # Never parallel
  delay_between_targets: 5 # 5 seconds between targets
  probe_delay: 0.6         # ~1.6 req/sec (safe for 2/sec limit)
```

Environment variable overrides:
```bash
export WAFMANCER_ORACLE__MAX_PROBES=100
export WAFMANCER_LOGGING__LEVEL=DEBUG
```

---

## 📁 PROJECT STRUCTURE

```
wafmancer/
├── wafmancer/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                  # Rich CLI with cyberpunk theme
│   ├── config.py               # YAML configuration management
│   ├── logging_config.py       # Structured JSON logging
│   ├── exceptions.py           # Custom exception hierarchy
│   ├── core/
│   │   ├── __init__.py
│   │   ├── oracle.py           # Response Oracle Engine
│   │   ├── http_client.py      # Async HTTP/2 client
│   │   ├── diff_engine.py      # Advanced response comparison
│   │   ├── fingerprinter.py    # WAF fingerprinting
│   │   ├── mutation_engine.py  # 50+ payload library
│   │   ├── neural_exploit.py   # AI payload synthesis
│   │   ├── trust_corruptor.py  # Trust manipulation + data exfiltration
│   │   ├── bounty_mode.py      # Automated multi-target scanning
│   │   └── research_store.py   # SQLite research database
│   ├── utils/
│   │   └── helpers.py          # Utility functions
│   └── plugins/
│       ├── base.py             # Abstract plugin interface
│       └── fuzzer.py           # Advanced fuzzer plugin
├── config.yaml                 # Default configuration
├── requirements.txt
├── pyproject.toml              # Modern Python packaging
├── README.md
└── research/                   # Research findings
    └── findings_export.md
```

---

## 💰 BUG BOUNTY USAGE

### Best Practices

1. **Always read program rules first** — Different platforms have different rate limits
2. **Use bounty-compliant settings** — `--concurrency 1 --delay 5`
3. **Test on your own infrastructure first** — Verify WAFMANCER works before using on bounties
4. **Document everything** — WAFMANCER generates reports automatically
5. **Submit PoC scripts** — Auto-generated Python scripts prove impact

### Rate Limit Compliance

| Platform | Rate Limit | WAFMANCER Setting |
|----------|-----------|-------------------|
| HackerOne | 2 req/sec | `concurrency: 1, probe_delay: 0.6` |
| Bugcrowd | Varies | Check program policy |
| Intigriti | 3 req/sec | `concurrency: 1, probe_delay: 0.4` |
| YesWeHack | 2 req/sec | `concurrency: 1, probe_delay: 0.6` |

---

## 📸 SCREENSHOTS

<!-- ═══════════════════════════════════════════════════════════════════════ -->
<!--                         ADD YOUR SCREENSHOTS HERE                       -->
<!-- ═══════════════════════════════════════════════════════════════════════ -->

<!--
### Module List
![WAFMANCER Modules](screenshots/modules.png)

### Oracle Scanning a Target
![Oracle Scan](screenshots/oracle_scan.png)

### Bypass Found Against Cloudflare
![Cloudflare Bypass](screenshots/cloudflare_bypass.png)

### Data Exfiltration Display
![Data Exfiltration](screenshots/data_exfil.png)

### Statistics Dashboard
![Stats Dashboard](screenshots/stats.png)

### Bounty Mode Results
![Bounty Mode](screenshots/bounty_mode.png)

### Full Attack Report
![Attack Report](screenshots/report.png)
-->

> **📸 To add screenshots:** Create a `screenshots/` folder, add your PNG files, and uncomment the lines above.

---

## 📚 RESEARCH & PUBLICATIONS

### Novel Concepts Introduced

1. **Response Oracle Technology** — Systematic WAF decision boundary mapping
2. **Neural Exploit Synthesis** — AI-powered payload generation with multi-vector chaining
3. **Trust Corruptor** — WAF reputation score manipulation for timed payload delivery

### Potential Research Papers

- *"Mapping the Decision Boundary: A Systematic Approach to WAF Evasion"*
- *"Genetic Algorithms vs Machine Learning: Evolving Payloads to Bypass AI-Powered WAFs"*
- *"Trust No One: Exploiting Reputation Scoring in Modern Web Application Firewalls"*

---

## 🤝 CONTRIBUTING

Contributions are welcome! Areas for contribution:

- New WAF tactical profiles (`trust_corruptor.py`)
- Additional mutation templates (`mutation_engine.py`)
- New attack surfaces (`neural_exploit.py`)
- Improved WAF fingerprinting signatures (`fingerprinter.py`)
- Documentation improvements

---

## ⚠️ DISCLAIMER

**WAFMANCER is designed for authorized security research only.**

- ✅ Bug bounty programs (with permission)
- ✅ Authorized penetration tests
- ✅ Your own infrastructure
- ✅ Security research labs
- ❌ Unauthorized testing of third-party systems
- ❌ Illegal activities of any kind

**The authors assume no liability for misuse of this tool. Always obtain proper authorization before testing any system.**

---

## 📄 LICENSE

MIT License — See [LICENSE](LICENSE) for details.

---

## 🙏 CREDITS

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗    ██╗ █████╗ ███████╗███╗   ███╗ █████╗ ███╗   ██╗    ║
║   ██║    ██║██╔══██╗██╔════╝████╗ ████║██╔══██╗████╗  ██║    ║
║   ██║ █╗ ██║███████║█████╗  ██╔████╔██║███████║██╔██╗ ██║    ║
║   ██║███╗██║██╔══██║██╔══╝  ██║╚██╔╝██║██╔══██║██║╚██╗██║    ║
║   ╚███╔███╔╝██║  ██║██║     ██║ ╚═╝ ██║██║  ██║██║ ╚████║    ║
║    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝    ║
║                                                              ║
║         ✦ crafted by kakashi4kx / kakashi-kx ✦              ║
║                                                              ║
║          https://github.com/kakashi-kx/WAFMANCER             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

<p align="center">
  <b>WAFMANCER v2.0</b> — Response Oracle Technology<br>
  <sub>Next-Generation WAF Evasion Research Framework</sub>
</p>

<p align="center">
  <sub>⭐ Star this repo if you find it useful! ⭐</sub>
</p>
```

---

