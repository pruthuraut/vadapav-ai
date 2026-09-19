# bb-harness: The Bug Hunter's Methodology Recon Orchestrator

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)](https://www.docker.com/)
[![Checklist](https://img.shields.io/badge/methodology-230%20checks-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

> **Interactive, agentic recon harness inspired by *The Bug Hunter's Methodology* (TBHM v4.02 by Jason Haddix).**  
> Covers **230 checklist items** across 5 categories with an interactive slash-command shell, dual execution engine (native host with Python fallbacks or fully loaded Docker container), and SQLite persistence.

---

## Table of Contents
1. [Key Features](#key-features)
2. [Checklist Methodology Overview](#checklist-methodology-overview)
3. [Architecture](#architecture)
4. [Quick Start](#quick-start)
5. [Interactive Slash Commands](#interactive-slash-commands)
6. [Execution Modes (Host vs Container)](#execution-modes-host-vs-container)
7. [API Keys & OSINT Setup](#api-keys--osint-setup)
8. [Reporting & Exports](#reporting--exports)
9. [Development & Testing](#development--testing)

---

## Key Features

- 🎯 **Complete TBHM v4.02 Coverage**: Exactly **230 checklist items** across 5 categories.
- ⚡ **Dual Execution Engine**:
  - **Host Mode**: Runs locally using installed binaries or falls back transparently to native async Python implementations (DNS, HTTP/2, CT logs, socket scanning, regex extractors).
  - **Container Mode**: Runs inside a container pre-baked with ProjectDiscovery Go tools (`subfinder`, `httpx`, `nuclei`, `katana`, `naabu`), `amass`, `nmap`, `massdns`, SecLists, and more.
- 💬 **Interactive Slash-Command REPL**: Dynamic terminal UI with Rich banners, live status indicators, tables, and progress bars.
- 🗄️ **Persistent SQLite Database**: Stores subdomains, open ports, banners, technologies, endpoints, query parameters, and security findings with WAL journal mode.
- 📊 **Multi-Format Export**: Generates reports in Markdown, JSON, and HTML.

---

## Checklist Methodology Overview

| Agent Category | Checks | Focus Areas & Primary Tools |
|---|:---:|---|
| 🌐 **Subdomain Enumeration** | 50 | Passive OSINT (crt.sh, subfinder, amass, Shodan, Censys, SecurityTrails), DNS bruteforcing, permutation (altdns), zone transfers, CDN/CNAME takeover checks |
| 🔌 **Port & Service Scanning** | 50 | Fast discovery (`naabu`, `masscan`), service detection (`nmap -sV -sC`), web probing (`httpx`), protocol auditing (SSL/TLS, SMB, SNMP, Redis, DBs, Docker/K8s) |
| 🔍 **Tech Fingerprinting** | 40 | Web server & framework identification (`wappalyzer`, `whatweb`), CDN/WAF detection, header analysis, Favicon hashing (mmh3), Cloud metadata checks |
| 📁 **Content Discovery** | 50 | Web path bruteforcing (`ffuf`, `dirsearch`, `feroxbuster`), sensitive files (`.git`, `.env`, backup files, logs), exposed dashboards (Spring Actuator, Swagger, Admin consoles) |
| 🔗 **Link & Parameter Discovery** | 40 | Deep crawling (`katana`, `hakrawler`), JavaScript endpoint extraction (`LinkFinder`, `JSParser`), parameter discovery (`paramspider`, `arjun`), GraphQL schema introspection |
| **Total** | **230** | **Complete end-to-end recon coverage** |

---

## Architecture

```
bb-harness/
├── bb_harness/
│   ├── __init__.py
│   ├── __main__.py               # CLI entrypoint (python -m bb_harness)
│   ├── core/
│   │   ├── config.py             # Settings, timeouts, OSINT API keys
│   │   ├── models.py             # Dataclasses & enumerations
│   │   ├── checklist.py          # 230-item methodology checklist registry
│   │   ├── db.py                 # SQLite database & data access layer
│   │   └── runner.py             # DualRunner: HostRunner & ContainerRunner
│   ├── agents/
│   │   ├── base.py               # BaseAgent class with async executor & check tracking
│   │   ├── subdomain_enum.py     # 50 subdomain checks + Python fallback
│   │   ├── port_scan.py          # 50 port/service checks + socket fallback
│   │   ├── tech_fingerprint.py   # 40 tech checks + Favicon/Header fallback
│   │   ├── content_discovery.py  # 50 content checks + async HTTP brute fallback
│   │   └── link_param_discovery.py# 40 link & parameter discovery checks
│   └── cli/
│       ├── console.py            # Rich terminal output, tables, and live logs
│       └── repl.py               # Interactive slash-command REPL
├── tests/
│   └── test_harness.py           # Pytest suite
├── Dockerfile                    # Multi-stage build with Go recon tools + SecLists
├── docker-compose.yml            # Docker Compose configuration
├── requirements.txt              # Python dependencies
└── .env.example                  # Template for API keys
```

---

## Recon Skills and Domain-Scoped Artifacts

Recon is organized as composable skills under `skills/`, following a staged workflow:

1. `recon-passive-enumeration`
2. `recon-live-host-validation`
3. `recon-port-service`
4. `recon-web-surface`
5. `recon-technology-js`
6. `recon-export`

Run the full workflow with the Windows wrapper or the Python CLI:

```powershell
./recon.ps1 -Target example.com -Mode container
# or
python -m bb_harness --target example.com --mode container --run all --export json
```

Every run is isolated under `output/recon/<domain>/<session_id>/`:

```text
manifest.json
subdomains.txt, live-hosts.txt, urls.txt
raw/<stage>/
normalized/{subdomains,live-hosts,open-ports,technologies,endpoints,parameters,findings,checks}.json
normalized/asset-graph.json
normalized/{subdomains,live-hosts,open-ports,technologies,urls,endpoints,parameters,findings}.txt
raw/<stage>/<check>_<tool>_<sequence>.txt
reports/recon.json
reports/recon.md
logs/
```

The 230-item checklist remains authoritative in `security-checklist.txt`, with the raw source retained at `raw.checklist.txt.txt`. Runtime databases, reports, credentials, cookies, tokens, and `.env` files are ignored and must not be committed.

---

## Quick Start

### 1. Host Mode (Local)
```bash
# Clone and enter directory
cd bb-harness

# Install Python dependencies
pip install -r requirements.txt

# Launch interactive REPL
python -m bb_harness
```

### 2. Container Mode (Docker & Docker Compose)

The Dockerfile completely containerizes the entire harness (all Go recon binaries, Linux network scanners, SecLists wordlists, Python dependencies, SQLite database, and the REPL).

#### Using Docker Compose (Recommended):
```bash
# Build the complete image
docker compose build

# Launch the interactive REPL in container
docker compose run --rm bb-harness

# Or run headlessly with CLI flags (ideal for Claude Code / Codex / scripts):
docker compose run --rm bb-harness -t example.com --run all --export markdown
```

#### Using Docker directly:
```bash
# Build the image
docker build -t bb-harness:latest .

# Run interactive REPL with persistent data and output mounts:
docker run -it --rm \
  --network host \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/.env:/app/.env:ro \
  bb-harness:latest

# Run headlessly:
docker run --rm \
  --network host \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/.env:/app/.env:ro \
  bb-harness:latest -t example.com --run all --json
```

### 3. Claude Code / Codex / Headless Automation
When running from **Claude Code**, **OpenAI Codex**, or CI/CD pipelines where an interactive prompt cannot block for input, pass CLI flags directly:

```bash
# Full recon scan on target
python -m bb_harness -t example.com --run all --export markdown

# Run specific agent (e.g. Subdomain Enumeration)
python -m bb_harness -t example.com --run subdomain_enum

# Output structured JSON to stdout for AI parsing
python -m bb_harness -t example.com --run all --json

# View methodology checklist progress non-interactively
python -m bb_harness -t example.com --checklist

# View discovered assets
python -m bb_harness -t example.com --results findings
```

---

## Interactive Slash Commands

Inside the REPL, use slash commands to control the harness:

| Command | Arguments | Description |
|---|---|---|
| `/target` | `<domain>` | Set the target domain (e.g., `/target example.com`) |
| `/mode` | `host` \| `container` | Toggle between host execution and Docker container |
| `/agents` | - | Display all 5 recon agents, check counts, and enable state |
| `/enable` | `<agent_id>` \| `all` | Enable an agent or all agents |
| `/disable`| `<agent_id>` \| `all` | Disable an agent or all agents |
| `/run` | `all` \| `<agent_id>` | Start the recon pipeline asynchronously |
| `/checklist` | - | Display all 230 checks with status icons and findings |
| `/status` | - | Display current session statistics and metrics |
| `/results`| `sub` \| `ports` \| `tech` \| `ep` \| `params` \| `findings` \| `all` | Browse discovered targets and vulnerabilities |
| `/export` | `markdown` \| `json` \| `html` | Export full report to `output/reports/` |
| `/set` | `<param>=<val>` | Dynamically update scan parameters/keys in real time |
| `/config` | - | View current scan configuration and API key statuses |
| `/keys` | - | Check which external OSINT API keys are active |
| `/clear` | - | Clear the terminal screen |
| `/help` | - | Show command help |
| `/exit` | - | Quit the REPL |

---

## Execution Modes (Host vs Container)

- **Host Mode (`/mode host`)**:
  - Requires only Python 3.10+.
  - If external tools (like `subfinder`, `nmap`, etc.) are in your `PATH`, the harness invokes them.
  - If tools are absent, the harness executes native Python fallback logic (DNS resolution, crt.sh querying, socket connection scanning, HTTP header analysis, Favicon mmh3 hashing, HTML/JS regex parsing).
- **Container Mode (`/mode container`)**:
  - Automatically verifies Docker engine availability.
  - Executes tool commands inside the `bb-harness:latest` container.
  - Uses full toolchains: `subfinder`, `amass`, `assetfinder`, `findomain`, `naabu`, `nmap`, `masscan`, `httpx`, `nuclei`, `katana`, `ffuf`, `dirsearch`, `arjun`, `paramspider`, etc.

---

## API Keys & OSINT Setup

While **none of the API keys are strictly mandatory** (the harness will gracefully use free public APIs and native fallbacks like `crt.sh`, Wayback CDX, socket scanning, and DNS brute forcing), adding API keys unlocks deeper OSINT intelligence and proprietary databases.

### 1. Configure via `.env` File (Recommended)

Create a `.env` file from the provided template in the root directory:

**Windows PowerShell:**
```powershell
Copy-Item .env.example .env
```

**Linux / macOS:**
```bash
cp .env.example .env
```

Then edit `.env` with your API credentials:

```ini
# ── Passive & OSINT Subdomain Enumeration ──────────────────────────────────────
SHODAN_API_KEY=your_shodan_api_key
SECURITYTRAILS_API_KEY=your_securitytrails_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
CENSYS_API_ID=your_censys_api_id
CENSYS_API_SECRET=your_censys_api_secret
GITHUB_TOKEN=your_github_personal_access_token
CHAOS_API_KEY=your_projectdiscovery_chaos_api_key

# ── Tech Fingerprinting & Web Intelligence ─────────────────────────────────────
BUILTWITH_API_KEY=your_builtwith_api_key
WHOXY_API_KEY=your_whoxy_api_key
FOFA_EMAIL=your_fofa_email
FOFA_KEY=your_fofa_api_key
ZOOMEYE_API_KEY=your_zoomeye_api_key

# ── Performance & Network Tuning (Optional) ───────────────────────────────────
BB_MODE=host                 # Default execution mode: host or container
BB_MAX_CONCURRENCY=10        # Max concurrent checks per agent
BB_HTTP_TIMEOUT=15           # HTTP timeout in seconds
BB_RATE_LIMIT=50             # Requests per second throttle
```

> **Docker Container Integration**: The `docker-compose.yml` mounts `./.env:/app/.env:ro` automatically, so keys added to `.env` work seamlessly inside container mode as well.

---

### 2. Configure via Shell Environment Variables

You can also export keys temporarily in your terminal session without writing them to disk:

**Windows PowerShell:**
```powershell
$env:SHODAN_API_KEY="your_key"
$env:SECURITYTRAILS_API_KEY="your_key"
$env:VIRUSTOTAL_API_KEY="your_key"
$env:GITHUB_TOKEN="your_token"
```

**Linux / macOS (Bash / Zsh):**
```bash
export SHODAN_API_KEY="your_key"
export SECURITYTRAILS_API_KEY="your_key"
export VIRUSTOTAL_API_KEY="your_key"
export GITHUB_TOKEN="your_token"
```

---

### 3. Verify Active API Keys

Check which keys are loaded and detected at any time:

- **From the CLI / Claude Code / Codex**:
  ```bash
  python -m bb_harness --keys
  ```
- **From the Interactive REPL**:
  ```text
  bb-harness> /keys
  ```

Output displays a clear status table:
```text
           API Keys           
┌────────────────┬──────────────┐
│ Key            │ Status       │
├────────────────┼──────────────┤
│ Shodan         │ ✓ Configured │
│ SecurityTrails │ ✓ Configured │
│ VirusTotal     │ ✓ Configured │
│ Censys         │ ✗ Missing    │
│ GitHub         │ ✓ Configured │
│ Chaos (PD)     │ ✗ Missing    │
│ BuiltWith      │ ✗ Missing    │
│ Whoxy          │ ✗ Missing    │
│ FOFA           │ ✗ Missing    │
│ ZoomEye        │ ✗ Missing    │
└────────────────┴──────────────┘
```
Missing keys will simply be skipped by their specific checks while all remaining 230 checks continue uninterrupted.

---

## Development & Testing

Run unit and integration tests:
```bash
python -m pytest -v tests/
```

## Recon-driven security assessment

The project includes `.cursor/agents/recon-security-tester.md` and the reusable implementation `bb_harness/agents/security_testing.py`. It consumes the current session's recon assets and a plain-text checklist, correlates checks to discovered URLs, parameters, and technologies, and persists safe findings through the existing database.

```python
from bb_harness.agents.security_testing import ReconSecurityAgent, load_har

agent = ReconSecurityAgent(
    db, runner, session_id,
    checklist_path="security-checklist.txt",
    traffic=load_har("authenticated-traffic.har"),
)
coverage = await agent.assess()
plans = agent.build_test_plans()  # one auditable plan for every checklist line
```

HAR/Burp traffic is metadata-only by default: credentials are not persisted and arbitrary traffic is not replayed. Credential guessing, RCE, internal/cloud SSRF, exfiltration, and denial-of-service checks are recorded as blocked/manual. A future Burp MCP adapter can convert its request stream to `TrafficRecord` objects.

Each `TestPlan` preserves the original checklist text and includes targets, preconditions, ordered steps, execution mode, and proof requirements. A finding is only considered confirmed when sanitized request/response evidence and a reproducible security-relevant difference are recorded.

To start the separate post-recon phase, use `bb_harness.agents.attack_phase.AttackPhaseAgent` with the completed session, the full checklist file, and optional `TrafficRecord` objects from Burp/HAR. Its `start()` method returns one result for every checklist line.

For a short host command, use `hunt.cmd --domain adobe.io` (or `./hunt.ps1 -Domain adobe.io` in PowerShell). The wrapper selects the latest completed recon session for that domain. You can select a recon JSON or generated Markdown recon report directly with `hunt.cmd --recon output/reports/recon.json` and include an optional HAR with `--har output/input/adobe-auth.har`. An explicitly selected unfinished report is labeled `partial_report_backed` in the hunt output; domain-only selection still requires a finalized recon session.
