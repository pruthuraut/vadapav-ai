# bb-harness

Host-based, checklist-driven recon for authorized bug-bounty and research targets.
The project keeps the original TBHM-style 230-check coverage, Python fallbacks,
scope controls, SQLite session state, skills, and plain-text handoffs. Docker is
not required or used.

## Linux setup

Run this on Debian/Ubuntu Linux:

```bash
git clone https://github.com/pruthuraut/vadapav-ai.git
cd vadapav-ai
chmod +x setup_linux.sh
./setup_linux.sh
source "$HOME/security-tools/venv/bin/activate"
```

The setup script installs the Python dependencies, recon binaries, SecLists,
nuclei templates, and additional wordlists under `$HOME/wordlists`. It does not
create or request credentials.

## Windows setup

Native Windows setup is also supported through PowerShell and `winget`:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\setup_windows.ps1
.\.venv\Scripts\Activate.ps1
python recon.py example.com
```

The Windows script installs Python, Go, Git, and Nmap; builds the Go recon
tools; creates `.venv`; and downloads SecLists, nuclei templates, Commonspeak2,
and LinkFinder. Some Linux-only binaries such as massdns/masscan may be
unavailable natively; the Python fallbacks remain available, or use the Linux
setup on WSL for the complete native toolchain.

## Configure API keys

Use environment variables or a local ignored `.env` file copied from
`.env.example`:

```bash
cp .env.example .env
export SHODAN_API_KEY="..."
export SECURITYTRAILS_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
export CENSYS_API_ID="..."
export CENSYS_API_SECRET="..."
export CHAOS_API_KEY="..."
export GITHUB_TOKEN="..."
```

Credentials are read at runtime and never written to recon artifacts.

## Run recon

The small host entry point runs the existing checklist-driven agents:

```bash
python3 recon.py example.com
python3 recon.py '*.example.com'
python3 recon.py domains.txt
```

The equivalent module command is:

```bash
python3 -m bb_harness --target example.com --mode host --run all --export json
```

Only authorized targets should be supplied. Missing optional tools are recorded
as skipped; safe Python fallbacks continue where available.

## Output layout

Each target/session is isolated under:

```text
output/recon/<domain>/<session_id>/
├── subdomains.txt
├── live-hosts.txt
├── urls.txt
├── live-urls.txt
├── javascript.txt
├── interesting-params.txt
├── api-endpoints.txt
├── uploads.txt
├── admin-paths.txt
├── auth-paths.txt
├── raw/<stage>/*.txt
├── normalized/*.json and *.txt
└── reports/recon.{json,md}
```

`raw/<stage>/*.txt` contains actual stdout/stderr from installed tools. The
plain-text files are designed for piping into later tools. `urls.txt` retains
all discovered URLs; `live-urls.txt` is the optional `httpx`-validated subset.

## Skills

- `skills/bb-harness-recon/SKILL.md` — the single complete recon workflow.
- `skills/bb-harness-js-recon/SKILL.md` — downstream JS collection and analysis
  using the selected recon session’s URL handoffs.
- `skills/bb-harness-hunt/SKILL.md` — later guarded checklist/hunt workflow.

The authoritative checklist is `security-checklist.txt`; the supplied raw copy
is `raw.checklist.txt.txt`.

## Tests

```bash
python3 -m pytest -q
```

## Safety

This project is for authorized targets only. It performs bounded discovery and
read-only observations. It does not invent credentials, brute-force accounts,
execute exploit payloads, access internal services, exfiltrate data, or claim
third-party resources.
