---
name: bb-harness-recon
description: Run the complete authorized bb-harness recon workflow for one domain, wildcard root, or domain list. The single recon orchestrator runs the existing agents, uses ProjectDiscovery httpx for live filtering when available, falls back safely, and saves all outputs as text and JSON under a domain/session directory.
---

# bb-harness recon

This is the only recon skill. It is the entry point for the complete recon
workflow; the Python agents are implementation details, not separate skills.
Use it only for authorized targets.

## Run the main recon script

From the repository root:

```powershell
./recon.ps1 -Target example.com -Mode container
./recon.cmd example.com container
```

Equivalent command:

```powershell
python -m bb_harness --target example.com --mode container --run all --export json
```

The target may be a domain, `*.domain`, comma-separated domains, or a newline-
delimited domain file. Each target gets its own session and output directory.

## Execution policy

1. Start the existing five-agent recon pipeline and preserve all 230 checklist items.
2. Prefer container execution for external tools.
3. If Docker or a requested binary is unavailable, `DualRunner` falls back to an installed host tool or the existing safe Python implementation.
4. Keep scope, rate limits, timeouts, concurrency, and read-only behavior active.
5. Run ProjectDiscovery `httpx` against discovered hosts for HTTPS/HTTP liveness, status, title, and technology filtering when available. If the CLI is unavailable, use the existing bounded Python HTTP probe.
6. Run `httpx` against the discovered URL list when available and save the live URL subset. The complete discovered URL list is always retained.

## Output contract

```text
output/recon/<domain>/<session_id>/
├── subdomains.txt                 # all discovered names
├── live-hosts.txt                 # httpx/Python-validated hosts
├── urls.txt                       # all discovered URLs
├── live-urls.txt                  # httpx-validated URL subset
├── interesting-params.txt
├── api-endpoints.txt
├── uploads.txt
├── admin-paths.txt
├── auth-paths.txt
├── manifest.json
├── raw/<stage>/*.txt              # actual tool stdout/stderr
├── normalized/*.json and *.txt
└── reports/recon.{json,md}
```

The text files are intended for handoff to later tools. Sensitive query values
are redacted in text exports.

`urls.txt` is never replaced by the live filter. `live-urls.txt` is a separate
subset produced by ProjectDiscovery `httpx` when available; if the CLI is not
available, it is created empty and the existing Python recon results remain
available in the other inventories.

## Checklist and safety

The authoritative checklist is `security-checklist.txt`; the supplied raw
checklist is retained at `raw.checklist.txt.txt`. Do not claim a vulnerability
or takeover from a banner, status, CNAME, or tool output alone. Do not use
credentials, brute force, exploit payloads, upload files, access internal
services, or test third-party URLs merely because they appeared in content.
