---
name: bb-harness-recon
description: Run the staged bb-harness recon workflow for an authorized domain, wildcard root, or domain list; preserve all checklist coverage, validate live hosts, map the web surface, and write isolated per-domain artifacts. Use when the user asks to launch recon, enumerate subdomains, check live hosts, or assess an attack surface.
---

# bb-harness recon

Use this skill only for authorized targets.

## Launch

From the repository root, use the Docker wrapper for reproducible execution:

```text
/recon example.com
/recon *.example.com
/recon domains.txt

# Equivalent direct command
python -m bb_harness --target example.com --mode container --run all --export json
```

If the host IDE does not support custom slash commands, use natural language or the Docker command documented in AGENTS.md/CLAUDE.md.

## Workflow

1. Normalize the target to its authorized base domain.
2. Run the five existing recon agents in the planned order: subdomains, ports, technology, content, then links/parameters.
3. Resolve discovered subdomains and probe HTTPS first, then HTTP, using bounded concurrency and timeouts.
4. Persist `is_alive`, status code, title, and resolved IPs. Treat DNS-only records as discovered but not live HTTP hosts.
5. Check CNAMEs for known hosted-service fingerprints and dangling/NXDOMAIN targets. Record takeover candidates as potential until ownership or provider-specific claims are independently verified.
6. Exclude dead or out-of-scope hosts from downstream web testing while retaining them in the recon inventory.
7. Export a report showing total discovered, live, dead, unresolved, takeover candidates, and evidence.
8. Write a portable artifact tree under `output/recon/<domain>/<session_id>/`.

## Artifact contract

Each run is isolated by normalized domain and session:

```text
output/recon/example.com/<session-id>/
├── manifest.json
├── raw/
│   ├── passive/ dns/ live-hosts/ ports/
│   ├── technology/ web-surface/ js-analysis/ triage/
├── normalized/
│   ├── subdomains.json
│   ├── live-hosts.json
│   ├── open-ports.json
│   ├── technologies.json
│   ├── endpoints.json
│   ├── parameters.json
│   ├── findings.json
│   ├── checks.json
│   └── asset-graph.json
├── reports/
│   ├── recon.json
│   └── recon.md
└── logs/
```

The SQLite database is authoritative; JSON files are sanitized, portable snapshots for later skills.

## Safety

Do not claim takeover from a CNAME fingerprint alone. Do not register services, claim cloud resources, upload proof files, or modify DNS. Keep all probes read-only and in scope.
