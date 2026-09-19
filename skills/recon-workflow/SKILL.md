---
name: recon-workflow
description: Plan and run the complete authorized bb-harness recon workflow with deterministic stage ordering, bounded execution, and per-domain artifacts. Use for a new recon target or a complete attack-surface inventory.
---

# Recon workflow

This is the top-level recon skill. It coordinates the stage skills and keeps the 230-item checklist as the source of coverage truth.

## Command plan

```powershell
# One target
python -m bb_harness --target example.com --mode container --run all --export json

# Wildcard roots are normalized to the authorized base domain
python -m bb_harness --target "*.example.com" --mode container --run all --export json

# Newline-delimited target file
python -m bb_harness --target domains.txt --mode container --run all --export json
```

For the repository wrapper:

```powershell
./recon.ps1 -Target example.com -Mode container
```

## Stage order

1. `recon-passive-enumeration`: certificate transparency, passive APIs, search sources, and tool-backed subdomain discovery.
2. `recon-live-host-validation`: DNS resolution, HTTPS/HTTP probes, status/title collection, and takeover candidates.
3. `recon-port-service`: bounded port and service discovery for in-scope hosts.
4. `recon-web-surface`: content discovery, crawled URLs, API routes, uploads, admin paths, and downloads.
5. `recon-technology-js`: technology fingerprints, JavaScript routes, parameters, and metadata.
6. `recon-export`: normalized asset graph, reports, and checklist coverage snapshot.

The implementation maps these stages onto the existing agents and every checklist item remains represented in `security-checklist.txt` and `bb_harness/core/checklist.py`.

## Completion criteria

- The target is normalized and remains in scope.
- Every applicable checklist item has a persisted status.
- Dead hosts remain inventory records but are excluded from downstream web checks.
- The run writes `output/recon/<domain>/<session_id>/manifest.json` and `reports/recon.md`.
- Missing external tools are recorded as skipped/failed; they are never silently treated as successful.

## Safety

Use only authorized domains. Keep Docker mode, request budgets, timeouts, and rate limits enabled. This skill performs discovery and read-only observations; it does not exploit, authenticate, upload, brute-force, or claim third-party resources.
