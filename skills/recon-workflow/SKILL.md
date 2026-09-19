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

## Tool-flow reference

The implementation runs the equivalent bounded stages through the recon agents.
These commands describe the planned handoff files for operators using the
container toolchain directly:

```bash
TARGET="example.com"
RECON_DIR="output/recon/$TARGET/manual"
mkdir -p "$RECON_DIR" "$RECON_DIR/raw" "$RECON_DIR/candidates"

# Passive sources
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" \
  | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u \
  > "$RECON_DIR/subdomains.txt"
subfinder -d "$TARGET" -silent | anew "$RECON_DIR/subdomains.txt"
assetfinder --subs-only "$TARGET" | anew "$RECON_DIR/subdomains.txt"

# Resolve and validate live hosts
cat "$RECON_DIR/subdomains.txt" | dnsx -silent \
  | httpx -silent -status-code -title -tech-detect \
  | tee "$RECON_DIR/live-hosts.txt"

# Crawl and collect historical URLs
awk '{print $1}' "$RECON_DIR/live-hosts.txt" | katana -d 3 -jc -kf all -silent \
  | anew "$RECON_DIR/urls.txt"
echo "$TARGET" | waybackurls | anew "$RECON_DIR/urls.txt"
gau "$TARGET" --subs | anew "$RECON_DIR/urls.txt"

# Bounded template scan; findings are preliminary until reviewed
nuclei -l "$RECON_DIR/live-hosts.txt" \
  -severity critical,high,medium -o "$RECON_DIR/nuclei.txt"
```

For normal operation, prefer `python -m bb_harness ... --run all`; it writes
the same handoff files under a real session ID and preserves checklist status.

## Completion criteria

- The target is normalized and remains in scope.
- Every applicable checklist item has a persisted status.
- Dead hosts remain inventory records but are excluded from downstream web checks.
- The run writes `output/recon/<domain>/<session_id>/manifest.json` and `reports/recon.md`.
- Missing external tools are recorded as skipped/failed; they are never silently treated as successful.

## Safety

Use only authorized domains. Keep Docker mode, request budgets, timeouts, and rate limits enabled. This skill performs discovery and read-only observations; it does not exploit, authenticate, upload, brute-force, or claim third-party resources.
