---
name: recon-export
description: Export a completed or partial recon session into portable, domain-separated JSON and Markdown artifacts.
---

# Recon export

The application exports automatically after `/run all` or the equivalent CLI command. The stable contract is:

```text
output/recon/<normalized-domain>/<session-id>/
├── subdomains.txt
├── live-hosts.txt
├── urls.txt
```

Important files:

- `manifest.json`: target, session, mode, status, stages, and layout.
- `normalized/*.json`: deduplicated inventories and checklist state.
- `normalized/asset-graph.json`: relationships across domains, hosts, ports, technologies, endpoints, and parameters.
- `reports/recon.json`: complete machine-readable snapshot.
- `reports/recon.md`: operator-friendly summary.

The root `.txt` files are shell-pipeline aliases. Canonical line-oriented
copies are also written under `normalized/`, while every external tool result
is captured as a text file under its stage in `raw/`.

The SQLite database remains local runtime state and is ignored by Git. Never commit `output/`, `data/`, `.env`, cookies, tokens, HAR files, or raw authenticated traffic.
