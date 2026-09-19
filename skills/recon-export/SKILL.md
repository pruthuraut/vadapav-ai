---
name: recon-export
description: Export a completed or partial recon session into portable, domain-separated JSON and Markdown artifacts.
---

# Recon export

The application exports automatically after `/run all` or the equivalent CLI command. The stable contract is:

```text
output/recon/<normalized-domain>/<session-id>/
```

Important files:

- `manifest.json`: target, session, mode, status, stages, and layout.
- `normalized/*.json`: deduplicated inventories and checklist state.
- `normalized/asset-graph.json`: relationships across domains, hosts, ports, technologies, endpoints, and parameters.
- `reports/recon.json`: complete machine-readable snapshot.
- `reports/recon.md`: operator-friendly summary.

The SQLite database remains local runtime state and is ignored by Git. Never commit `output/`, `data/`, `.env`, cookies, tokens, HAR files, or raw authenticated traffic.
