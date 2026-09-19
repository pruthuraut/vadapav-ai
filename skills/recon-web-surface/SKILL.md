---
name: recon-web-surface
description: Map the authorized web surface with content discovery, historical URLs, API routes, uploads, downloads, admin paths, and safe response observations.
---

# Web surface mapping

```powershell
python -m bb_harness --target example.com --mode container --run content_discovery --export json
python -m bb_harness --target example.com --mode container --run link_param_discovery --export json
```

Use the full pipeline for normal operation so live-host filtering happens first. Results are written to `normalized/endpoints.json`, `normalized/parameters.json`, and the asset graph. Retain source and method metadata for every endpoint.

No authenticated traffic is assumed. HAR input belongs to the later hunt phase and must be explicitly supplied by the operator.
