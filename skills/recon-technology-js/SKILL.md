---
name: recon-technology-js
description: Identify web technologies and extract route/parameter metadata from authorized responses and JavaScript without executing payloads.
---

# Technology and JavaScript analysis

```powershell
python -m bb_harness --target example.com --mode container --run tech_fingerprint --export json
```

Technology evidence is stored in `normalized/technologies.json`. JavaScript-derived endpoints and parameters are stored in `normalized/endpoints.json` and `normalized/parameters.json`; secrets are observations requiring sanitized review, never credentials to be reused.
