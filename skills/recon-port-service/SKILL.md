---
name: recon-port-service
description: Perform bounded port and service discovery for authorized hosts and preserve service metadata for later review.
---

# Port and service discovery

```powershell
python -m bb_harness --target example.com --mode container --run port_scan --export json
```

The `port_*` checklist family is mapped to `PortScanAgent`. Keep the configured port set, concurrency, timeout, and rate limit bounded. Do not scan IPs or hosts that are not linked to the approved target.

Output: `normalized/open-ports.json` and `raw/ports/` within the domain/session artifact directory.
