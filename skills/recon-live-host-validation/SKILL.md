---
name: recon-live-host-validation
description: Validate discovered hosts with bounded HTTPS/HTTP probes, DNS metadata, redirect observations, and conservative takeover indicators.
---

# Live host validation

Run the complete recon command to invoke final validation after enumeration:

```powershell
python -m bb_harness --target example.com --mode container --run all --export json
```

The finalizer probes HTTPS first, then HTTP, persists status/title/IP data, and separates live HTTP hosts from DNS-only or dead records.

## Outputs

- `normalized/live-hosts.json`
- `normalized/subdomains.json` with `is_alive`, `http_status`, `http_title`, and IPs
- `reports/recon.md` summary

Takeover results are candidates only. A CNAME or provider fingerprint is not proof of takeover.
