---
name: recon-passive-enumeration
description: Discover in-scope subdomains and DNS intelligence using passive sources and bounded tool commands. Use at the start of recon.
---

# Passive enumeration

## Command

```powershell
python -m bb_harness --target example.com --mode container --run subdomain_enum --export json
```

The stage maps to the 50 `sub_*` checklist items and the `SubdomainEnumAgent`. Sources may include crt.sh, passive DNS APIs, certificate data, web archives, and installed passive tools.

## Outputs

```text
output/recon/example.com/<session-id>/
├── raw/passive/
├── raw/dns/
└── normalized/subdomains.json
```

Discovered names are deduplicated and stored with source, DNS/IP metadata, CNAME, and timestamps. API keys are read only from environment variables and are never written to artifacts.

## Safety

Passive sources and bounded DNS checks only. Do not test third-party names that merely appear in content, and do not register or claim dangling services.
