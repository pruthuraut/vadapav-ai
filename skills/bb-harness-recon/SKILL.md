---
name: bb-harness-recon
description: Run the bb-harness Dockerized recon workflow for an authorized domain, wildcard root, or domain list; validate live hosts, filter dead subdomains, check DNS/CNAME takeover indicators, and produce scoped reports. Use when the user asks to launch recon, enumerate subdomains, check live hosts, or assess subdomain takeover.
---

# bb-harness recon

Use this skill only for authorized targets.

## Launch

From the repository root:

```text
/recon example.com
/recon *.example.com
/recon domains.txt
```

If the host IDE does not support custom slash commands, use natural language or the Docker command documented in AGENTS.md/CLAUDE.md.

## Workflow

1. Normalize the target to its authorized base domain.
2. Run the existing recon agents in Docker with the supplied scope.
3. Resolve discovered subdomains and probe HTTPS first, then HTTP, using bounded concurrency and timeouts.
4. Persist `is_alive`, status code, title, and resolved IPs. Treat DNS-only records as discovered but not live HTTP hosts.
5. Check CNAMEs for known hosted-service fingerprints and dangling/NXDOMAIN targets. Record takeover candidates as potential until ownership or provider-specific claims are independently verified.
6. Exclude dead or out-of-scope hosts from downstream web testing while retaining them in the recon inventory.
7. Export a report showing total discovered, live, dead, unresolved, takeover candidates, and evidence.

## Safety

Do not claim takeover from a CNAME fingerprint alone. Do not register services, claim cloud resources, upload proof files, or modify DNS. Keep all probes read-only and in scope.

