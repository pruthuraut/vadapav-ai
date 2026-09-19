---
name: bb-harness-hunt
description: Run the bb-harness hunt phase by routing the complete checklist through safe, recon-driven family adapters and producing one result/evidence plan per item.
---

# BB Harness Hunt

Use this portable skill from Codex, Claude Code, or another IDE pointed at the repository.

## Workflow

1. Require a completed recon session and verify the target allowlist.
2. Load `security-checklist.txt` without changing or dropping checklist items.
3. Import an optional Burp HAR as authenticated request metadata only; never persist secrets or replay arbitrary state-changing requests automatically.
4. Correlate each item to recon assets, live-host results, technologies, parameters, and applicable family adapter.
5. Read `tools/tool-manifest.json` before selecting a tool. Use only tools marked present and safe for automatic execution.
6. For every checklist item, emit a result with status, selected family/tool, targets, exact safe steps, and proof requirements.
7. Mark high-impact or unavailable work `approval_required`, `blocked`, or `manual`; do not silently skip it.
8. Write JSON evidence and a Markdown summary for later `/triage` and `/report` phases.

## Commands

```text
python run_attack_phase.py --session <session-id> --checklist security-checklist.txt --output output/reports/attack_phase_report.json
python run_triage.py --input output/reports/attack_phase_report.json --output output/reports/triage.json --target <domain>
python run_validation.py --input output/reports/triage.json --output output/reports/validation.json --target <domain>
```

Interactive REPL routing is available through natural language or `/recon`, `/hunt`, `/triage`, and `/report` when the host application does not reserve those slash commands.

## Safety boundary

Do not automate brute force, credential stuffing, account takeover, RCE, internal/cloud metadata access, exfiltration, destructive uploads, request-smuggling attacks, DoS, CAPTCHA bypass, social engineering, or payment abuse. These require a dedicated approved adapter, explicit human approval, and an isolated test target. A tool being listed in the manifest does not grant permission to use it.
