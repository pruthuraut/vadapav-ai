"""
bb_harness.cli.repl
Interactive slash-command REPL — the main user interface for bb-harness.
"""
from __future__ import annotations
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.prompt import Prompt

from bb_harness.core.config import scan_config, api_keys, OUTPUT_DIR, REPORTS_DIR
from bb_harness.core.artifacts import ReconArtifacts
from bb_harness.core.db import Database
from bb_harness.core.runner import DualRunner, ContainerRunner, HostRunner
from bb_harness.core.checklist import build_checklist, CATEGORY_INFO, TOTAL_CHECKS
from bb_harness.core.models import CheckItem, CheckStatus, AgentCategory

from bb_harness.agents.subdomain_enum import SubdomainEnumAgent
from bb_harness.agents.port_scan import PortScanAgent
from bb_harness.agents.tech_fingerprint import TechFingerprintAgent
from bb_harness.agents.content_discovery import ContentDiscoveryAgent
from bb_harness.agents.link_param_discovery import LinkParamDiscoveryAgent
from bb_harness.agents.attack_phase import AttackPhaseAgent
from bb_harness.agents.security_testing import load_har

from bb_harness.cli.console import (
    console, print_banner, print_help, print_checklist,
    print_agents, print_summary, print_results_table,
    print_config, ScanConsole,
)


# ── Agent Registry ────────────────────────────────────────────────────────────
AGENT_CLASSES = {
    "subdomain_enum": SubdomainEnumAgent,
    "port_scan": PortScanAgent,
    "tech_fingerprint": TechFingerprintAgent,
    "content_discovery": ContentDiscoveryAgent,
    "link_param_discovery": LinkParamDiscoveryAgent,
}

AGENT_INFO = {
    "subdomain_enum": {
        "category": "🌐 Subdomains",
        "checks": 50,
        "description": "Passive & active subdomain discovery (subfinder, amass, crt.sh, APIs...)",
    },
    "port_scan": {
        "category": "🔌 Ports",
        "checks": 50,
        "description": "Port scanning, service enumeration, protocol checks (nmap, masscan...)",
    },
    "tech_fingerprint": {
        "category": "🔍 Tech",
        "checks": 40,
        "description": "Technology fingerprinting, framework detection, CDN/WAF identification",
    },
    "content_discovery": {
        "category": "📁 Content",
        "checks": 50,
        "description": "Hidden files, directories, admin panels, sensitive data exposure",
    },
    "link_param_discovery": {
        "category": "🔗 Links",
        "checks": 40,
        "description": "JS endpoint extraction, parameter discovery, API route mapping",
    },
}


class HarnessREPL:
    """Interactive slash-command REPL for the recon orchestrator."""

    def __init__(self):
        self.db = Database()
        self.runner = DualRunner(mode=scan_config.mode)
        self.session_id: Optional[str] = None
        self.enabled_agents: set = set(AGENT_CLASSES.keys())  # All enabled by default
        self.checklist: List[CheckItem] = build_checklist()
        self.scan_console = ScanConsole()
        self.is_running = False
        self.attack_report: Optional[dict] = None
        self.artifacts: Optional[ReconArtifacts] = None

    # ── Session Management ────────────────────────────────────────────────────

    def _ensure_session(self):
        """Create a session if one doesn't exist."""
        if not self.session_id:
            self.session_id = self.db.create_session(
                scan_config.target or "none", scan_config.mode
            )
            self.db.init_checks(self.session_id, self.checklist)
            self.artifacts = ReconArtifacts(scan_config.target or "none", self.session_id, scan_config.mode)
            self.artifacts.write_manifest("running")
        return self.session_id

    # ── Command Handlers ──────────────────────────────────────────────────────

    def _cmd_target(self, args: str):
        """Set the target domain."""
        target = args.strip().lower()
        target = target.lstrip("*.")
        # Strip protocol and path
        target = target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0].split(":")[0]
        if not target:
            if scan_config.target:
                console.print(f"[cyan]Current target:[/cyan] [bold]{scan_config.target}[/bold]")
            else:
                console.print("[red]Usage: /target <domain>[/red]")
            return

        scan_config.target = target
        # Create new session for new target
        self.session_id = self.db.create_session(target, scan_config.mode)
        self.db.init_checks(self.session_id, self.checklist)
        self.artifacts = ReconArtifacts(target, self.session_id, scan_config.mode)
        self.artifacts.write_manifest("running")
        console.print(f"[green]✓ Target set:[/green] [bold]{target}[/bold]")
        console.print(f"[dim]  Session: {self.session_id}[/dim]")

    async def _cmd_recon(self, args: str):
        """Run recon for one domain, wildcard root, comma list, or newline list file."""
        raw = args.strip()
        if not raw:
            console.print("[red]Usage: /recon <domain|*.domain|domains.txt|a.com,b.com>[/red]")
            return
        source = Path(raw)
        if source.is_file():
            targets = [line.strip() for line in source.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
        else:
            targets = [part.strip() for part in raw.split(",") if part.strip()]
        for target in targets:
            self._cmd_target(target)
            await self._cmd_run("all")

    async def _filter_live_urls(self):
        """Use ProjectDiscovery httpx to produce a live URL handoff file."""
        if not self.artifacts or not self.session_id:
            return
        urls = [str(row.get("url", "")) for row in self.db.get_endpoints(self.session_id) if row.get("url")]
        self.artifacts.write_lines("raw/web-surface/httpx-url-input.txt", urls)
        input_path = Path("recon") / self.artifacts.domain / self.session_id / "raw" / "web-surface" / "httpx-url-input.txt"
        result = await self.runner.run_tool(
            "httpx",
            f"httpx -l {input_path.as_posix()} -silent -status-code -title -tech-detect -follow-redirects",
            timeout=600,
        )
        self.artifacts.record_tool_output(
            "web-surface", "live-url-filter", "httpx", result.stdout,
            result.stderr, result.mode, result.returncode,
        )
        live_urls = []
        if result.success:
            for line in result.lines:
                match = re.match(r"https?://[^\s\[]+", line)
                if match:
                    live_urls.append(match.group(0))
        self.artifacts.write_lines("live-urls.txt", live_urls)
        self.artifacts.write_lines("normalized/live-urls.txt", live_urls)

    def _cmd_mode(self, args: str):
        """Switch execution mode."""
        mode = args.strip().lower()
        if mode not in ("host", "container"):
            console.print(f"[cyan]Current mode:[/cyan] [bold]{scan_config.mode}[/bold]")
            console.print("[dim]Usage: /mode <host|container>[/dim]")
            return

        if mode == "container":
            if not ContainerRunner.is_docker_available():
                console.print("[red]✗ Docker is not available or not running[/red]")
                return
            if not ContainerRunner.image_exists():
                console.print("[yellow]⟳ Building Docker image (bb-harness:latest)...[/yellow]")
                result = ContainerRunner.build_image()
                if not result.success:
                    console.print(f"[red]✗ Docker build failed: {result.stderr[:200]}[/red]")
                    return
                console.print("[green]✓ Docker image built successfully[/green]")

        scan_config.mode = mode
        self.runner = DualRunner(mode=mode)
        console.print(f"[green]✓ Mode set:[/green] [bold]{mode}[/bold]")

    def _cmd_checklist(self):
        """Show the full methodology checklist."""
        if not self.session_id:
            self._ensure_session()
        checks = self.db.get_checks(self.session_id)
        checks_by_category = {}
        for c in checks:
            cat = c.get("category", "unknown")
            checks_by_category.setdefault(cat, []).append(c)
        print_checklist(checks_by_category)

    def _cmd_agents(self):
        """List all agents."""
        print_agents(AGENT_INFO, self.enabled_agents)

    def _cmd_enable(self, args: str):
        """Enable an agent."""
        agent_id = args.strip().lower()
        if agent_id == "all":
            self.enabled_agents = set(AGENT_CLASSES.keys())
            console.print("[green]✓ All agents enabled[/green]")
        elif agent_id in AGENT_CLASSES:
            self.enabled_agents.add(agent_id)
            console.print(f"[green]✓ Agent enabled:[/green] {agent_id}")
        else:
            console.print(f"[red]Unknown agent: {agent_id}[/red]")
            console.print(f"[dim]Available: {', '.join(AGENT_CLASSES.keys())}[/dim]")

    def _cmd_disable(self, args: str):
        """Disable an agent."""
        agent_id = args.strip().lower()
        if agent_id == "all":
            self.enabled_agents.clear()
            console.print("[yellow]⊘ All agents disabled[/yellow]")
        elif agent_id in AGENT_CLASSES:
            self.enabled_agents.discard(agent_id)
            console.print(f"[yellow]⊘ Agent disabled:[/yellow] {agent_id}")
        else:
            console.print(f"[red]Unknown agent: {agent_id}[/red]")

    async def _cmd_run(self, args: str):
        """Execute the recon pipeline."""
        try:
            scan_config.validate()
        except ValueError as e:
            console.print(f"[red]✗ {e}[/red]")
            return

        self._ensure_session()
        agent_filter = args.strip().lower() if args.strip() else "all"

        # Determine which agents to run
        if agent_filter == "all":
            agents_to_run = [a for a in AGENT_CLASSES if a in self.enabled_agents]
        elif agent_filter in AGENT_CLASSES:
            if agent_filter not in self.enabled_agents:
                console.print(f"[yellow]Agent {agent_filter} is disabled. Enable it first with /enable {agent_filter}[/yellow]")
                return
            agents_to_run = [agent_filter]
        else:
            console.print(f"[red]Unknown agent or stage: {agent_filter}[/red]")
            return

        if not agents_to_run:
            console.print("[yellow]No agents enabled. Use /enable <agent|all>[/yellow]")
            return

        console.print(f"\n[bold cyan]🚀 Starting recon on [white]{scan_config.target}[/white] "
                       f"({scan_config.mode} mode)[/bold cyan]")
        console.print(f"[dim]  Agents: {', '.join(agents_to_run)}[/dim]\n")

        self.is_running = True

        # Category to agent class mapping
        cat_to_agent = {
            "subdomain_enum": AgentCategory.SUBDOMAIN_ENUM,
            "port_scan": AgentCategory.PORT_SCAN,
            "tech_fingerprint": AgentCategory.TECH_FINGERPRINT,
            "content_discovery": AgentCategory.CONTENT_DISCOVERY,
            "link_param_discovery": AgentCategory.LINK_PARAM_DISCOVERY,
        }

        for agent_id in agents_to_run:
            agent_cls = AGENT_CLASSES[agent_id]
            agent = agent_cls(self.db, self.runner, self.session_id)
            category = cat_to_agent[agent_id]

            # Get checks for this agent's category
            agent_checks = [c for c in self.checklist if c.category == category]

            self.scan_console.log_agent_start(agent.NAME, len(agent_checks))

            try:
                await agent.run_all(agent_checks, self.scan_console, concurrency=3)
            except KeyboardInterrupt:
                console.print("\n[yellow]⊘ Scan interrupted by user[/yellow]")
                break
            except Exception as e:
                console.print(f"[red]✗ Agent {agent_id} error: {e}[/red]")

            # Print interim summary
            summary = self.db.get_summary(self.session_id)
            self.scan_console.log_agent_done(agent.NAME, summary)

        # Enumeration agents run concurrently; finalize the complete inventory
        # only after all discovery checks have finished.
        if "subdomain_enum" in agents_to_run:
            finalizer = SubdomainEnumAgent(self.db, self.runner, self.session_id)
            final = await finalizer.finalize_recon()
            console.print(f"[green]✓ Live-host validation:[/green] {final['live_hosts']}/{final['subdomains_checked']} responsive")
            console.print(f"[green]✓ Takeover review:[/green] {final['takeover_candidates']} candidate(s)")

        if "content_discovery" in agents_to_run or "link_param_discovery" in agents_to_run:
            await self._filter_live_urls()

        if self.artifacts:
            artifact_status = "completed" if agent_filter == "all" else "partial"
            paths = self.artifacts.export_snapshot(self.db, artifact_status)
            console.print(f"[green]✓ Recon artifacts:[/green] {self.artifacts.root}")
            console.print(f"[dim]  Report: {paths['recon.md']}[/dim]")
            if artifact_status == "completed":
                self.db.finish_session(self.session_id)

        self.is_running = False
        console.print("\n[bold green]✓ Scan complete[/bold green]\n")
        self._cmd_status()

    async def _cmd_hunt(self, args: str):
        """Run the full checklist-driven post-recon assessment."""
        if not self.session_id:
            console.print("[red]Set a target and run recon first.[/red]")
            return
        checklist_path = Path("security-checklist.txt")
        if not checklist_path.exists():
            console.print(f"[red]Checklist not found: {checklist_path.resolve()}[/red]")
            return
        har_path = Path(args.strip()) if args.strip() else None
        if har_path and not har_path.exists():
            console.print(f"[red]HAR file not found: {har_path.resolve()}[/red]")
            return
        traffic = load_har(har_path) if har_path else []
        console.print(f"[bold cyan]Starting hunt for {scan_config.target} ({scan_config.mode} mode)[/bold cyan]")
        agent = AttackPhaseAgent(self.db, self.runner, self.session_id, checklist_path, traffic)
        self.attack_report = await agent.start()
        path = REPORTS_DIR / f"hunt_{scan_config.target.replace('.', '_')}_{self.session_id}.json"
        path.write_text(json.dumps(self.attack_report, indent=2), encoding="utf-8")
        console.print(f"[green]✓ Hunt complete:[/green] {path}")
        console.print(json.dumps(self.attack_report.get("summary", {}), indent=2))

    def _cmd_triage(self):
        """Create a conservative triage queue from hunt results."""
        if not self.attack_report:
            console.print("[red]Run /hunt first.[/red]")
            return
        queue = []
        for result in self.attack_report.get("results", []):
            if result.get("status") == "completed":
                queue.append({"check_id": result["check_id"], "checklist_text": result["checklist_text"], "state": "needs_review", "evidence": result.get("evidence", [])})
        triage = {"session_id": self.session_id, "target": scan_config.target, "confirmed": [], "needs_review": queue, "note": "No item is confirmed solely by automated coverage; reproduce and validate evidence before reporting."}
        path = REPORTS_DIR / f"triage_{scan_config.target.replace('.', '_')}_{self.session_id}.json"
        path.write_text(json.dumps(triage, indent=2), encoding="utf-8")
        console.print(f"[green]✓ Triage queue created:[/green] {path}")
        console.print(f"[dim]Items needing review: {len(queue)}[/dim]")

    def _cmd_report(self):
        """Write a Markdown report for the recon and hunt phases."""
        if not self.session_id:
            console.print("[red]No active session.[/red]")
            return
        summary = self.db.get_summary(self.session_id)
        lines = [f"# Security Assessment Report: {scan_config.target}", "", f"- Session: `{self.session_id}`", f"- Mode: `{scan_config.mode}`", "", "## Recon summary", "", "| Metric | Count |", "|---|---:|"]
        lines.extend(f"| {key.replace('_', ' ').title()} | {value} |" for key, value in summary.items())
        if self.attack_report:
            lines.extend(["", "## Hunt coverage", "", "| Status | Count |", "|---|---:|"])
            for key, value in self.attack_report.get("summary", {}).items():
                lines.append(f"| {key.replace('_', ' ').title()} | {value} |")
            lines.extend(["", "## Checklist results", "", "| ID | Checklist item | Family | Status |", "|---|---|---|---|"])
            for result in self.attack_report.get("results", []):
                text = result.get("checklist_text", "").replace("|", "\\|")
                lines.append(f"| {result.get('check_id')} | {text} | {result.get('family')} | {result.get('status')} |")
        lines.extend(["", "## Validation policy", "", "Automated observations are preliminary. A vulnerability must be reproduced with sanitized evidence and reviewed before it is marked confirmed."])
        path = REPORTS_DIR / f"security_report_{scan_config.target.replace('.', '_')}_{self.session_id}.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown report written:[/green] {path}")

    def _cmd_status(self):
        """Show current scan status."""
        if not self.session_id:
            console.print("[dim]No active scan. Set a target with /target <domain>[/dim]")
            return
        summary = self.db.get_summary(self.session_id)
        print_summary(summary, scan_config.target, scan_config.mode, self.session_id)

    def _cmd_results(self, args: str):
        """View scan results."""
        if not self.session_id:
            console.print("[dim]No results yet. Run a scan first.[/dim]")
            return

        result_type = args.strip().lower() if args.strip() else "all"

        if result_type in ("subdomains", "sub", "all"):
            data = self.db.get_subdomains(self.session_id)
            if data:
                print_results_table("Discovered Subdomains", [
                    ("Subdomain", "subdomain", 40),
                    ("Source", "source", 20),
                    ("Alive", "is_alive", 6),
                    ("HTTP", "http_status", 6),
                ], data)

        if result_type in ("ports", "port", "all"):
            data = self.db.get_ports(self.session_id)
            if data:
                print_results_table("Open Ports", [
                    ("Host", "host", 25),
                    ("Port", "port", 8),
                    ("Proto", "protocol", 6),
                    ("Service", "service", 15),
                    ("Version", "version", 20),
                ], data)

        if result_type in ("technologies", "tech", "all"):
            data = self.db.get_technologies(self.session_id)
            if data:
                print_results_table("Technologies", [
                    ("URL", "url", 30),
                    ("Technology", "name", 20),
                    ("Version", "version", 10),
                    ("Category", "category", 15),
                ], data)

        if result_type in ("endpoints", "ep", "all"):
            data = self.db.get_endpoints(self.session_id)
            if data:
                print_results_table("Endpoints", [
                    ("URL", "url", 50),
                    ("Status", "status_code", 8),
                    ("Source", "source", 15),
                ], data)

        if result_type in ("parameters", "params", "all"):
            data = self.db.get_parameters(self.session_id)
            if data:
                print_results_table("Parameters", [
                    ("URL", "url", 35),
                    ("Name", "name", 15),
                    ("Type", "param_type", 10),
                    ("Source", "source", 15),
                ], data)

        if result_type in ("findings", "find", "all"):
            data = self.db.get_findings(self.session_id)
            if data:
                print_results_table("Findings", [
                    ("Severity", "severity", 10),
                    ("Title", "title", 40),
                    ("URL", "url", 25),
                    ("Source", "source", 12),
                ], data)

    def _cmd_export(self, args: str):
        """Export scan results."""
        if not self.session_id:
            console.print("[dim]No results to export.[/dim]")
            return

        fmt = args.strip().lower() if args.strip() else "markdown"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = scan_config.target.replace(".", "_")
        export_dir = self.artifacts.reports if self.artifacts else REPORTS_DIR

        if fmt == "json":
            report = {
                "target": scan_config.target,
                "session_id": self.session_id,
                "mode": scan_config.mode,
                "exported_at": datetime.utcnow().isoformat(),
                "summary": self.db.get_summary(self.session_id),
                "subdomains": self.db.get_subdomains(self.session_id),
                "ports": self.db.get_ports(self.session_id),
                "technologies": self.db.get_technologies(self.session_id),
                "endpoints": self.db.get_endpoints(self.session_id),
                "parameters": self.db.get_parameters(self.session_id),
                "findings": self.db.get_findings(self.session_id),
                "checks": self.db.get_checks(self.session_id),
            }
            path = export_dir / f"report_{target_safe}_{timestamp}.json"
            path.write_text(json.dumps(report, indent=2))

        elif fmt in ("markdown", "md"):
            summary = self.db.get_summary(self.session_id)
            lines = [
                f"# Recon Report: {scan_config.target}",
                f"**Session:** {self.session_id}  ",
                f"**Mode:** {scan_config.mode}  ",
                f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
                "",
                "## Summary",
                "",
                "| Metric | Count |",
                "|--------|-------|",
            ]
            for k, v in summary.items():
                lines.append(f"| {k.title()} | {v} |")
            lines.append("")

            # Subdomains
            subs = self.db.get_subdomains(self.session_id)
            if subs:
                lines.append(f"## Subdomains ({len(subs)})")
                lines.append("")
                for s in subs:
                    lines.append(f"- `{s['subdomain']}` (source: {s['source']})")
                lines.append("")

            # Findings
            findings = self.db.get_findings(self.session_id)
            if findings:
                lines.append(f"## Findings ({len(findings)})")
                lines.append("")
                for f in findings:
                    sev = f['severity'].upper()
                    lines.append(f"### [{sev}] {f['title']}")
                    if f.get('url'):
                        lines.append(f"**URL:** {f['url']}  ")
                    if f.get('description'):
                        lines.append(f"{f['description']}  ")
                    lines.append("")

            path = export_dir / f"report_{target_safe}_{timestamp}.md"
            path.write_text("\n".join(lines))

        elif fmt == "html":
            # Simple HTML export
            summary = self.db.get_summary(self.session_id)
            html = f"""<!DOCTYPE html>
<html><head><title>Recon Report: {scan_config.target}</title>
<style>body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #30363d;padding:8px;text-align:left}}
th{{background:#161b22}}h1,h2{{color:#58a6ff}}.critical{{color:#f85149}}.high{{color:#db6d28}}
.medium{{color:#d29922}}.low{{color:#8b949e}}</style></head><body>
<h1>Recon Report: {scan_config.target}</h1>
<p>Session: {self.session_id} | Mode: {scan_config.mode} | Date: {datetime.now().isoformat()}</p>
<h2>Summary</h2><table><tr><th>Metric</th><th>Count</th></tr>"""
            for k, v in summary.items():
                html += f"<tr><td>{k.title()}</td><td>{v}</td></tr>"
            html += "</table>"

            findings = self.db.get_findings(self.session_id)
            if findings:
                html += "<h2>Findings</h2><table><tr><th>Severity</th><th>Title</th><th>URL</th></tr>"
                for f in findings:
                    html += f'<tr><td class="{f["severity"]}">{f["severity"].upper()}</td><td>{f["title"]}</td><td>{f.get("url","")}</td></tr>'
                html += "</table>"

            html += "</body></html>"
            path = export_dir / f"report_{target_safe}_{timestamp}.html"
            path.write_text(html)
        else:
            console.print("[red]Unsupported format. Use: markdown, json, or html[/red]")
            return

        console.print(f"[green]✓ Report exported:[/green] {path}")

    def _cmd_set(self, args: str):
        """Set a configuration parameter or API key in real time: /set <key>=<value>"""
        if not args or "=" not in args:
            console.print("[red]Usage: /set <param>=<value>[/red]")
            console.print("[dim]Examples: /set rate_limit=20, /set timeout=45, /set concurrency=25[/dim]")
            return
        key, val = args.split("=", 1)
        key = key.strip().lower()
        val = val.strip()

        # Update ScanConfig properties
        int_fields = ["concurrency", "timeout", "threads", "rate_limit"]
        str_fields = ["mode", "user_agent", "wordlist_subdomain", "wordlist_content", "ports_top", "ports_common"]

        if key in int_fields:
            try:
                setattr(scan_config, key, int(val))
                console.print(f"[green]✓ Runtime config updated:[/green] {key} = [bold]{val}[/bold]")
            except ValueError:
                console.print(f"[red]Value for {key} must be an integer[/red]")
        elif key in str_fields:
            setattr(scan_config, key, val)
            console.print(f"[green]✓ Runtime config updated:[/green] {key} = [bold]{val}[/bold]")
        elif hasattr(api_keys, key):
            setattr(api_keys, key, val)
            console.print(f"[green]✓ API key updated:[/green] {key} = [bold]***[/bold]")
        else:
            console.print(f"[red]Unknown configuration key: {key}[/red]")
            console.print(f"[dim]Available: {', '.join(int_fields + str_fields)}[/dim]")

    def _cmd_config(self):
        """Show current configuration."""
        config = scan_config.to_dict()
        keys_status = {
            "Shodan": bool(api_keys.shodan),
            "SecurityTrails": bool(api_keys.securitytrails),
            "VirusTotal": bool(api_keys.virustotal),
            "Censys": bool(api_keys.censys_id),
            "GitHub": bool(api_keys.github_token),
            "Chaos (PD)": bool(api_keys.chaos),
            "BuiltWith": bool(api_keys.builtwith),
            "Whoxy": bool(api_keys.whoxy),
            "FOFA": bool(api_keys.fofa_key),
            "ZoomEye": bool(api_keys.zoomeye),
        }
        print_config(config, keys_status)

    def _cmd_keys(self):
        """Show API key status."""
        self._cmd_config()

    # ── REPL Loop ─────────────────────────────────────────────────────────────

    async def _process_command(self, raw: str) -> bool:
        """Process a single command. Returns False to exit."""
        raw = raw.strip()
        if not raw:
            return True

        if not raw.startswith("/"):
            console.print("[dim]Type /help for available commands[/dim]")
            return True

        parts = raw.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd == "/exit" or cmd == "/quit":
            return False
        elif cmd == "/help":
            print_help()
        elif cmd == "/target":
            self._cmd_target(args)
        elif cmd == "/mode":
            self._cmd_mode(args)
        elif cmd == "/checklist":
            self._cmd_checklist()
        elif cmd == "/agents":
            self._cmd_agents()
        elif cmd == "/enable":
            self._cmd_enable(args)
        elif cmd == "/disable":
            self._cmd_disable(args)
        elif cmd == "/run":
            await self._cmd_run(args)
        elif cmd == "/recon":
            await self._cmd_recon(args)
        elif cmd == "/hunt":
            await self._cmd_hunt(args)
        elif cmd == "/triage":
            self._cmd_triage()
        elif cmd == "/report":
            self._cmd_report()
        elif cmd == "/status":
            self._cmd_status()
        elif cmd == "/results":
            self._cmd_results(args)
        elif cmd == "/export":
            self._cmd_export(args)
        elif cmd == "/config":
            self._cmd_config()
        elif cmd == "/keys":
            self._cmd_keys()
        elif cmd == "/set":
            self._cmd_set(args)
        elif cmd == "/clear":
            os.system("cls" if os.name == "nt" else "clear")
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")
            console.print("[dim]Type /help for available commands[/dim]")

        return True

    async def run_headless(
        self,
        target: Optional[str] = None,
        mode: str = "host",
        agents: Optional[str] = None,
        export_fmt: Optional[str] = None,
        show_checklist: bool = False,
        show_agents: bool = False,
        show_config: bool = False,
        results_type: Optional[str] = None,
        json_output: bool = False,
    ):
        """Headless non-interactive execution for AI agents (Claude Code, Codex) and automation."""
        if mode:
            self._cmd_mode(mode)

        if show_config:
            self._cmd_config()
            return

        if show_agents:
            self._cmd_agents()
            return

        if target:
            self._cmd_target(target)

        if show_checklist:
            self._cmd_checklist()
            return

        if agents:
            await self._cmd_run(agents)

        if results_type:
            self._cmd_results(results_type)

        if export_fmt:
            self._cmd_export(export_fmt)

        if json_output and self.session_id:
            import json
            data = {
                "session_id": self.session_id,
                "target": scan_config.target,
                "mode": scan_config.mode,
                "summary": self.db.get_summary(self.session_id),
                "subdomains": self.db.get_subdomains(self.session_id),
                "ports": self.db.get_ports(self.session_id),
                "technologies": self.db.get_technologies(self.session_id),
                "endpoints": self.db.get_endpoints(self.session_id),
                "parameters": self.db.get_parameters(self.session_id),
                "findings": self.db.get_findings(self.session_id),
            }
            print(json.dumps(data, indent=2))

        self.db.close()

    async def run_loop(self):
        """Main REPL loop."""
        print_banner()

        # Show quick start
        console.print("[bold white]Quick Start:[/bold white]")
        console.print("  1. [cyan]/target[/cyan] example.com")
        console.print("  2. [cyan]/agents[/cyan]                    — view agents")
        console.print("  3. [cyan]/run[/cyan] all                   — run full recon")
        console.print("  4. [cyan]/checklist[/cyan]                 — view progress")
        console.print("  5. [cyan]/results[/cyan]                   — view findings")
        console.print("  6. [cyan]/export[/cyan] markdown           — export report")
        console.print(f"\n[dim]Type /help for all commands[/dim]\n")

        running = True
        while running:
            try:
                prompt_target = f"[{scan_config.target}]" if scan_config.target else ""
                prompt_mode = f"({scan_config.mode})" if scan_config.target else ""
                raw = Prompt.ask(
                    f"[bold cyan]bb-harness[/bold cyan]{prompt_target}{prompt_mode}",
                    default="",
                )
                running = await self._process_command(raw)
            except KeyboardInterrupt:
                console.print("\n[dim]Use /exit to quit[/dim]")
            except EOFError:
                running = False

        console.print("[dim]Goodbye![/dim]")
        self.db.close()


def main(argv=None):
    """Entry point for both interactive REPL and headless CLI execution."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="bb-harness",
        description="bb-harness: The Bug Hunter's Methodology Recon Orchestrator (TBHM v4.02, 230 checks)",
    )
    parser.add_argument("-t", "--target", help="Target domain (e.g. example.com)")
    parser.add_argument("-m", "--mode", choices=["host", "container"], default="host",
                        help="Execution mode (default: host)")
    parser.add_argument("-r", "--run", nargs="?", const="all",
                        help="Run recon agents ('all', or specific agent name like 'subdomain_enum')")
    parser.add_argument("-e", "--export", choices=["markdown", "md", "json", "html"],
                        help="Export results to specified format")
    parser.add_argument("--checklist", action="store_true", help="Display 230-item methodology checklist")
    parser.add_argument("--agents", action="store_true", help="List available agents and check counts")
    parser.add_argument("--keys", "--config", dest="config", action="store_true", help="Display API keys and scan configuration")
    parser.add_argument("--results", nargs="?", const="all",
                        help="Display discovered results table (sub, ports, tech, ep, params, findings, all)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout for AI/scripts")
    parser.add_argument("-i", "--interactive", action="store_true", help="Force interactive REPL mode")

    args = parser.parse_args(argv)

    # Determine if running in headless CLI mode or interactive REPL
    is_headless = bool(
        args.target or args.run or args.checklist or args.agents or args.config or args.results
    ) and not args.interactive

    repl = HarnessREPL()

    if is_headless:
        try:
            asyncio.run(
                repl.run_headless(
                    target=args.target,
                    mode=args.mode,
                    agents=args.run,
                    export_fmt=args.export,
                    show_checklist=args.checklist,
                    show_agents=args.agents,
                    show_config=args.config,
                    results_type=args.results,
                    json_output=args.json,
                )
            )
        except KeyboardInterrupt:
            pass
    else:
        try:
            asyncio.run(repl.run_loop())
        except KeyboardInterrupt:
            pass

    return 0
