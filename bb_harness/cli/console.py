"""
bb_harness.cli.console
Rich terminal output formatting -- tables, progress bars, status indicators.
"""
from __future__ import annotations
import os
import sys
from typing import Dict, List

# Force UTF-8 on Windows to prevent cp1252 encoding errors
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.text import Text
from rich.layout import Layout
from rich.columns import Columns
from rich import box

from bb_harness.core.models import CheckItem, CheckStatus, AgentCategory
from bb_harness.core.checklist import CATEGORY_INFO, TOTAL_CHECKS

console = Console(force_terminal=True)


# -- Status icons ---------------------------------------------------------------
STATUS_ICONS = {
    CheckStatus.PENDING: "[dim]o[/dim]",
    CheckStatus.RUNNING: "[yellow]>[/yellow]",
    CheckStatus.DONE: "[green]+[/green]",
    CheckStatus.FAILED: "[red]x[/red]",
    CheckStatus.SKIPPED: "[dim]-[/dim]",
}

STATUS_COLORS = {
    "pending": "dim",
    "running": "yellow",
    "done": "green",
    "failed": "red",
    "skipped": "dim",
}


def print_banner():
    """Print the bb-harness ASCII banner."""
    banner = r"""
[bold cyan]  _     _           _
 | |__ | |__        | |__   __ _ _ __ _ __   ___  ___ ___
 | '_ \| '_ \ _____| '_ \ / _` | '__| '_ \ / _ \/ __/ __|
 | |_) | |_) |_____| | | | (_| | |  | | | |  __/\__ \__ \
 |_.__/|_.__/      |_| |_|\__,_|_|  |_| |_|\___||___/___/[/bold cyan]

  [bold white]TBHM v4.02 Recon Orchestrator[/bold white]
  [dim]230 checks | 5 categories | Dual Host/Container mode[/dim]
"""
    console.print(banner)


def print_help():
    """Print slash command help."""
    table = Table(title="[bold cyan]Available Commands[/bold cyan]",
                  box=box.ROUNDED, border_style="cyan")
    table.add_column("Command", style="bold green", width=30)
    table.add_column("Description", style="white")

    commands = [
        ("/target <domain>", "Set the target domain or URL"),
        ("/mode <host|container>", "Switch between host and container execution"),
        ("/checklist", "Show full TBHM methodology checklist with progress"),
        ("/agents", "List all recon agents with enable/disable status"),
        ("/enable <agent|all>", "Enable an agent or all agents"),
        ("/disable <agent|all>", "Disable an agent or all agents"),
        ("/recon <domain>", "Run recon for an in-scope domain"),
        ("/run [agent|all]", "Execute recon pipeline for enabled agents"),
        ("/hunt [traffic.har]", "Run the checklist-driven post-recon hunt"),
        ("/triage", "Create a validation queue from hunt observations"),
        ("/report", "Write the combined Markdown report"),
        ("/status", "Show current scan progress and statistics"),
        ("/results [type]", "View results (subdomains|ports|tech|endpoints|params|findings|all)"),
        ("/export <format>", "Export report (markdown|json|html)"),
        ("/config", "Show current configuration"),
        ("/keys", "Show API key status (configured/missing)"),
        ("/clear", "Clear terminal screen"),
        ("/help", "Show this help message"),
        ("/exit", "Exit bb-harness"),
    ]
    for cmd, desc in commands:
        table.add_row(cmd, desc)
    console.print(table)


def print_checklist(checks_by_category: Dict[str, List[dict]]):
    """Print the full TBHM methodology checklist with progress."""
    for cat_enum, info in CATEGORY_INFO.items():
        cat_key = cat_enum.value
        checks = checks_by_category.get(cat_key, [])
        total = info["total"]
        done = sum(1 for c in checks if c.get("status") == "done")
        failed = sum(1 for c in checks if c.get("status") == "failed")
        running = sum(1 for c in checks if c.get("status") == "running")

        # Progress bar
        pct = (done / total * 100) if total > 0 else 0
        bar_len = 30
        filled = min(int(bar_len * done / total), bar_len) if total > 0 else 0
        bar = f"[green]{'#' * filled}[/green][dim]{'.' * (bar_len - filled)}[/dim]"

        title = f"{info['icon']} {info['name']}  {bar}  [bold]{done}/{total}[/bold] ({pct:.0f}%)"
        if running:
            title += f"  [yellow]⟳ {running} running[/yellow]"
        if failed:
            title += f"  [red]✗ {failed} failed[/red]"

        table = Table(
            title=title,
            box=box.SIMPLE_HEAVY,
            border_style="cyan",
            show_lines=False,
            pad_edge=False,
        )
        table.add_column("#", style="dim", width=8)
        table.add_column("Status", width=4)
        table.add_column("Check", style="white", ratio=1)
        table.add_column("Found", justify="right", width=6)

        for c in checks:
            status = c.get("status", "pending")
            icon = STATUS_ICONS.get(CheckStatus(status), "?")
            desc = c.get("description", "")
            result_count = c.get("result_count", 0)
            count_str = str(result_count) if status == "done" and result_count > 0 else ""

            style = STATUS_COLORS.get(status, "")
            table.add_row(
                f"[dim]{c.get('check_id', '')}[/dim]",
                icon,
                f"[{style}]{desc}[/{style}]" if style else desc,
                f"[green]{count_str}[/green]" if count_str else "",
            )

        console.print(table)
        console.print()


def print_agents(agents: dict, enabled_agents: set):
    """Print agent list with enable/disable status."""
    table = Table(title="[bold cyan]Recon Agents[/bold cyan]",
                  box=box.ROUNDED, border_style="cyan")
    table.add_column("Agent ID", style="bold", width=22)
    table.add_column("Status", width=10)
    table.add_column("Category", width=14)
    table.add_column("Checks", justify="right", width=8)
    table.add_column("Description", ratio=1)

    for agent_id, agent_info in agents.items():
        is_enabled = agent_id in enabled_agents
        status = "[green]● ENABLED[/green]" if is_enabled else "[red]○ DISABLED[/red]"
        table.add_row(
            f"[cyan]{agent_id}[/cyan]",
            status,
            agent_info["category"],
            str(agent_info["checks"]),
            agent_info["description"],
        )
    console.print(table)


def print_summary(summary: Dict[str, int], target: str, mode: str, session_id: str):
    """Print scan summary statistics."""
    stats = Table(box=box.ROUNDED, border_style="cyan",
                  title=f"[bold cyan]Scan Summary — {target}[/bold cyan]")
    stats.add_column("Metric", style="bold")
    stats.add_column("Count", justify="right", style="green")

    icons = {
        "subdomains": "🌐", "ports": "🔌", "technologies": "🔍",
        "endpoints": "📁", "parameters": "🔗", "findings": "⚠️",
    }
    for key, count in summary.items():
        stats.add_row(f"{icons.get(key, '•')} {key.title()}", str(count))

    stats.add_section()
    stats.add_row("[dim]Session[/dim]", f"[dim]{session_id}[/dim]")
    stats.add_row("[dim]Mode[/dim]", f"[dim]{mode}[/dim]")

    console.print(stats)


def print_results_table(title: str, columns: List[tuple], rows: List[dict], limit: int = 50):
    """Generic results table printer."""
    table = Table(title=f"[bold cyan]{title}[/bold cyan]",
                  box=box.ROUNDED, border_style="cyan",
                  show_lines=False)
    for col_name, col_key, width in columns:
        table.add_column(col_name, width=width)

    for row in rows[:limit]:
        values = []
        for _, col_key, _ in columns:
            val = str(row.get(col_key, ""))
            values.append(val[:80])
        table.add_row(*values)

    console.print(table)
    if len(rows) > limit:
        console.print(f"[dim]  ... and {len(rows) - limit} more results[/dim]")


def print_config(config: dict, keys_status: dict):
    """Print current configuration."""
    table = Table(title="[bold cyan]Configuration[/bold cyan]",
                  box=box.ROUNDED, border_style="cyan")
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    for k, v in config.items():
        table.add_row(k, str(v))
    console.print(table)

    # API Keys
    keys_table = Table(title="[bold cyan]API Keys[/bold cyan]",
                       box=box.ROUNDED, border_style="cyan")
    keys_table.add_column("Key", style="bold")
    keys_table.add_column("Status")
    for k, v in keys_status.items():
        status = "[green]✓ Configured[/green]" if v else "[red]✗ Missing[/red]"
        keys_table.add_row(k, status)
    console.print(keys_table)


class ScanConsole:
    """Live scan progress tracker."""

    def __init__(self):
        self.console = console

    def log_check_start(self, check: CheckItem):
        self.console.print(
            f"  [yellow]⟳[/yellow] [{check.category.value}] {check.check_id}: {check.description[:70]}..."
        )

    def log_check_done(self, check: CheckItem):
        count = f" [green](+{check.result_count})[/green]" if check.result_count else ""
        self.console.print(
            f"  [green]✓[/green] [{check.category.value}] {check.check_id}: done{count}"
        )

    def log_check_fail(self, check: CheckItem):
        err = f": {check.error_message[:50]}" if check.error_message else ""
        self.console.print(
            f"  [red]✗[/red] [{check.category.value}] {check.check_id}: failed{err}"
        )

    def log_agent_start(self, agent_name: str, check_count: int):
        self.console.print(
            Panel(f"[bold]Running {agent_name}[/bold] — {check_count} checks",
                  border_style="cyan")
        )

    def log_agent_done(self, agent_name: str, results: dict):
        self.console.print(
            f"[green]✓ {agent_name} complete[/green] — {results}"
        )
