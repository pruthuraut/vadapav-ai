"""Resolve a completed recon session and run the guarded hunt phase."""
from __future__ import annotations

import argparse
import asyncio
import json
import re
from datetime import datetime
from pathlib import Path

from bb_harness.agents.attack_phase import AttackPhaseAgent
from bb_harness.agents.security_testing import load_har
from bb_harness.core.db import Database
from bb_harness.core.runner import DualRunner


def clean_target(value: str) -> str:
    value = value.strip().lower().lstrip("*.")
    value = re.sub(r"^https?://", "", value).split("/", 1)[0].split(":", 1)[0]
    return value.rstrip(".")


def resolve_session(db: Database, domain: str, recon: str) -> tuple[str, str, bool]:
    if recon:
        raw = Path(recon).read_text(encoding="utf-8", errors="replace")
        if Path(recon).suffix.lower() == ".json":
            data = json.loads(raw)
            session_id = str(data.get("session_id", ""))
            target = clean_target(str(data.get("target", domain)))
        else:
            session_match = re.search(r"\*\*Session:\*\*\s*`?([A-Za-z0-9_-]+)", raw, re.IGNORECASE)
            target_match = re.search(r"^#\s*Recon Report:\s*(\S+)", raw, re.IGNORECASE | re.MULTILINE)
            session_id = session_match.group(1) if session_match else ""
            target = clean_target(target_match.group(1) if target_match else domain)
        if session_id:
            row = db.conn.execute(
                "SELECT session_id, target, finished_at FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if row:
                # Explicit --recon selection may use a report-backed partial
                # session, but the caller is told clearly that recon was not
                # finalized. Domain-only selection still requires completion.
                return row["session_id"], clean_target(row["target"]), not bool(row["finished_at"])
        if not domain:
            domain = target
    target = clean_target(domain)
    row = db.conn.execute(
        "SELECT session_id, target FROM sessions WHERE lower(target) = ? AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 1",
        (target,),
    ).fetchone()
    if not row:
        raise SystemExit(f"No completed recon session found for {target!r}.")
    return row["session_id"], clean_target(row["target"]), False


async def main() -> None:
    parser = argparse.ArgumentParser(description="Run guarded hunt from the latest completed recon")
    parser.add_argument("--domain", default="", help="Recon target, e.g. adobe.io")
    parser.add_argument("--recon", default="", help="Recon JSON containing session_id/target")
    parser.add_argument("--har", default="", help="Optional HAR path mounted under output/")
    parser.add_argument("--checklist", default="security-checklist.txt")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    db = Database()
    session_id, target, partial_recon = resolve_session(db, args.domain, args.recon)
    traffic = load_har(args.har) if args.har else []
    report = await AttackPhaseAgent(db, DualRunner(mode="host"), session_id, args.checklist, traffic).start()
    report["generated_at"] = datetime.utcnow().isoformat()
    report["recon_completion"] = "partial_report_backed" if partial_recon else "completed"
    output = Path(args.output or f"output/reports/hunt_{target.replace('.', '_')}_{session_id}.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"session_id": session_id, "target": target, **report.get("summary", {})}, indent=2))
    print(output)


if __name__ == "__main__":
    asyncio.run(main())
